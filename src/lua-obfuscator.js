// Workers-safe Lua obfuscator.
//
// What it does per-request on the protected Lua payload:
//   1. Strips --line and --[[block]] comments.
//   2. Replaces every short-quoted string literal ("..." or '...') with
//      __v(index), where __v decrypts an array of XOR-encrypted bytes using
//      a fresh per-request key. Long-bracket strings ([[...]]) and strings
//      that use escape sequences we don't recognize are left alone.
//   3. Minifies whitespace while preserving token boundaries.
//   4. Prepends a tiny Lua decoder bootstrap.
//   5. Injects a watermark table whose contents are the caller's license-hmac
//      prefix, so a leaked copy identifies the licensed user.
//
// NOT a bytecode-level VM. A determined analyst with a Lua debugger will still
// recover the decrypted strings at runtime; the goal is to raise the cost of
// static dumping and watermark every delivered copy.

const BYTES_PER_HEX = 2;

export function obfuscateLua(source, options = {}) {
  const src = String(source == null ? "" : source);
  if (!src.trim()) return src;

  const nonceBytes = options.nonceBytes || crypto.getRandomValues(new Uint8Array(16));
  const key = Array.from(nonceBytes);
  const watermark = String(options.watermark || "").slice(0, 64);

  const tokens = tokenize(src);
  const encrypted = [];
  const rendered = [];

  for (const token of tokens) {
    if (token.type === "comment") continue;

    if (token.type === "string" && token.canEncrypt) {
      const bytes = xorEncrypt(token.value, key);
      const index = encrypted.length;
      encrypted.push(hexLiteral(bytes));
      rendered.push(`__v(${index})`);
      continue;
    }

    rendered.push(token.raw || token.value);
  }

  const body = minifyWhitespace(rendered.join(""));
  const bootstrap = buildBootstrap(key, encrypted);
  const watermarkLua = watermark ? buildWatermark(watermark) : "";

  return `${bootstrap}${watermarkLua}${body}`;
}

// --- lexer -----------------------------------------------------------------

function tokenize(src) {
  const tokens = [];
  const n = src.length;
  let i = 0;

  while (i < n) {
    const c = src[i];
    const c1 = src[i + 1];

    // Line and long-bracket comments.
    if (c === "-" && c1 === "-") {
      if (src[i + 2] === "[" && isLongBracketStart(src, i + 2)) {
        const closed = scanLongBracket(src, i + 2);
        tokens.push({ type: "comment", raw: src.slice(i, closed) });
        i = closed;
        continue;
      }
      const nl = src.indexOf("\n", i);
      const end = nl === -1 ? n : nl;
      tokens.push({ type: "comment", raw: src.slice(i, end) });
      i = end;
      continue;
    }

    // Long-bracket strings: [[ ... ]], [=[ ... ]=], etc. We don't try to
    // encrypt these; they often contain large payloads we'd rather pass
    // through unchanged.
    if (c === "[" && (c1 === "[" || c1 === "=")) {
      if (isLongBracketStart(src, i)) {
        const closed = scanLongBracket(src, i);
        tokens.push({ type: "string", raw: src.slice(i, closed), canEncrypt: false });
        i = closed;
        continue;
      }
    }

    // Short-quoted strings. Encryption is attempted; strings with unknown
    // escapes fall back to raw passthrough so we never change program meaning.
    if (c === '"' || c === "'") {
      const parsed = parseShortString(src, i);
      tokens.push({
        type: "string",
        raw: parsed.raw,
        value: parsed.value,
        canEncrypt: parsed.ok,
      });
      i = parsed.end;
      continue;
    }

    // Numbers.
    if (isDigit(c) || (c === "." && isDigit(c1))) {
      let j = i + 1;
      // Allow 0x hex prefix.
      if (c === "0" && (c1 === "x" || c1 === "X")) j = i + 2;
      while (j < n && /[0-9a-fA-F._pPeExX]/.test(src[j])) {
        if ((src[j] === "+" || src[j] === "-") && !/[pPeE]/.test(src[j - 1])) break;
        j++;
      }
      // Signed exponent: pick up a trailing + or - after e/E/p/P.
      if (j < n && /[pPeE]/.test(src[j - 1]) && (src[j] === "+" || src[j] === "-")) {
        j++;
        while (j < n && /[0-9]/.test(src[j])) j++;
      }
      tokens.push({ type: "number", raw: src.slice(i, j) });
      i = j;
      continue;
    }

    // Identifiers and keywords.
    if (isIdentStart(c)) {
      let j = i + 1;
      while (j < n && isIdentPart(src[j])) j++;
      tokens.push({ type: "ident", raw: src.slice(i, j) });
      i = j;
      continue;
    }

    // Whitespace.
    if (/\s/.test(c)) {
      let j = i + 1;
      while (j < n && /\s/.test(src[j])) j++;
      tokens.push({ type: "ws", raw: src.slice(i, j) });
      i = j;
      continue;
    }

    // Multi-char operators.
    const three = src.slice(i, i + 3);
    if (three === "...") { tokens.push({ type: "op", raw: three }); i += 3; continue; }
    const two = src.slice(i, i + 2);
    if (["==", "~=", "<=", ">=", "..", "::", "<<", ">>", "//"].includes(two)) {
      tokens.push({ type: "op", raw: two });
      i += 2;
      continue;
    }

    tokens.push({ type: "op", raw: c });
    i++;
  }

  return tokens;
}

function isDigit(ch) { return ch >= "0" && ch <= "9"; }
function isIdentStart(ch) { return (ch >= "a" && ch <= "z") || (ch >= "A" && ch <= "Z") || ch === "_"; }
function isIdentPart(ch) { return isIdentStart(ch) || isDigit(ch); }

// Detect [[ or [=*[ at index i. Returns true if a long bracket opens here.
function isLongBracketStart(src, i) {
  if (src[i] !== "[") return false;
  let j = i + 1;
  while (src[j] === "=") j++;
  return src[j] === "[";
}

// Scan a long bracket (string or comment) that opens at `start` and return the
// index just past its closer. Falls through to end-of-input if unclosed.
function scanLongBracket(src, start) {
  let j = start + 1;
  let eqs = 0;
  while (src[j] === "=") { eqs++; j++; }
  // At this point src[j] === "[" (confirmed by caller).
  const closer = "]" + "=".repeat(eqs) + "]";
  const end = src.indexOf(closer, j + 1);
  if (end === -1) return src.length;
  return end + closer.length;
}

// Parse a short-quoted string beginning at index `start`. Returns:
//   { raw, value, ok, end }
// `ok` is true when every escape in the source could be resolved to a byte
// value; otherwise the caller skips encryption and uses the raw source.
function parseShortString(src, start) {
  const quote = src[start];
  const bytes = [];
  let ok = true;
  let i = start + 1;
  const n = src.length;

  while (i < n) {
    const c = src[i];
    if (c === quote) {
      return { raw: src.slice(start, i + 1), value: bytes, ok, end: i + 1 };
    }
    if (c === "\n") { ok = false; break; }
    if (c === "\\") {
      const nx = src[i + 1];
      if (nx === "n") { bytes.push(0x0a); i += 2; continue; }
      if (nx === "r") { bytes.push(0x0d); i += 2; continue; }
      if (nx === "t") { bytes.push(0x09); i += 2; continue; }
      if (nx === "a") { bytes.push(0x07); i += 2; continue; }
      if (nx === "b") { bytes.push(0x08); i += 2; continue; }
      if (nx === "f") { bytes.push(0x0c); i += 2; continue; }
      if (nx === "v") { bytes.push(0x0b); i += 2; continue; }
      if (nx === "\\") { bytes.push(0x5c); i += 2; continue; }
      if (nx === "\"") { bytes.push(0x22); i += 2; continue; }
      if (nx === "'") { bytes.push(0x27); i += 2; continue; }
      if (nx === "0" || nx === "1" || nx === "2" || nx === "3" || nx === "4" ||
          nx === "5" || nx === "6" || nx === "7" || nx === "8" || nx === "9") {
        let j = i + 1;
        let num = 0;
        for (let k = 0; k < 3 && j < n && src[j] >= "0" && src[j] <= "9"; k++, j++) {
          num = num * 10 + (src.charCodeAt(j) - 0x30);
        }
        if (num > 255) { ok = false; break; }
        bytes.push(num);
        i = j;
        continue;
      }
      if (nx === "x" || nx === "X") {
        const h1 = src[i + 2];
        const h2 = src[i + 3];
        if (!h1 || !h2 || !isHex(h1) || !isHex(h2)) { ok = false; break; }
        bytes.push(parseInt(h1 + h2, 16));
        i += 4;
        continue;
      }
      // Unknown escape (\z, \u{...}, continuation lines, etc.) — bail out and
      // leave the string untouched.
      ok = false;
      break;
    }
    bytes.push(src.charCodeAt(i) & 0xff);
    i++;
  }

  // Unterminated or unsupported escape: return raw passthrough.
  const closeIdx = src.indexOf(quote, start + 1);
  const end = closeIdx === -1 ? n : closeIdx + 1;
  return { raw: src.slice(start, end), value: bytes, ok: false, end };
}

function isHex(ch) { return (ch >= "0" && ch <= "9") || (ch >= "a" && ch <= "f") || (ch >= "A" && ch <= "F"); }

// --- transforms ------------------------------------------------------------

function xorEncrypt(bytes, key) {
  if (!key.length) return bytes.slice();
  const out = new Array(bytes.length);
  for (let i = 0; i < bytes.length; i++) {
    out[i] = (bytes[i] ^ key[i % key.length]) & 0xff;
  }
  return out;
}

// Emit a Lua short-quoted string literal using only \xHH escapes. Safe for
// arbitrary bytes because \xHH never terminates a string early.
function hexLiteral(bytes) {
  let out = "\"";
  for (const b of bytes) {
    out += "\\x" + b.toString(16).padStart(BYTES_PER_HEX, "0");
  }
  out += "\"";
  return out;
}

// Collapse runs of whitespace into a single space, and drop spaces where the
// adjoining tokens cannot possibly collide (e.g. between an identifier and a
// `(`). Conservative: when in doubt, keep the space.
function minifyWhitespace(src) {
  const out = [];
  let prev = "";
  const pushable = (a, b) => {
    if (!a || !b) return false;
    return (isIdentPart(a[a.length - 1]) || isDigit(a[a.length - 1])) &&
           (isIdentStart(b[0]) || isDigit(b[0]));
  };
  // Rebuild from the already-rendered string. We only need to kill redundant
  // runs of spaces/newlines.
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    if (/\s/.test(c)) {
      // Collapse to zero-or-one space.
      let j = i + 1;
      while (j < src.length && /\s/.test(src[j])) j++;
      const left = out.length ? out[out.length - 1] : "";
      const right = src.slice(j, j + 1);
      if (pushable(left, right)) out.push(" ");
      i = j;
      continue;
    }
    out.push(c);
    i++;
  }
  return out.join("");
}

// --- bootstrap -------------------------------------------------------------

function buildBootstrap(key, encryptedStrings) {
  const keyHex = key.map((b) => b.toString(16).padStart(2, "0")).join("");
  const table = encryptedStrings.join(",");
  // The decoder:
  //   - __K: XOR key bytes (packed as a Lua string, decoded by string.byte)
  //   - __S: array of encrypted string literals, each a Lua string of raw bytes
  //   - __v(i): fetches __S[i+1], XORs each byte against __K, returns plaintext
  // Index arithmetic uses i+1 because Lua arrays are 1-indexed; obfuscator
  // emits 0-based __v(idx) calls to stay consistent with JavaScript indexing.
  return (
    `local __K=(function() local t={} ` +
    keyHex.match(/.{2}/g).map((h, i) => `t[${i + 1}]=0x${h}`).join(" ") +
    ` return t end)() ` +
    `local __S={${table}} ` +
    `local __KL=${key.length} ` +
    `local __BX=(bit32 and bit32.bxor) or (bit and bit.bxor) or function(a,b) local r,p=0,1 for _=1,8 do local x,y=a%2,b%2 if x~=y then r=r+p end a=(a-x)/2 b=(b-y)/2 p=p*2 end return r end ` +
    `local function __v(i) local s=__S[i+1] local out={} ` +
    `for n=1,#s do out[n]=string.char(__BX(string.byte(s,n),__K[((n-1)%__KL)+1])) end ` +
    `return table.concat(out) end `
  );
}

function buildWatermark(watermark) {
  // The watermark is placed in a dead `if false then` branch so it never runs
  // but survives obfuscators / minifiers that preserve string literals.
  const safe = String(watermark).replace(/\\/g, "\\\\").replace(/"/g, "\\\"");
  return `if false then local __w="${safe}" end `;
}
