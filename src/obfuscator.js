// ShadowVM v4 — Bytecode VM Luau Obfuscator, ported to JavaScript for the
// Eternal Auth Cloudflare Worker. This is a faithful port of app.py: it runs
// entirely in-process (no external service) and produces the same executable
// Luarmor-V4-style VM output.
//
// Entry point: obfuscateLuau(source, settings) -> { code, stats }
//
// Correctness note: the generated Lua VM decodes data this module embeds, so
// the encryption math here and the Lua decoder strings below are exact inverses
// copied from app.py. Random choices (handler names, decoys, trigger values)
// only affect obfuscation strength, not correctness, because the state machine
// wires everything together by values computed in the same run.

/* eslint-disable no-bitwise */

// ── RNG helpers (non-cryptographic, mirrors Python's random usage) ──
const rnd = () => Math.random();
function randint(a, b) { return a + Math.floor(Math.random() * (b - a + 1)); }
function choice(arr) { return arr[Math.floor(Math.random() * arr.length)]; }
function choices(arr, k) { const o = []; for (let i = 0; i < k; i++) o.push(choice(arr)); return o; }
function shuffle(arr) {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}
// random.sample without replacement -> k distinct items from arr
function sample(arr, k) { return shuffle(arr.slice()).slice(0, k); }
function rangeArr(lo, hi) { const o = []; for (let i = lo; i < hi; i++) o.push(i); return o; }
function sampleRange(lo, hi, k) { return sample(rangeArr(lo, hi), k); }

// ══════════════════════════════════════════════════════════════════════
//  LUAU LANGUAGE DATA
// ══════════════════════════════════════════════════════════════════════
const LUAU_KEYWORDS = new Set([
  "and", "break", "do", "else", "elseif", "end", "false", "for", "function",
  "if", "in", "local", "nil", "not", "or", "repeat", "return", "then", "true",
  "until", "while", "continue", "type", "export", "typeof",
]);
const LUAU_GLOBALS = new Set([
  "print", "warn", "error", "assert", "type", "typeof", "tostring", "tonumber",
  "select", "unpack", "rawget", "rawset", "rawequal", "rawlen", "require",
  "setmetatable", "getmetatable", "newproxy", "pcall", "xpcall", "coroutine",
  "math", "string", "table", "bit32", "os", "debug", "game", "workspace",
  "script", "Instance", "Vector3", "Vector2", "CFrame", "Color3", "BrickColor",
  "Enum", "UDim", "UDim2", "Ray", "Region3", "TweenInfo", "NumberRange",
  "NumberSequence", "ColorSequence", "Rect", "task", "wait", "spawn", "delay",
  "tick", "time", "pairs", "ipairs", "next", "loadstring", "_G", "shared",
  "_VERSION", "buffer", "vector",
]);

// ══════════════════════════════════════════════════════════════════════
//  TOKENIZER
// ══════════════════════════════════════════════════════════════════════
const isDigit = (c) => c >= "0" && c <= "9";
const isAlpha = (c) => (c >= "a" && c <= "z") || (c >= "A" && c <= "Z");
const isAlnum = (c) => isAlpha(c) || isDigit(c);

function tokenize(source) {
  const tokens = [];
  let i = 0;
  const n = source.length;
  while (i < n) {
    const c = source[i];
    if (c === " " || c === "\t" || c === "\r" || c === "\n") {
      let j = i + 1;
      while (j < n && " \t\r\n".includes(source[j])) j += 1;
      tokens.push(["ws", source.slice(i, j)]); i = j; continue;
    }
    if (source.slice(i, i + 2) === "--") {
      if (source.slice(i, i + 4) === "--[[" || (i + 2 < n && source[i + 2] === "[")) {
        let eq = 0; let ci = i + 2;
        if (ci < n && source[ci] === "[") {
          ci += 1;
          while (ci < n && source[ci] === "=") { eq += 1; ci += 1; }
          if (ci < n && source[ci] === "[") {
            ci += 1; const close = "]" + "=".repeat(eq) + "]";
            let ei = source.indexOf(close, ci);
            if (ei === -1) { tokens.push(["comment", source.slice(i)]); break; }
            ei += close.length; tokens.push(["comment", source.slice(i, ei)]); i = ei; continue;
          }
        }
      }
      let j = source.indexOf("\n", i);
      if (j === -1) { tokens.push(["comment", source.slice(i)]); break; }
      tokens.push(["comment", source.slice(i, j)]); i = j; continue;
    }
    if (c === "[" && i + 1 < n && "[=".includes(source[i + 1])) {
      let eq = 0; let ci = i + 1;
      while (ci < n && source[ci] === "=") { eq += 1; ci += 1; }
      if (ci < n && source[ci] === "[") {
        ci += 1; const close = "]" + "=".repeat(eq) + "]";
        let ei = source.indexOf(close, ci);
        if (ei !== -1) {
          ei += close.length; tokens.push(["string", source.slice(i, ei)]); i = ei; continue;
        }
      }
    }
    if (c === '"' || c === "'") {
      const q = c; let j = i + 1;
      while (j < n) {
        if (source[j] === "\\" && j + 1 < n) { j += 2; continue; }
        if (source[j] === q) { j += 1; break; }
        j += 1;
      }
      tokens.push(["string", source.slice(i, j)]); i = j; continue;
    }
    if (isDigit(c) || (c === "." && i + 1 < n && isDigit(source[i + 1]))) {
      let j = i;
      if (source[j] === "0" && j + 1 < n && "xXbB".includes(source[j + 1])) {
        j += 2;
        while (j < n && "0123456789abcdefABCDEF_".includes(source[j])) j += 1;
      } else {
        while (j < n && (isDigit(source[j]) || source[j] === "_")) j += 1;
        if (j < n && source[j] === ".") {
          j += 1;
          while (j < n && (isDigit(source[j]) || source[j] === "_")) j += 1;
        }
        if (j < n && "eE".includes(source[j])) {
          j += 1;
          if (j < n && "+-".includes(source[j])) j += 1;
          while (j < n && isDigit(source[j])) j += 1;
        }
      }
      tokens.push(["number", source.slice(i, j)]); i = j; continue;
    }
    if (isAlpha(c) || c === "_") {
      let j = i;
      while (j < n && (isAlnum(source[j]) || source[j] === "_")) j += 1;
      const w = source.slice(i, j);
      if (LUAU_KEYWORDS.has(w)) tokens.push(["kw", w]);
      else if (LUAU_GLOBALS.has(w)) tokens.push(["global", w]);
      else tokens.push(["id", w]);
      i = j; continue;
    }
    const two = i + 1 < n ? source.slice(i, i + 2) : "";
    const three = i + 2 < n ? source.slice(i, i + 3) : "";
    if (three === "..." || three === "//=") { tokens.push(["op", three]); i += 3; continue; }
    if (["..", "==", "~=", ">=", "<=", "//", "<<", ">>", "+=", "-=", "*=", "/=", "%=", "^=", "..=", "->"].includes(two)) {
      tokens.push(["op", two]); i += 2; continue;
    }
    tokens.push(["op", c]); i += 1;
  }
  return tokens;
}

// ══════════════════════════════════════════════════════════════════════
//  NAME GENERATION
// ══════════════════════════════════════════════════════════════════════
class NameGen {
  constructor() {
    this._BLACKLIST = new Set(["TK", "VM", "Sa", "Tk", "tk", "vm"]);
    this._pool = [];
    const uppers = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const lowers = "abcdefghijklmnopqrstuvwxyz";
    const suffixes = (lowers + uppers).split("");
    const firsts = (uppers + lowers).split("").concat(["_"]);
    for (const a of firsts) {
      for (const b of suffixes) {
        const name = a + b;
        if (!LUAU_KEYWORDS.has(name) && !LUAU_GLOBALS.has(name) && !this._BLACKLIST.has(name)) {
          this._pool.push(name);
        }
      }
    }
    shuffle(this._pool);
    this.counter = 0;
    this.cache = {};
    this._entry_name = this._pool.pop();
  }

  next() {
    if (this.counter < this._pool.length) {
      const name = this._pool[this.counter]; this.counter += 1; return name;
    }
    this.counter += 1; return `_${this.counter.toString(16)}`;
  }

  entry() { return this._entry_name; }

  get(original) {
    if (!(original in this.cache)) this.cache[original] = this.next();
    return this.cache[original];
  }
}

const PARAM_POOL = "LorViSNesfPIDRwBhzKMXZGHQYcntmdEqpjakbgxuJFTCW".split("");
function pick_params(n) { return PARAM_POOL.slice(0, Math.min(n, PARAM_POOL.length)); }

// ══════════════════════════════════════════════════════════════════════
//  CUSTOM ALPHABET
// ══════════════════════════════════════════════════════════════════════
const _CUSTOM_SYMBOL_POOL = (() => {
  const o = [];
  for (let cc = 33; cc < 127; cc++) { if (cc !== 34 && cc !== 92) o.push(String.fromCharCode(cc)); }
  return o;
})();
function make_custom_alphabet() { return sample(_CUSTOM_SYMBOL_POOL, 64).join(""); }

// ══════════════════════════════════════════════════════════════════════
//  ARITHMETIC CONSTANT OBFUSCATION
// ══════════════════════════════════════════════════════════════════════
function _arith_expr(val) {
  if (val === 0) { const a = randint(1, 4096); return `(${a}-${a})`; }
  const form = randint(0, 3);
  if (form === 0) { const a = randint(0, val); return `(${a}+${val - a})`; }
  if (form === 1) { const a = randint(val + 1, val + 4096); return `(${a}-${a - val})`; }
  if (form === 2 && val < 2 ** 40) {
    const m = randint(2, 9); const a = Math.floor(val / m); return `(${a}*${m}+${val - a * m})`;
  }
  const a = randint(0, val); return `(${val - a}+${a})`;
}

function obfuscate_numbers(code) {
  const out = [];
  let i = 0;
  const n = code.length;
  while (i < n) {
    const c = code[i];
    if (code.startsWith("--[[", i)) {
      let end = code.indexOf("]]", i + 4);
      end = end === -1 ? n : end + 2;
      out.push(code.slice(i, end)); i = end; continue;
    }
    if (code.startsWith("--", i)) {
      let end = code.indexOf("\n", i);
      end = end === -1 ? n : end;
      out.push(code.slice(i, end)); i = end; continue;
    }
    if (c === '"' || c === "'") {
      const q = c; let j = i + 1;
      while (j < n) {
        if (code[j] === "\\") { j += 2; continue; }
        if (code[j] === q) { j += 1; break; }
        j += 1;
      }
      out.push(code.slice(i, j)); i = j; continue;
    }
    if (isDigit(c)) {
      const prev = i > 0 ? code[i - 1] : "";
      if (isAlnum(prev) || prev === "_" || prev === ".") {
        let j = i;
        while (j < n && (isAlnum(code[j]) || code[j] === "_")) j += 1;
        out.push(code.slice(i, j)); i = j; continue;
      }
      let j = i;
      while (j < n && isDigit(code[j])) j += 1;
      if (code[i] === "0" && j < n && "xX".includes(code[j])) {
        j += 1;
        while (j < n && "0123456789abcdefABCDEF".includes(code[j])) j += 1;
        out.push(code.slice(i, j)); i = j; continue;
      }
      if (j < n && (code[j] === "." || "eE".includes(code[j]))) {
        let k = j;
        if (code[k] === ".") {
          k += 1;
          while (k < n && isDigit(code[k])) k += 1;
        }
        if (k < n && "eE".includes(code[k])) {
          k += 1;
          if (k < n && "+-".includes(code[k])) k += 1;
          while (k < n && isDigit(code[k])) k += 1;
        }
        out.push(code.slice(i, k)); i = k; continue;
      }
      out.push(_arith_expr(parseInt(code.slice(i, j), 10)));
      i = j; continue;
    }
    out.push(c); i += 1;
  }
  return out.join("");
}

// ══════════════════════════════════════════════════════════════════════
//  SHA-256 (over bytes) -> 8 big-endian uint32 words
// ══════════════════════════════════════════════════════════════════════
const SHA256_K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

function sha256Words(bytes) {
  const H = [1779033703, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635, 1541459225];
  const ml = bytes.length;
  const withOne = ml + 1;
  let padLen = withOne;
  while (padLen % 64 !== 56) padLen += 1;
  const total = padLen + 8;
  const buf = new Uint8Array(total);
  buf.set(bytes, 0);
  buf[ml] = 0x80;
  const bitLenHi = Math.floor((ml * 8) / 0x100000000);
  const bitLenLo = (ml * 8) >>> 0;
  buf[padLen] = (bitLenHi >>> 24) & 0xff;
  buf[padLen + 1] = (bitLenHi >>> 16) & 0xff;
  buf[padLen + 2] = (bitLenHi >>> 8) & 0xff;
  buf[padLen + 3] = bitLenHi & 0xff;
  buf[padLen + 4] = (bitLenLo >>> 24) & 0xff;
  buf[padLen + 5] = (bitLenLo >>> 16) & 0xff;
  buf[padLen + 6] = (bitLenLo >>> 8) & 0xff;
  buf[padLen + 7] = bitLenLo & 0xff;

  const w = new Uint32Array(64);
  const rotr = (x, nn) => ((x >>> nn) | (x << (32 - nn))) >>> 0;
  for (let off = 0; off < total; off += 64) {
    for (let t = 0; t < 16; t++) {
      w[t] = ((buf[off + t * 4] << 24) | (buf[off + t * 4 + 1] << 16) | (buf[off + t * 4 + 2] << 8) | (buf[off + t * 4 + 3])) >>> 0;
    }
    for (let t = 16; t < 64; t++) {
      const s0 = (rotr(w[t - 15], 7) ^ rotr(w[t - 15], 18) ^ (w[t - 15] >>> 3)) >>> 0;
      const s1 = (rotr(w[t - 2], 17) ^ rotr(w[t - 2], 19) ^ (w[t - 2] >>> 10)) >>> 0;
      w[t] = (w[t - 16] + s0 + w[t - 7] + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, h] = H;
    for (let t = 0; t < 64; t++) {
      const S1 = (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) >>> 0;
      const ch = ((e & f) ^ (~e & g)) >>> 0;
      const t1 = (h + S1 + ch + SHA256_K[t] + w[t]) >>> 0;
      const S0 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) >>> 0;
      const maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
      const t2 = (S0 + maj) >>> 0;
      h = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0; H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0;
    H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0; H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0;
  }
  return H.map((x) => x >>> 0);
}

// ── base64 (standard) over a byte array ──
const STD_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
function b64encode(bytes) {
  let out = "";
  const len = bytes.length;
  for (let i = 0; i < len; i += 3) {
    const b0 = bytes[i];
    const b1 = i + 1 < len ? bytes[i + 1] : 0;
    const b2 = i + 2 < len ? bytes[i + 2] : 0;
    out += STD_B64[b0 >> 2];
    out += STD_B64[((b0 & 3) << 4) | (b1 >> 4)];
    out += i + 1 < len ? STD_B64[((b1 & 15) << 2) | (b2 >> 6)] : "=";
    out += i + 2 < len ? STD_B64[b2 & 63] : "=";
  }
  return out;
}

// ══════════════════════════════════════════════════════════════════════
//  BYTECODE COMPILER — 4-round encryption + VoltraScript custom encoding
// ══════════════════════════════════════════════════════════════════════
function compile_to_bytecode(source, settings) {
  const strength = settings.vm_strength != null ? settings.vm_strength : 5;
  const source_bytes = Array.from(new TextEncoder().encode(source));

  const master_key = randint(17, 253);
  const xor_key = randint(1, 255);
  const block_key = randint(1, 255);
  const noise_xor = randint(1, 255);
  const noise_add = randint(1, 255);

  // Round 1: non-linear key schedule + XOR
  const key_schedule = new Array(256).fill(0);
  key_schedule[0] = master_key;
  for (let i = 1; i < 256; i++) {
    key_schedule[i] = ((key_schedule[i - 1] * xor_key + master_key) ^ ((i * 137) & 0xff)) & 0xff;
  }
  const r1 = source_bytes.map((b, i) => (b ^ key_schedule[i % 256]) & 0xff);

  // Round 2: S-box substitution (any permutation; inverse is embedded)
  const sbox = rangeArr(0, 256);
  shuffle(sbox);
  const inv_sbox = new Array(256).fill(0);
  sbox.forEach((v, i) => { inv_sbox[v] = i; });
  const r2 = r1.map((b) => sbox[b]);

  // Round 3: byte rotation (left by variable shift)
  const r3 = r2.map((b, i) => {
    const shift = (i % 7) + 1;
    return ((b << shift) | (b >> (8 - shift))) & 0xff;
  });

  // Round 4: CBC-like block XOR chaining
  const r4 = [];
  let prev = block_key;
  for (const b of r3) { const cc = (b ^ prev) & 0xff; r4.push(cc); prev = cc; }

  // Round 5: VoltraScript custom base64
  const custom_alphabet = make_custom_alphabet();
  const transMap = {};
  for (let i = 0; i < 64; i++) transMap[STD_B64[i]] = custom_alphabet[i];
  const b64 = b64encode(r4).replace(/=+$/, "").split("").map((ch) => transMap[ch]).join("");
  const data_len = r4.length;

  // SHA-256 of the processed source
  const sha_words = sha256Words(new TextEncoder().encode(source));

  let num_groups = Math.min(10, Math.max(4, 4 + Math.floor(strength / 4)));
  num_groups = Math.min(num_groups, Math.max(1, b64.length));

  const chunk_size = Math.max(40, 180 - strength * 5);
  const per_group = Math.floor((b64.length + num_groups - 1) / num_groups);
  const groups = [];
  let idx = 0;
  let total_chunks = 0;
  for (let g = 0; g < num_groups; g++) {
    const gstr = b64.slice(idx, idx + per_group);
    idx += per_group;
    let gchunks = [];
    for (let i = 0; i < gstr.length; i += chunk_size) gchunks.push(gstr.slice(i, i + chunk_size));
    if (gchunks.length === 0) gchunks = [""];
    groups.push(gchunks);
    total_chunks += gchunks.length;
  }

  return {
    groups, master_key, xor_key, block_key, noise_xor, noise_add,
    inv_sbox, data_len, sha_words, custom_alphabet,
    source_len: source_bytes.length, num_chunks: total_chunks, num_groups,
  };
}

function chunks_to_escaped_strings(chunks) {
  return chunks.map((chunk) => (chunk ? `"${chunk}"` : '""')).join(",");
}

// ══════════════════════════════════════════════════════════════════════
//  HANDLER GENERATORS — decoys (dead code)
// ══════════════════════════════════════════════════════════════════════
function _rand_ret(params, local_vars, ngen) {
  const ret_opcode = randint(1, 1024);
  const ret_vals = [String(ret_opcode)];
  const available = params.slice(1).concat(local_vars);
  const num_ret = randint(4, 10);
  for (let k = 0; k < num_ret; k++) {
    const cc = randint(0, 7);
    if (cc <= 2 && available.length) ret_vals.push(choice(available));
    else if (cc === 3) { const p = choice(params.slice(1, Math.min(5, params.length))); ret_vals.push(`${p}+${randint(1, 8)}`); }
    else if (cc === 4) { const p = choice(params.slice(1, Math.min(5, params.length))); ret_vals.push(`${p}-${randint(1, 4)}`); }
    else if (cc === 5 && available.length) ret_vals.push(`(${choice(available)}%256)`);
    else if (cc === 6) ret_vals.push(String(randint(0, 255)));
    else ret_vals.push(available.length ? choice(available) : "0");
  }
  return `return ${ret_vals.join(",")}`;
}

function _gen_fake_branch_code(params, ngen) {
  const ops = [];
  const lvs = [];
  const count = randint(1, 3);
  for (let k = 0; k < count; k++) {
    const lv = ngen.next();
    lvs.push(lv);
    const fp = params[randint(1, Math.min(5, params.length - 1))];
    const ot = randint(0, 5);
    if (ot === 0) ops.push(`local ${lv}=L[3](${fp},${randint(1, 4)})`);
    else if (ot === 1) ops.push(`local ${lv}=L[31](${fp},${randint(1, 255)})`);
    else if (ot === 2) ops.push(`local ${lv}=L[114](${fp},${randint(128, 255)})`);
    else if (ot === 3) ops.push(`local ${lv}=${fp}-128`);
    else if (ot === 4) ops.push(`local ${lv}=L[116](${fp},${randint(1, 7)})`);
    else ops.push(`local ${lv}=(${fp}-128)*${choice([128, 16384])}`);
  }
  ops.push(_rand_ret(params, lvs, ngen));
  return ops.join(";");
}

function gen_handler_buffer_chain(name, ngen) {
  const np = randint(6, 14);
  const params = pick_params(np);
  const branches = randint(3, 7);
  const base = randint(30, 600);
  const ci = randint(2, Math.min(4, np - 1));
  const cv = params[ci];
  const parts = [`${name}=function(${params.join(",")})`];
  for (let bi = 0; bi < branches; bi++) {
    const thr = base + bi * randint(15, 90);
    if (bi === 0) parts.push(`if ${cv}<=${thr} then `);
    else if (bi < branches - 1) parts.push(`elseif ${cv}<=${thr} then `);
    else parts.push("else ");
    const ops = []; const lvs = [];
    const num_reads = randint(1, 4);
    for (let ri = 0; ri < num_reads; ri++) {
      const lv = ngen.next(); lvs.push(lv);
      const p1 = params[randint(1, Math.min(4, np - 1))];
      const p2 = params[randint(1, Math.min(5, np - 1))];
      ops.push(`local ${lv}=L[3](${p1},${p2}+${randint(0, 8)})`);
    }
    if (lvs.length) {
      const t = randint(1, 3);
      for (let k = 0; k < t; k++) {
        const lv = choice(lvs);
        const xform = randint(0, 5);
        if (xform === 0) ops.push(`${lv}=L[31](${lv},${randint(1, 255)})`);
        else if (xform === 1) ops.push(`${lv}=L[114](${lv},${randint(1, 255)})`);
        else if (xform === 2) ops.push(`${lv}=L[41](${lv},${randint(1, 7)})`);
        else if (xform === 3) ops.push(`${lv}=L[116](${lv},${randint(1, 7)})`);
        else if (xform === 4) ops.push(`${lv}=L[35](${lv},${randint(1, 7)})`);
        else ops.push(`${lv}=L[38](${lv})`);
      }
    }
    if (lvs.length && rnd() > 0.3) {
      const wlv = choice(lvs);
      const p1 = params[randint(1, Math.min(3, np - 1))];
      ops.push(`L[11](${p1},${randint(0, 4)},${wlv})`);
    }
    ops.push(_rand_ret(params, lvs, ngen));
    parts.push(ops.join(";") + ";");
  }
  parts.push("end;end");
  return parts.join("");
}

function gen_handler_string_ops(name, ngen) {
  const np = randint(5, 12);
  const params = pick_params(np);
  const branches = randint(2, 6);
  const base = randint(50, 500);
  const ci = randint(2, Math.min(4, np - 1));
  const cv = params[ci];
  const parts = [`${name}=function(${params.join(",")})`];
  for (let bi = 0; bi < branches; bi++) {
    const thr = base + bi * randint(10, 80);
    if (bi === 0) parts.push(`if ${cv}<=${thr} then `);
    else if (bi < branches - 1) parts.push(`elseif ${cv}<=${thr} then `);
    else parts.push("else ");
    const ops = []; const lvs = [];
    const p1 = params[randint(1, Math.min(3, np - 1))];
    const lv = ngen.next(); lvs.push(lv);
    ops.push(`local ${lv}=L[106](${p1},${randint(1, 4)})`);
    const lv2 = ngen.next(); lvs.push(lv2);
    ops.push(`local ${lv2}=L[31](${lv},${randint(1, 255)})`);
    if (rnd() > 0.4) {
      const lv3 = ngen.next(); lvs.push(lv3);
      ops.push(`local ${lv3}=L[114](${lv2},${randint(128, 255)})`);
    }
    if (rnd() > 0.5) ops.push(`local ${ngen.next()}=L[34](${choice(lvs)})`);
    ops.push(_rand_ret(params, lvs, ngen));
    parts.push(ops.join(";") + ";");
  }
  parts.push("end;end");
  return parts.join("");
}

function gen_handler_table_state(name, ngen) {
  const np = randint(6, 13);
  const params = pick_params(np);
  const branches = randint(3, 6);
  const base = randint(50, 500);
  const ci = randint(2, Math.min(4, np - 1));
  const cv = params[ci];
  const parts = [`${name}=function(${params.join(",")})`];
  for (let bi = 0; bi < branches; bi++) {
    const thr = base + bi * randint(10, 60);
    if (bi === 0) parts.push(`if ${cv}<=${thr} then `);
    else if (bi < branches - 1) parts.push(`elseif ${cv}<=${thr} then `);
    else parts.push("else ");
    const ops = []; const lvs = [];
    const p1 = params[randint(1, Math.min(3, np - 1))];
    const p2 = params[randint(1, Math.min(5, np - 1))];
    const p3 = params[randint(1, Math.min(6, np - 1))];
    const op_type = randint(0, 4);
    if (op_type === 0) {
      const lv = ngen.next(); lvs.push(lv);
      ops.push(`local ${lv}=L[9](${p1},${p2})`);
      const lv2 = ngen.next(); lvs.push(lv2);
      ops.push(`local ${lv2}=${lv} and L[31](${lv},${randint(1, 255)}) or ${randint(0, 255)}`);
      ops.push(`L[82](${p1},${p3},${lv2})`);
    } else if (op_type === 1) {
      const lv = ngen.next(); lvs.push(lv);
      ops.push(`local ${lv}=L[86](${randint(4, 32)})`);
      const lv2 = ngen.next(); lvs.push(lv2);
      ops.push(`local ${lv2}=L[31](L[3](${p1},${p2}+${randint(0, 4)}),${randint(1, 255)})`);
      ops.push(`L[11](${lv},0,${lv2})`);
    } else if (op_type === 2) {
      const lv = ngen.next(); lvs.push(lv);
      const lv2 = ngen.next(); lvs.push(lv2);
      const lv3 = ngen.next(); lvs.push(lv3);
      ops.push(`local ${lv},${lv2},${lv3}=(${p1}-128)*16384,(${p2}-128)*128,L[3](${p3},${randint(1, 4)}+${p1})`);
      ops.push(`${lv}=${lv}+${lv2}+${lv3}`);
    } else if (op_type === 3) {
      const lv = ngen.next(); lvs.push(lv);
      ops.push(`local ${lv}=(128+${p1})%256`);
      const lv2 = ngen.next(); lvs.push(lv2);
      ops.push(`local ${lv2}=L[86](1)`);
      ops.push(`L[11](${lv2},0,L[31]((${lv}*173+23)%256,${randint(1, 255)}))`);
    } else {
      const lv = ngen.next(); lvs.push(lv);
      ops.push(`local ${lv}=L[61](${randint(4, 16)},0)`);
      ops.push(`${lv}[1]=${p1};${lv}[2]=${p2};${lv}[3]=L[114](${p1},${randint(128, 255)})`);
    }
    ops.push(_rand_ret(params, lvs, ngen));
    parts.push(ops.join(";") + ";");
  }
  parts.push("end;end");
  return parts.join("");
}

function gen_handler_conditional_not(name, ngen) {
  const np = randint(5, 11);
  const params = pick_params(np);
  const branches = randint(3, 6);
  const base = randint(50, 500);
  const ci = randint(2, Math.min(4, np - 1));
  const cv = params[ci];
  const parts = [`${name}=function(${params.join(",")})`];
  for (let bi = 0; bi < branches; bi++) {
    const thr = base + bi * randint(10, 80);
    if (bi === 0) parts.push(`if ${cv}<=${thr} then `);
    else if (bi < branches - 1) parts.push(`elseif ${cv}<=${thr} then `);
    else parts.push("else ");
    const p1 = params[randint(1, Math.min(3, np - 1))];
    const p2 = params[randint(1, Math.min(4, np - 1))];
    const lv = ngen.next();
    const op_a = randint(1, 1024);
    const op_b = randint(1, 1024);
    const retCount = randint(4, 8);
    const ret_vars = Array.from({ length: retCount }, () => choice(params.slice(1))).join(",");
    const threshold = choice([128, 64, 192, 256]);
    const pt = randint(0, 4);
    if (pt === 0) parts.push(`local ${lv}=L[3](${p1},${p2}+${randint(1, 4)});return not(${threshold}<=${lv})and ${op_a} or ${op_b},${ret_vars};`);
    else if (pt === 1) parts.push(`local ${lv}=L[3](${p1},${randint(1, 3)}+${p2});return not not(${lv}>=${threshold})and ${op_a} or ${op_b},${ret_vars};`);
    else if (pt === 2) parts.push(`local ${lv}=L[3](${p1},${p2}+${randint(1, 2)});return ${lv}<${threshold} and ${op_a} or ${op_b},${ret_vars};`);
    else if (pt === 3) parts.push(`local ${lv}=L[3](${p1},${p2}+1);if ${threshold}>${lv} then return ${op_a},${ret_vars};else return ${op_b},${ret_vars};end;`);
    else {
      const lv2 = ngen.next();
      parts.push(`local ${lv}=L[3](${p1},${p2}+${randint(1, 3)});local ${lv2}=L[31](${lv},${randint(1, 255)});return not(${threshold}<=${lv2})and ${op_a} or ${op_b},${ret_vars};`);
    }
  }
  parts.push("end;end");
  return parts.join("");
}

function gen_handler_multi_decode(name, ngen) {
  const np = randint(7, 14);
  const params = pick_params(np);
  const branches = randint(2, 5);
  const base = randint(50, 500);
  const ci = randint(2, Math.min(4, np - 1));
  const cv = params[ci];
  const parts = [`${name}=function(${params.join(",")})`];
  for (let bi = 0; bi < branches; bi++) {
    const thr = base + bi * randint(15, 90);
    if (bi === 0) parts.push(`if ${cv}<=${thr} then `);
    else if (bi < branches - 1) parts.push(`elseif ${cv}<=${thr} then `);
    else parts.push("else ");
    const ops = []; const lvs = [];
    const p1 = params[randint(1, Math.min(4, np - 1))];
    const p2 = params[randint(1, Math.min(5, np - 1))];
    const num_reads = randint(2, 4);
    for (let ri = 0; ri < num_reads; ri++) {
      const lv = ngen.next(); lvs.push(lv);
      ops.push(`local ${lv}=L[3](${p1},${ri}+${p2})`);
    }
    if (lvs.length >= 2) {
      const combo = ngen.next(); lvs.push(combo);
      const multipliers = [1, 256, 65536, 16777216];
      const expr_parts = [];
      for (let ri = 0; ri < num_reads; ri++) {
        const lv = lvs[ri];
        if (ri === 0) expr_parts.push(lv);
        else expr_parts.push(`(${lv}*${multipliers[Math.min(ri, 3)]})`);
      }
      ops.push(`local ${combo}=${expr_parts.join("+")}`);
    }
    if (rnd() > 0.4 && lvs.length) {
      const lv_new = ngen.next(); lvs.push(lv_new);
      ops.push(`local ${lv_new}=(${lvs[lvs.length - 2]}-128)*${choice([128, 16384, 2097152])}`);
    }
    ops.push(_rand_ret(params, lvs, ngen));
    parts.push(ops.join(";") + ";");
  }
  parts.push("end;end");
  return parts.join("");
}

function gen_handler_integrity_check(name, ngen) {
  const np = randint(6, 12);
  const params = pick_params(np);
  const branches = randint(2, 4);
  const base = randint(50, 400);
  const ci = randint(2, Math.min(4, np - 1));
  const cv = params[ci];
  const parts = [`${name}=function(${params.join(",")})`];
  for (let bi = 0; bi < branches; bi++) {
    const thr = base + bi * randint(20, 100);
    if (bi === 0) parts.push(`if ${cv}<=${thr} then `);
    else if (bi < branches - 1) parts.push(`elseif ${cv}<=${thr} then `);
    else parts.push("else ");
    const ops = []; const lvs = [];
    const p1 = params[randint(1, Math.min(3, np - 1))];
    const p2 = params[randint(1, Math.min(5, np - 1))];
    const lv = ngen.next(); lvs.push(lv);
    ops.push(`local ${lv}=0`);
    const lv2 = ngen.next(); lvs.push(lv2);
    ops.push(`for ${lv2}=1,4 do ${lv}=L[31](${lv},L[3](${p1},${lv2}+${p2})) end`);
    const lv3 = ngen.next(); lvs.push(lv3);
    ops.push(`local ${lv3}=L[114](${lv},255)`);
    ops.push(_rand_ret(params, lvs, ngen));
    parts.push(ops.join(";") + ";");
  }
  parts.push("end;end");
  return parts.join("");
}

function gen_handler_env_sandbox(name, ngen) {
  const np = randint(5, 10);
  const params = pick_params(np);
  const branches = randint(2, 4);
  const base = randint(50, 500);
  const ci = randint(2, Math.min(4, np - 1));
  const cv = params[ci];
  const parts = [`${name}=function(${params.join(",")})`];
  for (let bi = 0; bi < branches; bi++) {
    const thr = base + bi * randint(10, 70);
    if (bi === 0) parts.push(`if ${cv}<=${thr} then `);
    else if (bi < branches - 1) parts.push(`elseif ${cv}<=${thr} then `);
    else parts.push("else ");
    const ops = []; const lvs = [];
    const p1 = params[randint(1, Math.min(3, np - 1))];
    const p2 = params[randint(1, Math.min(5, np - 1))];
    const check_type = randint(0, 3);
    if (check_type === 0) {
      const lv = ngen.next(); lvs.push(lv);
      ops.push(`local ${lv}=L[111](${p1})`);
      const lv2 = ngen.next(); lvs.push(lv2);
      ops.push(`local ${lv2}=(${lv}=='number')and ${p1}+${p2} or 0`);
    } else if (check_type === 1) {
      const lv = ngen.next(); lvs.push(lv);
      ops.push(`local ${lv}=L[111](${p1})`);
      const lv2 = ngen.next(); lvs.push(lv2);
      ops.push(`local ${lv2}=${p2}`);
    } else if (check_type === 2) {
      const lv = ngen.next(); lvs.push(lv);
      ops.push(`local ${lv}=L[99](L[111],${p1})`);
      const lv2 = ngen.next(); lvs.push(lv2);
      ops.push(`local ${lv2}=${lv} and ${p2} or 0`);
    } else {
      const lv = ngen.next(); lvs.push(lv);
      ops.push(`local ${lv}=L[111](${p1})`);
      const lv2 = ngen.next(); lvs.push(lv2);
      ops.push(`local ${lv2}=${lv}=='table' and L[43](${p1}) or 0`);
    }
    ops.push(_rand_ret(params, lvs, ngen));
    parts.push(ops.join(";") + ";");
  }
  parts.push("end;end");
  return parts.join("");
}

function gen_handler_classic(name, ngen) {
  const np = randint(5, 13);
  const params = pick_params(np);
  const branches = randint(2, 5);
  const base = randint(50, 500);
  const ci = randint(2, Math.min(4, np - 1));
  const cv = params[ci];
  const parts = [`${name}=function(${params.join(",")})`];
  for (let bi = 0; bi < branches; bi++) {
    const thr = base + bi * randint(10, 80);
    if (bi === 0) parts.push(`if ${cv}<=${thr} then `);
    else if (bi < branches - 1) parts.push(`elseif ${cv}<=${thr} then `);
    else parts.push("else ");
    const ops = []; const lvs = [];
    const num_locals = randint(1, 3);
    for (let k = 0; k < num_locals; k++) {
      const lv = ngen.next(); lvs.push(lv);
      const p1 = params[randint(1, Math.min(4, np - 1))];
      const p2 = params[randint(1, Math.min(5, np - 1))];
      const ot = randint(0, 7);
      if (ot === 0) ops.push(`local ${lv}=L[3](${p1},${p2}+${randint(1, 4)})`);
      else if (ot === 1) ops.push(`local ${lv}=(${p1}-128)*${choice([128, 16384, 2097152])}`);
      else if (ot === 2) ops.push(`local ${lv}=L[3](${p1},${randint(1, 3)}+${p2})`);
      else if (ot === 3) ops.push(`local ${lv}=${p1}-128`);
      else if (ot === 4) {
        const lv2 = ngen.next(); lvs.push(lv2);
        ops.push(`local ${lv},${lv2}=L[3](${p1},${randint(1, 3)}+${p2}),${p2}-128`);
      } else if (ot === 5) ops.push(`local ${lv}=(${p1}-128)*16384`);
      else if (ot === 6) ops.push(`local ${lv}=L[31](${p1},${randint(1, 255)})`);
      else ops.push(`local ${lv}=L[114](${p1},${randint(128, 255)})`);
    }
    if (lvs.length && rnd() > 0.4) {
      const lv = lvs[0];
      const p3 = params[randint(1, Math.min(3, np - 1))];
      const extra = randint(0, 2);
      if (extra === 0) ops.push(`${lv}=${p3}+(${lv})`);
      else if (extra === 1) ops.push(`${lv}=L[31](${lv},${p3})`);
      else ops.push(`local ${ngen.next()}=(${lv}*173+23)%256`);
    }
    ops.push(_rand_ret(params, lvs, ngen));
    parts.push(ops.join(";") + ";");
  }
  parts.push("end;end");
  return parts.join("");
}

function gen_coroutine_handler(name) {
  const p = pick_params(4);
  const sv = choice("SNesfP".split(""));
  const sv2 = choice("NVir".split(""));
  return `${name}=function(${p.join(",")},...)`
    + `local ${p[3]}=L[40];${p[3]}();`
    + `local ${sv}=L[17];`
    + `for L,${sv2} in ${p[1]},${p[2]},${p[3]} do `
    + `${p[3]}(${sv},L,${sv2});end;end`;
}

// ── Dispatch decoys ──
function gen_f_function(name, handler_names, ngen, depth_limit = 12) {
  const dv = "_";
  function build_dispatch(handlers, lo, hi, depth = 0) {
    if (!handlers.length || depth > depth_limit) return "";
    if (handlers.length === 1) {
      const h = handlers[0];
      const sv = choices(["_", "d", "o", "S", "m", "E", "F", "G", "Y", "Q", "n", "K", "h", "B", "p", "J", "N", "V", "w", "z"], randint(6, 12)).join(",");
      return `${dv},d,o,S,m,E,F,G=L:${h}(${sv});continue;`;
    }
    const mid = Math.floor((lo + hi) / 2);
    const left = handlers.slice(0, Math.floor(handlers.length / 2));
    const right = handlers.slice(Math.floor(handlers.length / 2));
    const lc = build_dispatch(left, lo, mid, depth + 1);
    const rc = build_dispatch(right, mid + 1, hi, depth + 1);
    return `if ${dv}<=${mid} then ${lc}else ${rc}end;`;
  }
  const num_d = Math.min(handler_names.length, randint(60, 150));
  const dh = sample(handler_names, num_d);
  const dc = build_dispatch(dh, 0, 1023, 0);
  return `${name}=function(L,o,r)`
    + `local V={[1]=o};local i,S,N,e,s,f,P,I,D,R,w,B,h,z=L:${ngen.next()}(V);`
    + `local _,d=S,N;o=V[1];`
    + `local S,N,K,n,m,E,Y,Q,F,G,O,p,J=V[2],r,e,s,f,P,I,D,R,w,B,h,z;`
    + `while i do ${dc}end;end`;
}

function gen_ur_function(name) {
  return `${name}=function(L,...)`
    + `local o=L[32](L[127](L[104](1,...)));`
    + `local r={};`
    + `for V=1,#o do r[V]=L[106](o,V) end;`
    + `return #r>0,r,L[80](r);`
    + `end`;
}

function gen_sub_dispatcher(name, handler_names, ngen) {
  const num_d = Math.min(handler_names.length, randint(15, 40));
  const dh = sample(handler_names, num_d);
  function build(handlers, lo, hi, depth = 0) {
    if (!handlers.length || depth > 8) return "";
    if (handlers.length === 1) {
      const h = handlers[0];
      const sv = choices(["o", "r", "V", "i", "S", "N", "e"], randint(4, 7)).join(",");
      return `return L:${h}(${sv});`;
    }
    const mid = Math.floor((lo + hi) / 2);
    const left = handlers.slice(0, Math.floor(handlers.length / 2));
    const right = handlers.slice(Math.floor(handlers.length / 2));
    return `if o<=${mid} then ${build(left, lo, mid, depth + 1)}else ${build(right, mid + 1, hi, depth + 1)}end;`;
  }
  const dc = build(dh, 0, 255, 0);
  return `${name}=function(L,o,r,V,i,S,N,e)${dc}end`;
}

// ══════════════════════════════════════════════════════════════════════
//  REAL HANDLER GENERATORS — disguised decryption pipeline stages
// ══════════════════════════════════════════════════════════════════════
function _wrapReal(name, params, cv, real_code, extra) {
  const num_fake = randint(2, 4);
  const thresholds = sampleRange(50, 500, num_fake).sort((a, b) => a - b);
  const parts = [`${name}=function(${params.join(",")})`];
  thresholds.forEach((thr, fi) => {
    if (fi === 0) parts.push(`if ${cv}<=${thr} then `);
    else parts.push(`elseif ${cv}<=${thr} then `);
    parts.push(_gen_fake_branch_code(params, extra.ngen) + ";");
  });
  parts.push("else ");
  parts.push(real_code + ";");
  parts.push("end;end");
  const trigger = thresholds[thresholds.length - 1] + randint(10, 200);
  return { code: parts.join(""), trigger };
}

function gen_real_collect_handler(name, data_indices, ngen) {
  const num_groups = data_indices.length;
  const np = Math.max(num_groups + 4, randint(8, 14));
  const params = pick_params(np);
  const ci = np - 1;
  const cv = params[ci];
  const rv = ngen.next();
  const real_parts = [`local ${rv}={}`];
  for (let gi = 0; gi < num_groups; gi++) {
    const gp = params[1 + gi];
    const iv = ngen.next();
    real_parts.push(`for ${iv}=1,#${gp} do ${rv}[#${rv}+1]=${gp}[${iv}] end`);
  }
  real_parts.push(`return L[25](${rv})`);
  const { code, trigger } = _wrapReal(name, params, cv, real_parts.join(";"), { ngen });
  return { code, ci, trigger, num_params: np, data_param_indices: rangeArr(1, 1 + num_groups) };
}

function gen_real_b64decode_handler(name, data_len, alphabet, ngen) {
  const np = randint(9, 14);
  const params = pick_params(np);
  const ci = np - 1;
  const cv = params[ci];
  const sp = params[1];
  const A = ngen.next(); const rev = ngen.next(); const out = ngen.next();
  const ii = ngen.next(); const oi = ngen.next(); const nn = ngen.next();
  const c1 = ngen.next(); const c2 = ngen.next(); const c3 = ngen.next(); const c4 = ngen.next();
  const ri = ngen.next();
  const real_code = `local ${A}="${alphabet}";`
    + `local ${rev}={};`
    + `for ${ri}=1,64 do ${rev}[L[106](${A},${ri})]=${ri}-1 end;`
    + `local ${out}={};local ${nn}=#${sp};local ${ii}=1;local ${oi}=1;`
    + `while ${ii}<=${nn} do `
    + `local ${c1}=${rev}[L[106](${sp},${ii})] or 0;`
    + `local ${c2}=${rev}[L[106](${sp},${ii}+1)] or 0;`
    + `local ${c3}=${rev}[L[106](${sp},${ii}+2)] or 0;`
    + `local ${c4}=${rev}[L[106](${sp},${ii}+3)] or 0;`
    + `${out}[${oi}]=L[114](L[115](L[41](${c1},2),L[116](${c2},4)),255);${oi}=${oi}+1;`
    + `${out}[${oi}]=L[114](L[115](L[41](L[114](${c2},15),4),L[116](${c3},2)),255);${oi}=${oi}+1;`
    + `${out}[${oi}]=L[114](L[115](L[41](L[114](${c3},3),6),${c4}),255);${oi}=${oi}+1;`
    + `${ii}=${ii}+4 `
    + `end;`
    + `return ${out},${data_len}`;
  const { code, trigger } = _wrapReal(name, params, cv, real_code, { ngen });
  return { code, ci, trigger, num_params: np };
}

function gen_real_collect_global_handler(name, gname, ngen) {
  const np = randint(8, 14);
  const params = pick_params(np);
  const ci = np - 1;
  const cv = params[ci];
  const rv = ngen.next();
  const iv = ngen.next();
  const real_code = `local ${rv}={};`
    + `for ${iv}=1,#${gname} do ${rv}[#${rv}+1]=${gname}[${iv}] end;`
    + `return L[25](${rv})`;
  const { code, trigger } = _wrapReal(name, params, cv, real_code, { ngen });
  return { code, ci, trigger, num_params: np, data_param_indices: [] };
}

function gen_real_unrotate_handler(name, ngen) {
  const np = randint(8, 14);
  const params = pick_params(np);
  const ci = np - 1;
  const cv = params[ci];
  const dp = params[1];
  const lp = params[2];
  const iv = ngen.next();
  const sv = ngen.next();
  const real_code = `for ${iv}=1,${lp} do `
    + `local ${sv}=(${iv}-1)%7+1;`
    + `${dp}[${iv}]=L[114](L[115](L[116](${dp}[${iv}],${sv}),L[41](${dp}[${iv}],8-${sv})),255) `
    + `end;`
    + `return ${dp}`;
  const { code, trigger } = _wrapReal(name, params, cv, real_code, { ngen });
  return { code, ci, trigger, num_params: np, data_idx: 1, len_idx: 2 };
}

function gen_real_invsbox_handler(name, ngen) {
  const np = randint(8, 14);
  const params = pick_params(np);
  const ci = np - 1;
  const cv = params[ci];
  const dp = params[1];
  const sp = params[2];
  const lp = params[3];
  const iv = ngen.next();
  const real_code = `for ${iv}=1,${lp} do `
    + `${dp}[${iv}]=L[106](${sp},${dp}[${iv}]+1) `
    + `end;`
    + `return ${dp}`;
  const { code, trigger } = _wrapReal(name, params, cv, real_code, { ngen });
  return { code, ci, trigger, num_params: np };
}

function gen_real_xordecrypt_handler(name, mk_a, mk_b, xk_a, xk_b, ngen) {
  const np = randint(8, 14);
  const params = pick_params(np);
  const ci = np - 1;
  const cv = params[ci];
  const dp = params[1];
  const lp = params[2];
  const rv = ngen.next();
  const mkv = ngen.next();
  const xkv = ngen.next();
  const iv = ngen.next();
  const ksv = ngen.next();
  const jv = ngen.next();
  const real_code = `local ${rv}={};`
    + `local ${mkv}=L[31](${mk_a},${mk_b});`
    + `local ${xkv}=L[31](${xk_a},${xk_b});`
    + `local ${ksv}={};${ksv}[1]=${mkv};`
    + `for ${jv}=2,256 do `
    + `${ksv}[${jv}]=L[114](L[31](${ksv}[${jv}-1]*${xkv}+${mkv},L[114]((${jv}-1)*137,255)),255) `
    + `end;`
    + `for ${iv}=1,${lp} do `
    + `${rv}[${iv}]=L[34](L[31](${dp}[${iv}],${ksv}[(${iv}-1)%256+1])) `
    + `end;`
    + `return L[25](${rv})`;
  const { code, trigger } = _wrapReal(name, params, cv, real_code, { ngen });
  return { code, ci, trigger, num_params: np };
}

function gen_real_unblock_handler(name, bk_a, bk_b, ngen) {
  const np = randint(8, 14);
  const params = pick_params(np);
  const ci = np - 1;
  const cv = params[ci];
  const dp = params[1];
  const lp = params[2];
  const bkv = ngen.next();
  const pv = ngen.next();
  const iv = ngen.next();
  const cuv = ngen.next();
  const real_code = `local ${bkv}=L[31](${bk_a},${bk_b});`
    + `local ${pv}=${bkv};`
    + `for ${iv}=1,${lp} do `
    + `local ${cuv}=${dp}[${iv}];`
    + `${dp}[${iv}]=L[31](${cuv},${pv});`
    + `${pv}=${cuv} `
    + `end;`
    + `return ${dp}`;
  const { code, trigger } = _wrapReal(name, params, cv, real_code, { ngen });
  return { code, ci, trigger, num_params: np };
}

function gen_real_noise_handler(name, op, val, ngen) {
  const np = randint(8, 14);
  const params = pick_params(np);
  const ci = np - 1;
  const cv = params[ci];
  const dp = params[1];
  const lp = params[2];
  const iv = ngen.next();
  let body;
  if (op === "xor") body = `for ${iv}=1,${lp} do ${dp}[${iv}]=L[31](${dp}[${iv}],${val}) end`;
  else if (op === "add") body = `for ${iv}=1,${lp} do ${dp}[${iv}]=L[114](${dp}[${iv}]+${val},255) end`;
  else if (op === "sub") body = `for ${iv}=1,${lp} do ${dp}[${iv}]=L[114](${dp}[${iv}]-${val}+256,255) end`;
  else {
    const tv = ngen.next();
    body = `for ${iv}=1,${lp}-1,2 do `
      + `local ${tv}=${dp}[${iv}];${dp}[${iv}]=${dp}[${iv}+1];${dp}[${iv}+1]=${tv} `
      + `end`;
  }
  const real_code = `${body};return ${dp}`;
  const { code, trigger } = _wrapReal(name, params, cv, real_code, { ngen });
  return { code, ci, trigger, num_params: np };
}

function _sha256_body(sp, sha_words, ngen) {
  const AND = "L[114]"; const OR = "L[115]"; const RS = "L[116]"; const LS = "L[41]";
  const BYTE = "L[106]"; const ERR = "L[39]"; const X = "L[31]"; const M = "4294967296";
  const n = ngen;
  const nine = []; for (let i = 0; i < 9; i++) nine.push(n.next());
  const [b, ml, i, lo, off, w, Hs, nb, blk] = nine;
  const rotr = n.next();
  const xp = n.next(); const mp = n.next();
  const eight = []; for (let k = 0; k < 8; k++) eight.push(n.next());
  const [a, bb, cc, dd, ee, ff, gg, hh] = eight;
  const Kv = n.next(); const Ev = n.next();
  const x1 = n.next(); const s0 = n.next(); const x2 = n.next(); const s1 = n.next();
  const S1 = n.next(); const ch = n.next(); const t1 = n.next(); const S0 = n.next(); const mj = n.next(); const t2 = n.next();
  const kvals = SHA256_K.join(",");
  const exp = sha_words.join(",");
  const xor3 = (p, q, r) => `${X}(${X}(${p},${q}),${r})`;
  const xor2 = (p, q) => `${X}(${p},${q})`;
  return `local ${b}={};local ${ml}=#${sp};`
    + `for ${i}=1,${ml} do ${b}[${i}]=${BYTE}(${sp},${i}) end;`
    + `${b}[#${b}+1]=128;`
    + `while (#${b}%64)~=56 do ${b}[#${b}+1]=0 end;`
    + `local ${lo}=${ml}*8;`
    + `${b}[#${b}+1]=0;${b}[#${b}+1]=0;${b}[#${b}+1]=0;${b}[#${b}+1]=0;`
    + `${b}[#${b}+1]=${AND}(${RS}(${lo},24),255);${b}[#${b}+1]=${AND}(${RS}(${lo},16),255);`
    + `${b}[#${b}+1]=${AND}(${RS}(${lo},8),255);${b}[#${b}+1]=${AND}(${lo},255);`
    + `local ${Hs}={1779033703,3144134277,1013904242,2773480762,1359893119,2600822924,528734635,1541459225};`
    + `local ${Kv}={${kvals}};`
    + `local function ${rotr}(${xp},${mp}) return ${AND}(${OR}(${RS}(${xp},${mp}),${LS}(${xp},32-${mp})),4294967295) end;`
    + `local ${nb}=#${b}/64;`
    + `for ${blk}=0,${nb}-1 do `
    + `local ${off}=${blk}*64;local ${w}={};`
    + `for ${i}=0,15 do `
    + `${w}[${i}]=${OR}(${LS}(${b}[${off}+${i}*4+1],24),${OR}(${LS}(${b}[${off}+${i}*4+2],16),`
    + `${OR}(${LS}(${b}[${off}+${i}*4+3],8),${b}[${off}+${i}*4+4]))) end;`
    + `for ${i}=16,63 do `
    + `local ${x1}=${w}[${i}-15];local ${s0}=${xor3(`${rotr}(${x1},7)`, `${rotr}(${x1},18)`, `${RS}(${x1},3)`)};`
    + `local ${x2}=${w}[${i}-2];local ${s1}=${xor3(`${rotr}(${x2},17)`, `${rotr}(${x2},19)`, `${RS}(${x2},10)`)};`
    + `${w}[${i}]=((${w}[${i}-16]+${s0}+${w}[${i}-7]+${s1})%${M}) end;`
    + `local ${a},${bb},${cc},${dd},${ee},${ff},${gg},${hh}=`
    + `${Hs}[1],${Hs}[2],${Hs}[3],${Hs}[4],${Hs}[5],${Hs}[6],${Hs}[7],${Hs}[8];`
    + `for ${i}=0,63 do `
    + `local ${S1}=${xor3(`${rotr}(${ee},6)`, `${rotr}(${ee},11)`, `${rotr}(${ee},25)`)};`
    + `local ${ch}=${xor2(`${AND}(${ee},${ff})`, `${AND}(4294967295-${ee},${gg})`)};`
    + `local ${t1}=((${hh}+${S1}+${ch}+${Kv}[${i}+1]+${w}[${i}])%${M});`
    + `local ${S0}=${xor3(`${rotr}(${a},2)`, `${rotr}(${a},13)`, `${rotr}(${a},22)`)};`
    + `local ${mj}=${xor3(`${AND}(${a},${bb})`, `${AND}(${a},${cc})`, `${AND}(${bb},${cc})`)};`
    + `local ${t2}=((${S0}+${mj})%${M});`
    + `${hh}=${gg};${gg}=${ff};${ff}=${ee};${ee}=((${dd}+${t1})%${M});`
    + `${dd}=${cc};${cc}=${bb};${bb}=${a};${a}=((${t1}+${t2})%${M}) end;`
    + `${Hs}[1]=((${Hs}[1]+${a})%${M});${Hs}[2]=((${Hs}[2]+${bb})%${M});`
    + `${Hs}[3]=((${Hs}[3]+${cc})%${M});${Hs}[4]=((${Hs}[4]+${dd})%${M});`
    + `${Hs}[5]=((${Hs}[5]+${ee})%${M});${Hs}[6]=((${Hs}[6]+${ff})%${M});`
    + `${Hs}[7]=((${Hs}[7]+${gg})%${M});${Hs}[8]=((${Hs}[8]+${hh})%${M}) end;`
    + `local ${Ev}={${exp}};`
    + `for ${i}=1,8 do if ${Hs}[${i}]~=${Ev}[${i}] then ${ERR}('') end end;`
    + `return ${sp}`;
}

function gen_real_sha256verify_handler(name, sha_words, ngen) {
  const np = randint(9, 14);
  const params = pick_params(np);
  const ci = np - 1;
  const cv = params[ci];
  const sp = params[1];
  const real_code = _sha256_body(sp, sha_words, ngen);
  const { code, trigger } = _wrapReal(name, params, cv, real_code, { ngen });
  return { code, ci, trigger, num_params: np };
}

// ══════════════════════════════════════════════════════════════════════
//  Sa DISPATCH LOOP
// ══════════════════════════════════════════════════════════════════════
function gen_sa_function(entry_name, real_handlers, fake_handler_names, data_indices, sbox_index, ngen) {
  const pipeline = [
    ["collect", "collect"],
    ["b64decode", "b64"],
    ["noise_xor1", "std"],
    ["noise_xor1b", "std"],
    ["unblock", "std"],
    ["noise_add", "std"],
    ["noise_sub", "std"],
    ["unrotate", "std"],
    ["noise_swap1", "std"],
    ["noise_swap1b", "std"],
    ["invsbox", "sbox"],
    ["noise_xor2", "std"],
    ["noise_xor2b", "std"],
    ["xordecrypt", "std"],
    ["sha256verify", "sha"],
    ["execute", "exec"],
  ];
  const num_real = pipeline.length;
  const num_fake_states = randint(20, 40);
  const total_states = num_real + num_fake_states;
  const all_ids = sampleRange(0, total_states * 4, total_states);
  const real_ids = all_ids.slice(0, num_real);
  const fake_ids = all_ids.slice(num_real);

  const init_a = randint(1, 255);
  const init_b = real_ids[0] ^ init_a;

  const states = {};

  function _mk_transition(cur_id, next_id) {
    const key_val = cur_id ^ next_id;
    const a = randint(1, 255);
    const b = key_val ^ a;
    return `U=L[31](U,L[31](${a},${b}));`;
  }

  function _std_args(h) {
    const args = [];
    for (let i = 1; i < h.num_params; i++) {
      if (i === 1) args.push("_");
      else if (i === 2) args.push("H");
      else if (i === h.ci) args.push(String(h.trigger));
      else args.push(String(randint(0, 255)));
    }
    return args;
  }
  function _collect_args(h) {
    const args = [];
    const dpi = h.data_param_indices || [];
    for (let i = 1; i < h.num_params; i++) {
      if (dpi.includes(i)) { const pos = dpi.indexOf(i); args.push(`L[${data_indices[pos]}]`); }
      else if (i === h.ci) args.push(String(h.trigger));
      else args.push(String(randint(0, 255)));
    }
    return args;
  }
  function _sbox_args(h) {
    const args = [];
    for (let i = 1; i < h.num_params; i++) {
      if (i === 1) args.push("_");
      else if (i === 2) args.push(`L[${sbox_index}]`);
      else if (i === 3) args.push("H");
      else if (i === h.ci) args.push(String(h.trigger));
      else args.push(String(randint(0, 255)));
    }
    return args;
  }

  for (let si = 0; si < pipeline.length; si++) {
    const [key, role] = pipeline[si];
    const cur_id = real_ids[si];
    if (role === "exec") {
      states[cur_id] = "local B=L[130](_);if not B then L[39]('') end;return B;";
      continue;
    }
    const h = real_handlers[key];
    let call;
    if (role === "collect") call = `_=L:${h.name}(${_collect_args(h).join(",")});`;
    else if (role === "b64") call = `_,H=L:${h.name}(${_std_args(h).join(",")});`;
    else if (role === "sbox") call = `_=L:${h.name}(${_sbox_args(h).join(",")});`;
    else if (role === "sha") call = `_=L:${h.name}(${_std_args(h).join(",")});`;
    else call = `_=L:${h.name}(${_std_args(h).join(",")});`;
    const next_id = real_ids[si + 1];
    states[cur_id] = call + _mk_transition(cur_id, next_id);
  }

  for (const fid of fake_ids) {
    if (fake_handler_names.length) {
      const fh = choice(fake_handler_names);
      const fargs = Array.from({ length: randint(4, 8) }, () => String(randint(0, 255))).join(",");
      const other_fake = choice(fake_ids);
      const ftk = fid ^ other_fake;
      states[fid] = `L:${fh}(${fargs});U=L[31](U,${ftk});`;
    } else {
      states[fid] = "U=0;";
    }
  }

  const sorted_ids = Object.keys(states).map(Number).sort((a, b) => a - b);

  function build_tree(ids, depth = 0) {
    if (!ids.length) return "";
    if (ids.length === 1) { const sid = ids[0]; return `if U==${sid} then ${states[sid]}end;`; }
    if (ids.length === 2) { const [s1, s2] = ids; return `if U==${s1} then ${states[s1]}elseif U==${s2} then ${states[s2]}end;`; }
    const mid_idx = Math.floor(ids.length / 2);
    const left = ids.slice(0, mid_idx);
    const right = ids.slice(mid_idx);
    const pivot = left[left.length - 1];
    const lc = build_tree(left, depth + 1);
    const rc = build_tree(right, depth + 1);
    return `if U<=${pivot} then ${lc}else ${rc}end;`;
  }

  const dispatch = build_tree(sorted_ids);
  return `${entry_name}=function(L,...)`
    + `local U=L[31](${init_a},${init_b});`
    + `local _,H;`
    + `while true do `
    + `${dispatch}`
    + `end;end`;
}

// ══════════════════════════════════════════════════════════════════════
//  BUILTINS
// ══════════════════════════════════════════════════════════════════════
const ALL_BUILTINS = {
  0: "buffer.writef32", 1: "buffer.readu16", 2: "table.sort",
  3: "buffer.readu8", 4: "table.remove", 5: "setmetatable",
  6: "math.floor", 7: "math.abs", 8: "math.max",
  9: "rawget", 10: "buffer.writei8", 11: "buffer.writeu8",
  12: "string.unpack", 13: "math.min", 14: "string.format",
  15: "string.rep", 16: "table.freeze", 17: "math.random",
  18: "rawequal", 19: "buffer.copy", 20: "math.ceil",
  21: "string.match", 22: "table.isfrozen", 23: "buffer.readf64",
  24: "buffer.readf32", 25: "table.concat", 26: "coroutine.resume",
  27: "select", 28: "math.log",
  29: "buffer.writei32", 30: "tostring",
  31: "bit32.bxor", 32: "tonumber",
  33: "assert", 34: "string.char", 35: "bit32.rrotate",
  36: "table.insert", 37: "buffer.writestring", 38: "bit32.bnot",
  39: "error", 40: "coroutine.yield", 41: "bit32.lshift",
  42: "math.sqrt", 43: "rawlen", 44: "string.sub",
  45: "bit32.lrotate", 46: "math.huge", 47: "math.pi",
  48: "table.find", 49: "math.clamp", 50: "typeof",
  51: "table.clear", 52: "getmetatable", 53: "newproxy",
  54: "math.sign", 55: "math.round",
  56: "bit32.countlz", 57: "coroutine.isyieldable",
  58: "buffer.fromstring", 59: "bit32.countrz",
  60: "table.create", 61: "table.create", 62: "math.fmod",
  63: "bit32.extract", 64: "buffer.readi8", 65: "string.gsub",
  66: "bit32.replace", 67: "math.pow", 68: "math.exp",
  69: "math.atan2", 70: "bit32.countlz", 71: "bit32.arshift",
  72: "buffer.fill", 73: "math.sin", 74: "math.cos",
  75: "math.tan", 76: "math.asin", 77: "buffer.writef64",
  78: "math.acos", 79: "math.atan",
  80: "unpack", 81: "coroutine.running", 82: "rawset",
  83: "math.modf", 84: "math.frexp", 85: "math.ldexp",
  86: "buffer.create", 87: "math.noise",
  88: "string.lower", 89: "string.upper", 90: "string.reverse",
  91: "string.len", 92: "string.pack", 93: "buffer.readu32",
  94: "buffer.readstring", 95: "table.getn",
  96: "buffer.readi16", 97: "buffer.readu16",
  98: "bit32.byteswap", 99: "pcall",
  100: "table.foreach", 101: "buffer.writeu32",
  102: "table.foreachi", 103: "coroutine.close",
  104: "select", 105: "string.gmatch", 106: "string.byte",
  107: "table.maxn", 108: "string.split",
  109: "table.pack", 110: "buffer.writei16",
  111: "type", 112: "string.find", 113: "bit32.btest",
  114: "bit32.band", 115: "bit32.bor", 116: "bit32.rshift",
  117: "xpcall", 118: "buffer.readi32",
  119: "table.unpack", 120: "table.move",
  121: "buffer.len", 122: "buffer.tostring",
  123: "buffer.writeu16", 124: "coroutine.create",
  125: "pcall", 126: "coroutine.wrap", 127: "tostring",
  130: "loadstring",
};

// ══════════════════════════════════════════════════════════════════════
//  FULL OUTPUT GENERATOR
// ══════════════════════════════════════════════════════════════════════
function generate_luarmor_output(bc_data, source, settings, mode = "shadowvm") {
  const ngen = new NameGen();
  const strength = settings.vm_strength != null ? settings.vm_strength : 5;
  const superflow_name = "superflow_bytecode";

  const num_handlers = Math.max(30, strength * 30);
  const dispatch_depth = Math.min(14, 6 + Math.floor(strength / 3));

  let header;
  if (mode === "luarmor") {
    header = "--[[\n"
      + "        Voltra Obfuscator. \n"
      + "        discord.gg/voltrahub\n"
      + "\n"
      + "]]";
  } else {
    header = "--[[\n"
      + "        ShadowVM V4 bytecode-protected script. \n"
      + " this code deserializes & decrypts & executes compiled bytecode via custom VM interpreter.../\n"
      + "        https://shadowvm.dev/\n"
      + "\n"
      + "]]";
  }

  const data_indices = sampleRange(1000, 9999, bc_data.num_groups).sort((a, b) => a - b);
  const data_entries = [];
  bc_data.groups.forEach((group, gi) => {
    const escaped = chunks_to_escaped_strings(group);
    data_entries.push([data_indices[gi], `{${escaped}}`]);
  });

  let sbox_index = randint(500, 999);
  while (data_indices.includes(sbox_index)) sbox_index = randint(500, 999);
  const inv_sbox_str = '"' + bc_data.inv_sbox.map((b) => `\\${b}`).join("") + '"';

  // Scale builtins with strength
  const num_builtins = Math.min(Object.keys(ALL_BUILTINS).length, 20 + strength * 4);
  const builtin_keys = Object.keys(ALL_BUILTINS).map(Number).sort((a, b) => a - b).slice(0, num_builtins);
  const builtin_items = builtin_keys.map((k) => [k, ALL_BUILTINS[k]]);

  const required_builtins = [25, 31, 34, 39, 41, 106, 111, 114, 115, 116, 130];
  const included_keys = new Set(builtin_items.map(([k]) => k));
  for (const idx of required_builtins) {
    if (!included_keys.has(idx) && idx in ALL_BUILTINS) builtin_items.push([idx, ALL_BUILTINS[idx]]);
  }

  // Inline watermark builtins
  const num_inline = 2 + Math.floor(strength / 3);
  const inline_ids = sampleRange(140, 250, Math.min(num_inline, 50));
  for (const fid of inline_ids) {
    const p = choice("LorV".split(""));
    const h1 = choices("0123456789abcdef".split(""), randint(12, 32)).join("");
    const h2 = choices("0123456789abcdef".split(""), 6).join("");
    const h3 = choices("0123456789abcdef".split(""), randint(16, 32)).join("");
    builtin_items.push([fid, `function(${p},${p})return function()return  "${h1}", "${h2}", "${h3}" ;end;end`]);
  }
  builtin_items.sort((a, b) => a[0] - b[0]);

  // Fake handlers (decoys)
  const handler_names = [];
  const handler_entries = [];
  const handler_types = [
    gen_handler_classic, gen_handler_conditional_not, gen_handler_buffer_chain,
    gen_handler_string_ops, gen_handler_table_state, gen_handler_multi_decode,
    gen_handler_integrity_check, gen_handler_env_sandbox,
  ];
  for (let k = 0; k < num_handlers; k++) {
    const hname = ngen.next();
    handler_names.push(hname);
    const gen_func = choice(handler_types);
    handler_entries.push(gen_func(hname, ngen));
  }
  for (let k = 0; k < 1 + Math.floor(strength / 5); k++) {
    const cn = ngen.next();
    handler_entries.push(gen_coroutine_handler(cn));
    handler_names.push(cn);
  }
  for (let k = 0; k < Math.floor(strength / 4); k++) {
    const sn = ngen.next();
    handler_entries.push(gen_sub_dispatcher(sn, handler_names, ngen));
    handler_names.push(sn);
  }
  const f_name = ngen.next();
  handler_entries.push(gen_f_function(f_name, handler_names, ngen, dispatch_depth));
  const ur_name = ngen.next();
  handler_entries.push(gen_ur_function(ur_name));

  // Real handler chain — keys split so real values never appear literally
  const mk_a = randint(1, 255); const mk_b = bc_data.master_key ^ mk_a;
  const xk_a = randint(1, 255); const xk_b = bc_data.xor_key ^ xk_a;
  const bk_a = randint(1, 255); const bk_b = bc_data.block_key ^ bk_a;
  const noise_xor1_val = bc_data.noise_xor;
  const noise_add_val = bc_data.noise_add;
  const noise_xor2_val = randint(1, 255);

  function _mk_real(gen_fn, ...args) {
    const nm = ngen.next();
    const h = gen_fn(nm, ...args, ngen);
    handler_entries.push(h.code);
    return { ...h, name: nm };
  }

  let collect_hdl;
  if (mode === "luarmor") collect_hdl = _mk_real(gen_real_collect_global_handler, superflow_name);
  else collect_hdl = _mk_real(gen_real_collect_handler, data_indices);

  const real_handlers = {
    collect: collect_hdl,
    b64decode: _mk_real(gen_real_b64decode_handler, bc_data.data_len, bc_data.custom_alphabet),
    noise_xor1: _mk_real(gen_real_noise_handler, "xor", noise_xor1_val),
    noise_xor1b: _mk_real(gen_real_noise_handler, "xor", noise_xor1_val),
    unblock: _mk_real(gen_real_unblock_handler, bk_a, bk_b),
    noise_add: _mk_real(gen_real_noise_handler, "add", noise_add_val),
    noise_sub: _mk_real(gen_real_noise_handler, "sub", noise_add_val),
    unrotate: _mk_real(gen_real_unrotate_handler),
    noise_swap1: _mk_real(gen_real_noise_handler, "swap", 0),
    noise_swap1b: _mk_real(gen_real_noise_handler, "swap", 0),
    invsbox: _mk_real(gen_real_invsbox_handler),
    noise_xor2: _mk_real(gen_real_noise_handler, "xor", noise_xor2_val),
    noise_xor2b: _mk_real(gen_real_noise_handler, "xor", noise_xor2_val),
    xordecrypt: _mk_real(gen_real_xordecrypt_handler, mk_a, mk_b, xk_a, xk_b),
    sha256verify: _mk_real(gen_real_sha256verify_handler, bc_data.sha_words),
  };

  const entry_name = ngen.entry();
  const sa_code = gen_sa_function(entry_name, real_handlers, handler_names, data_indices, sbox_index, ngen);
  handler_entries.push(sa_code);

  // Interleave data + builtins + handlers
  const all_entries = [];
  let superflow_literal = null;
  if (mode === "luarmor") {
    const superflow_frags = [];
    for (const group of bc_data.groups) for (const frag of group) superflow_frags.push(frag);
    superflow_literal = "{" + superflow_frags.map((f) => `"${f}"`).join(",") + "}";
  } else {
    for (const [didx, dval] of data_entries) all_entries.push(`[${didx}]=${dval}`);
  }
  all_entries.push(`[${sbox_index}]=${inv_sbox_str}`);

  let bi = 0; let hi = 0;
  const start_b = Math.min(3, builtin_items.length);
  while (bi < start_b) {
    const [idx, val] = builtin_items[bi];
    all_entries.push(`[${idx}]=${val}`); bi += 1;
  }
  while (bi < builtin_items.length || hi < handler_entries.length) {
    const num_h = randint(1, 4);
    for (let k = 0; k < num_h; k++) {
      if (hi < handler_entries.length) { all_entries.push(handler_entries[hi]); hi += 1; }
    }
    const num_b = randint(1, 2);
    for (let k = 0; k < num_b; k++) {
      if (bi < builtin_items.length) { const [idx, val] = builtin_items[bi]; all_entries.push(`[${idx}]=${val}`); bi += 1; }
    }
  }
  while (hi < handler_entries.length) { all_entries.push(handler_entries[hi]); hi += 1; }
  while (bi < builtin_items.length) { const [idx, val] = builtin_items[bi]; all_entries.push(`[${idx}]=${val}`); bi += 1; }

  // Metatable
  let meta_trap;
  if (mode === "luarmor") meta_trap = "{}";
  else if (strength >= 5) {
    const idx_n = ngen.next(); const ni_n = ngen.next(); const call_n = ngen.next();
    meta_trap = `{__index=function(${idx_n},${ni_n})`
      + `return rawget(${idx_n},${ni_n}) or error('');`
      + `end,`
      + `__newindex=function(${idx_n},${ni_n},${call_n})`
      + `rawset(${idx_n},${ni_n},${call_n});`
      + `end,`
      + `__call=function(${idx_n},...)`
      + `return ${idx_n}:${entry_name}()(...);`
      + `end}`;
  } else meta_trap = "{}";

  const vm_table = all_entries.join(",");
  const ret_line = `return setmetatable({${vm_table}},${meta_trap}):${entry_name}()(...);`;

  if (mode === "luarmor") {
    return header + "\n\n" + `${superflow_name}=${superflow_literal}\n` + ret_line;
  }
  return header + "\n\n" + ret_line;
}

// ══════════════════════════════════════════════════════════════════════
//  PRE-PROCESSING PASSES
// ══════════════════════════════════════════════════════════════════════
function pass_strip_comments(tokens) { return tokens.filter(([t]) => t !== "comment"); }

function pass_encrypt_strings(tokens, strength = 5) {
  const result = [];
  for (const [t, v] of tokens) {
    if (t === "string" && (v[0] === '"' || v[0] === "'") && v.length > 2) {
      const inner = v.slice(1, -1);
      if (inner.includes("\\")) { result.push([t, v]); continue; }
      const key1 = randint(1, 254);
      const key2 = randint(1, 254);
      if (strength >= 10) {
        const enc = [];
        for (let ci = 0; ci < inner.length; ci++) {
          let b = inner.charCodeAt(ci);
          b ^= key1;
          const shift = (ci % 7) + 1;
          b = ((b << shift) | (b >> (8 - shift))) & 0xff;
          b ^= key2;
          enc.push(b);
        }
        const byte_str = enc.join(",");
        const expr = `(function() local _s={} local _k1,_k2=${key1},${key2} `
          + `for _i,_b in ipairs({${byte_str}}) do `
          + `local _v=bit32.bxor(_b,_k2) `
          + `local _sh=(_i-1)%7+1 `
          + `_v=bit32.band(bit32.bor(bit32.rshift(_v,_sh),bit32.lshift(_v,8-_sh)),255) `
          + `_s[#_s+1]=string.char(bit32.band(bit32.bxor(_v,_k1),255)) end `
          + `return table.concat(_s) end)()`;
        result.push(["raw", expr]);
      } else {
        const enc = [];
        for (let ci = 0; ci < inner.length; ci++) enc.push((inner.charCodeAt(ci) ^ key1 ^ ((key2 + ci) % 256)) & 0xff);
        const byte_str = enc.join(",");
        const expr = `(function() local _s={} local _k=${key1} local _k2=${key2} `
          + `for _i,_b in ipairs({${byte_str}}) do `
          + `_s[#_s+1]=string.char(bit32.bxor(bit32.bxor(_b,_k),bit32.band(_k2+_i-1,255))) end `
          + `return table.concat(_s) end)()`;
        result.push(["raw", expr]);
      }
    } else {
      result.push([t, v]);
    }
  }
  return result;
}

function pass_encode_numbers(tokens, strength = 5) {
  const result = [];
  for (const [t, v] of tokens) {
    if (t === "number") {
      if (v.includes(".") || v.toLowerCase().includes("e")) { result.push([t, v]); continue; }
      let num;
      try {
        num = v.toLowerCase().startsWith("0x") ? parseInt(v, 16) : parseInt(v, 10);
        if (Number.isNaN(num)) { result.push([t, v]); continue; }
      } catch (e) { result.push([t, v]); continue; }
      if (num >= 0 && num <= 0x7fffffff) {
        const k1 = randint(1, 0xffff);
        const k2 = randint(1, 0xffff);
        const k3 = randint(1, 0xffff);
        if (strength >= 10) {
          const enc = num ^ k1 ^ k2 ^ k3;
          result.push(["raw", `bit32.bxor(bit32.bxor(bit32.bxor(${enc},${k3}),${k2}),${k1})`]);
        } else {
          const enc = num ^ k1 ^ k2;
          result.push(["raw", `bit32.bxor(bit32.bxor(${enc},${k2}),${k1})`]);
        }
      } else {
        result.push([t, v]);
      }
    } else {
      result.push([t, v]);
    }
  }
  return result;
}

function pass_rename_variables(tokens) {
  const gen = new NameGen();
  const scope_vars = new Set();
  const n = tokens.length;
  for (let idx = 0; idx < n; idx++) {
    const [t, v] = tokens[idx];
    if (t === "kw" && v === "local") {
      let j = idx + 1;
      while (j < n && tokens[j][0] === "ws") j += 1;
      while (j < n && tokens[j][0] === "id") {
        scope_vars.add(tokens[j][1]); j += 1;
        while (j < n && tokens[j][0] === "ws") j += 1;
        if (j < n && tokens[j][1] === ",") {
          j += 1;
          while (j < n && tokens[j][0] === "ws") j += 1;
        } else break;
      }
    } else if (t === "kw" && (v === "function" || v === "for")) {
      let j = idx + 1;
      while (j < n && tokens[j][0] === "ws") j += 1;
      if (v === "function") {
        while (j < n && tokens[j][0] !== "op") j += 1;
        if (j < n && tokens[j][1] === "(") {
          j += 1;
          while (j < n && tokens[j][1] !== ")") {
            if (tokens[j][0] === "id") scope_vars.add(tokens[j][1]);
            j += 1;
          }
        }
      } else {
        while (j < n && tokens[j][0] === "id") {
          scope_vars.add(tokens[j][1]); j += 1;
          while (j < n && tokens[j][0] === "ws") j += 1;
          if (j < n && tokens[j][1] === ",") {
            j += 1;
            while (j < n && tokens[j][0] === "ws") j += 1;
          } else break;
        }
      }
    }
  }
  const result = [];
  for (const [t, v] of tokens) {
    if (t === "id" && scope_vars.has(v)) result.push([t, gen.get(v)]);
    else result.push([t, v]);
  }
  return result;
}

function pass_junk_code(tokens, strength = 5) {
  const gen = new NameGen();
  const patterns = [
    (v) => ` if false then local ${v}=0 end `,
    (v) => ` do local ${v}=nil;if ${v} then ${v}=0 end end `,
    () => ` if true and false then error("") end `,
    (v) => ` do local ${v}=0;while ${v}>1 do ${v}=${v}-1 end end `,
    (v) => ` do local ${v}={} end `,
    (v) => ` if not not false then local ${v}=0 end `,
    (v) => ` do local ${v}=table.create(0);table.clear(${v}) end `,
    (v) => ` do local ${v}=0;${v}=${v}+1;${v}=nil end `,
  ];
  const freq = Math.min(0.6, 0.15 + strength * 0.02);
  const result = [];
  for (const [t, v] of tokens) {
    result.push([t, v]);
    if ((t === "kw" && v === "end") || (t === "op" && v === ";")) {
      if (rnd() < freq) result.push(["raw", choice(patterns)(gen.next())]);
    }
  }
  return result;
}

function pass_control_flow(tokens, strength = 5) {
  const result = [];
  for (const [t, v] of tokens) {
    if (t === "kw" && v === "if") {
      if (strength >= 10) {
        const a = randint(100, 999); const b = randint(100, 999); const c = randint(1, 99);
        result.push([t, v]);
        result.push(["raw", ` (bit32.bxor(${a},${b})==${a ^ b}) and ((${c}+${c})==${c * 2}) and`]);
      } else {
        const a = randint(100, 999); const b = randint(100, 999);
        result.push([t, v]);
        result.push(["raw", ` (${a}+${b}==${a + b}) and`]);
      }
    } else if (t === "kw" && v === "while") {
      if (strength >= 10) {
        const a = randint(100, 999); const b = randint(100, 999);
        result.push([t, v]);
        result.push(["raw", ` (bit32.band(${a},${b})==${a & b}) and`]);
      } else {
        const a = randint(100, 999);
        result.push([t, v]);
        result.push(["raw", ` (${a}==${a}) and`]);
      }
    } else {
      result.push([t, v]);
    }
  }
  return result;
}

function pass_minify(tokens) {
  const result = []; let prev_needs = false;
  for (const [t, v] of tokens) {
    if (t === "ws") {
      if (prev_needs) { result.push(["ws", " "]); prev_needs = false; }
      continue;
    }
    const needs = ["id", "kw", "global", "number", "raw"].includes(t);
    if (needs && prev_needs) result.push(["ws", " "]);
    result.push([t, v]); prev_needs = needs;
  }
  return result;
}

function tokens_to_string(tokens) { return tokens.map(([, v]) => v).join(""); }

// ══════════════════════════════════════════════════════════════════════
//  MASTER PIPELINE
// ══════════════════════════════════════════════════════════════════════
function obfuscateLuau(source, settings = {}) {
  const stats = { original_size: source.length, passes: [] };
  const strength = settings.vm_strength != null ? settings.vm_strength : 5;
  const get = (k, d) => (settings[k] != null ? settings[k] : d);

  let tokens = tokenize(source);

  if (get("strip_comments", true)) { tokens = pass_strip_comments(tokens); stats.passes.push("strip_comments"); }
  if (get("encrypt_strings", true)) { tokens = pass_encrypt_strings(tokens, strength); stats.passes.push("encrypt_strings"); }
  if (get("encode_numbers", true)) { tokens = pass_encode_numbers(tokens, strength); stats.passes.push("encode_numbers"); }
  if (get("rename_variables", true)) { tokens = pass_rename_variables(tokens); stats.passes.push("rename_variables"); }
  if (get("junk_code", true)) { tokens = pass_junk_code(tokens, strength); stats.passes.push("junk_code"); }
  if (get("control_flow", true)) { tokens = pass_control_flow(tokens, strength); stats.passes.push("control_flow"); }
  if (get("minify", false)) { tokens = pass_minify(tokens); stats.passes.push("minify"); }

  const processed_source = tokens_to_string(tokens);

  let layers = get("layers", 2);
  layers = parseInt(layers, 10);
  if (Number.isNaN(layers)) layers = 2;
  layers = Math.max(1, Math.min(5, layers));

  let code = processed_source;
  let inner_size = null;
  for (let li = 0; li < layers; li++) {
    const is_last = li === layers - 1;
    const mode = is_last ? "luarmor" : "shadowvm";
    const bc = compile_to_bytecode(code, settings);
    code = generate_luarmor_output(bc, code, settings, mode);
    stats.passes.push(`layer${li + 1}_${is_last ? "luarmor" : "shadowvm"}`);
    if (li === 0) inner_size = code.length;
  }

  if (get("arith_constants", true)) { code = obfuscate_numbers(code); stats.passes.push("arith_constants(no_bare_numbers)"); }

  const num_handlers = Math.max(30, strength * 30);
  stats.obfuscated_size = code.length;
  stats.ratio = Math.round((code.length / Math.max(source.length, 1)) * 100) / 100;
  stats.inner_size = inner_size;
  stats.vm_layers = layers;
  stats.vm_handlers = num_handlers;

  return { code, stats };
}

// Test-only internals (used by the verification harness; harmless in the Worker).
const _internals = { compile_to_bytecode, sha256Words, tokenize, tokens_to_string };

export { obfuscateLuau, _internals };
