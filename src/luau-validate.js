// Conservative static validation for protected Luau source.
//
// This does NOT attempt to be a full Luau parser. It only flags breakage that
// is unambiguous and can never be a false positive on valid Luau, so that the
// auth server refuses to STORE or SERVE a protected script that could not
// possibly compile on the client:
//
//   * empty / whitespace-only source
//   * an unterminated string, long string, or long comment
//   * unbalanced ( ) [ ] { } brackets (truncated / corrupted uploads)
//
// The goal is to turn a cryptic client-side `loadstring` failure (which gets a
// player kicked) into a clear, owner-facing error at upload time. Subtle
// mistakes a real parser would catch (e.g. a missing statement separator) are
// intentionally left alone here to avoid ever rejecting a valid obfuscated
// one-liner — those are handled at runtime by the loader's graceful-failure
// path instead.

const OPEN = { "(": ")", "[": "]", "{": "}" };
const CLOSE = { ")": "(", "]": "[", "}": "{" };

function lineAt(source, index) {
  let line = 1;
  for (let i = 0; i < index && i < source.length; i++) {
    if (source[i] === "\n") line++;
  }
  return line;
}

// If `source` has a long-bracket opener at `i` ("[", "[=[", "[==[", ...),
// return the level (number of '='); otherwise return -1.
function longBracketLevel(source, i) {
  if (source[i] !== "[") return -1;
  let j = i + 1;
  let level = 0;
  while (source[j] === "=") { level++; j++; }
  return source[j] === "[" ? level : -1;
}

export function validateProtectedLua(input) {
  const source = typeof input === "string" ? input : String(input ?? "");

  if (!source.trim()) {
    return { ok: false, error: "source is empty" };
  }

  const stack = []; // { char, index }
  let i = 0;
  const n = source.length;

  while (i < n) {
    const c = source[i];

    // Line comment or long comment: "--"
    if (c === "-" && source[i + 1] === "-") {
      const level = longBracketLevel(source, i + 2);
      if (level >= 0) {
        const close = "]" + "=".repeat(level) + "]";
        const end = source.indexOf(close, i + 2 + level + 2);
        if (end === -1) {
          return { ok: false, error: `unterminated long comment (starts at line ${lineAt(source, i)})` };
        }
        i = end + close.length;
        continue;
      }
      // line comment: skip to end of line
      const nl = source.indexOf("\n", i + 2);
      i = nl === -1 ? n : nl;
      continue;
    }

    // Long string: "[[ ... ]]" / "[=[ ... ]=]"
    const level = longBracketLevel(source, i);
    if (level >= 0) {
      const close = "]" + "=".repeat(level) + "]";
      const end = source.indexOf(close, i + level + 2);
      if (end === -1) {
        return { ok: false, error: `unterminated long string (starts at line ${lineAt(source, i)})` };
      }
      i = end + close.length;
      continue;
    }

    // Short string: " ... " or ' ... '
    if (c === '"' || c === "'") {
      const startLine = lineAt(source, i);
      let j = i + 1;
      let closed = false;
      while (j < n) {
        const d = source[j];
        if (d === "\\") { j += 2; continue; } // escape (incl. line continuation)
        if (d === "\n") break;                // raw newline => unterminated
        if (d === c) { closed = true; j++; break; }
        j++;
      }
      if (!closed) {
        return { ok: false, error: `unterminated string (starts at line ${startLine})` };
      }
      i = j;
      continue;
    }

    // Interpolated string: ` ... ` — treated as opaque to avoid false
    // positives from its inner {expr} braces.
    if (c === "`") {
      const startLine = lineAt(source, i);
      let j = i + 1;
      let closed = false;
      while (j < n) {
        const d = source[j];
        if (d === "\\") { j += 2; continue; }
        if (d === "`") { closed = true; j++; break; }
        j++;
      }
      if (!closed) {
        return { ok: false, error: `unterminated interpolated string (starts at line ${startLine})` };
      }
      i = j;
      continue;
    }

    // Brackets
    if (OPEN[c]) {
      stack.push({ char: c, index: i });
      i++;
      continue;
    }
    if (CLOSE[c]) {
      const top = stack.pop();
      if (!top) {
        return { ok: false, error: `unexpected '${c}' at line ${lineAt(source, i)}` };
      }
      if (OPEN[top.char] !== c) {
        return {
          ok: false,
          error: `mismatched '${top.char}' (line ${lineAt(source, top.index)}) closed by '${c}' (line ${lineAt(source, i)})`,
        };
      }
      i++;
      continue;
    }

    i++;
  }

  if (stack.length) {
    const top = stack[stack.length - 1];
    return { ok: false, error: `unclosed '${top.char}' (opened at line ${lineAt(source, top.index)})` };
  }

  return { ok: true };
}

export default validateProtectedLua;
