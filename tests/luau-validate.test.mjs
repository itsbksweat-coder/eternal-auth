import test from 'node:test';
import assert from 'node:assert/strict';
import { validateProtectedLua } from '../src/luau-validate.js';

test('accepts ordinary Luau', () => {
  assert.equal(validateProtectedLua('local a = 1\nprint(a)\n').ok, true);
});

test('accepts a minified obfuscated-style one-liner', () => {
  const src = 'local a={1,2,3};local function f(x)return x[1]..x[2]end;print(f(a))';
  assert.equal(validateProtectedLua(src).ok, true);
});

test('accepts two call statements on one line (no false positive)', () => {
  // `x() y()` is valid Luau (two statements) — a naive adjacency check would
  // wrongly reject this.
  assert.equal(validateProtectedLua('print(1) print(2)').ok, true);
});

test('accepts long strings and long comments', () => {
  assert.equal(validateProtectedLua('local s=[==[ any ]] text ]==]\n--[[ c ]]\nreturn s').ok, true);
});

test('accepts strings containing brackets and quotes', () => {
  assert.equal(validateProtectedLua('local s=")(}{][" local t=\'a"b\' return s,t').ok, true);
});

test('accepts escaped quote and line-continuation in strings', () => {
  assert.equal(validateProtectedLua('local s="a\\"b" local u="line\\\ncont"').ok, true);
});

test('accepts backtick interpolated string with inner braces', () => {
  assert.equal(validateProtectedLua('local n=5 local s=`value is {n}!` return s').ok, true);
});

test('rejects empty / whitespace-only source', () => {
  assert.equal(validateProtectedLua('').ok, false);
  assert.equal(validateProtectedLua('   \n\t ').ok, false);
});

test('rejects unterminated string', () => {
  const r = validateProtectedLua('local s="oops\nprint(s)');
  assert.equal(r.ok, false);
  assert.match(r.error, /unterminated string/);
});

test('rejects unterminated long string', () => {
  const r = validateProtectedLua('local s=[[ never closed');
  assert.equal(r.ok, false);
  assert.match(r.error, /unterminated long string/);
});

test('rejects unbalanced / truncated brackets', () => {
  const r = validateProtectedLua('local function f() return (1+2 end');
  assert.equal(r.ok, false);
  assert.match(r.error, /unclosed|unexpected|mismatched/);
});

test('rejects mismatched brackets', () => {
  const r = validateProtectedLua('local t={1,2,3)');
  assert.equal(r.ok, false);
  assert.match(r.error, /mismatched|unexpected/);
});

test('a "]]" inside a short string is not treated as a long-string close', () => {
  assert.equal(validateProtectedLua('local s="]]" return s').ok, true);
});
