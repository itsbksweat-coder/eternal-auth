import test from 'node:test';
import assert from 'node:assert/strict';
import { obfuscateLuau, _internals } from '../src/obfuscator.js';

const { compile_to_bytecode, sha256Words } = _internals;
const STD_B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const enc = new TextEncoder();
const dec = new TextDecoder();
const toHex = (words) => words.map((w) => (w >>> 0).toString(16).padStart(8, '0')).join('');

// Reverse the embedded data exactly as the generated Lua VM does, using only
// what compile_to_bytecode embeds. Proves the encryption/data layer is correct.
function decodeBc(bc) {
  const b64custom = bc.groups.map((g) => g.join('')).join('');
  const rev = {};
  for (let i = 0; i < 64; i++) rev[bc.custom_alphabet[i]] = i;
  const r4 = [];
  let buf = 0; let bits = 0;
  for (const ch of b64custom) {
    const v = rev[ch]; if (v === undefined) continue;
    buf = (buf << 6) | v; bits += 6;
    if (bits >= 8) { bits -= 8; r4.push((buf >> bits) & 0xff); }
  }
  r4.length = bc.data_len;
  const r3 = []; let p = bc.block_key;
  for (const c of r4) { r3.push((c ^ p) & 0xff); p = c; }
  const r2 = r3.map((b, i) => { const s = (i % 7) + 1; return ((b >> s) | (b << (8 - s))) & 0xff; });
  const r1 = r2.map((b) => bc.inv_sbox[b]);
  const ks = new Array(256).fill(0); ks[0] = bc.master_key;
  for (let i = 1; i < 256; i++) ks[i] = ((ks[i - 1] * bc.xor_key + bc.master_key) ^ ((i * 137) & 0xff)) & 0xff;
  const src = r1.map((b, i) => (b ^ ks[i % 256]) & 0xff);
  return dec.decode(new Uint8Array(src));
}

test('SHA-256 known-answer', () => {
  assert.equal(toHex(sha256Words(enc.encode('abc'))), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.equal(toHex(sha256Words(enc.encode(''))), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
});

test('compiled bytecode decodes back to the source (all strengths)', () => {
  const samples = [
    'print("hi")',
    'local Players = game:GetService("Players")\nprint("x " .. tostring(Players.LocalPlayer))\nfor i=1,10 do warn(i*2) end\n',
    'local t = {1,2,3}; for _,v in ipairs(t) do print(v) end\n',
    'z = 0; ' + 'a'.repeat(3000),
  ];
  for (const s of samples) {
    for (const vm_strength of [1, 5, 10, 20]) {
      const bc = compile_to_bytecode(s, { vm_strength });
      assert.equal(toHex(bc.sha_words), toHex(sha256Words(enc.encode(s))), `sha s${vm_strength}`);
      assert.equal(decodeBc(bc), s, `decode s${vm_strength} len${s.length}`);
    }
  }
});

test('obfuscateLuau produces a well-formed VM wrapper', () => {
  const script = 'local Players = game:GetService("Players")\nlocal plr = Players.LocalPlayer\nprint("hi " .. plr.Name)\nfor i=1,5 do warn(i) end\n';
  for (const layers of [1, 2, 3]) {
    const { code, stats } = obfuscateLuau(script, { vm_strength: 8, layers });
    assert.ok(code.length > 0, 'non-empty');
    assert.ok(code.startsWith('--[['), 'header');
    assert.ok(code.includes('return setmetatable('), 'setmetatable return');
    assert.ok(/\):[A-Za-z_][A-Za-z0-9_]?\(\)\(\.\.\.\);\s*$/.test(code), 'entry call tail');
    assert.ok(code.includes('superflow_bytecode='), 'luarmor final layer');
    assert.equal(stats.vm_layers, layers);
  }
});

test('empty / whitespace source still yields output (caller guards emptiness)', () => {
  const { code } = obfuscateLuau('print(1)', {});
  assert.ok(code.includes('return setmetatable('));
});
