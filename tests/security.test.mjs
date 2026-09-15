import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { DatabaseSync } from 'node:sqlite';
import { hwidCooldownSeconds } from '../src/device-security.js';
let source = await readFile(new URL('../src/index.js', import.meta.url), 'utf8');
source = source.replace('import { DurableObject } from "cloudflare:workers";', 'class DurableObject {}');
for (const file of ['dm-responder.js', 'device-security.js']) source = source.replace(`"./${file}"`, JSON.stringify(new URL(`../src/${file}`, import.meta.url).href));
source = source.replace('"../public/entry-loader.js"', JSON.stringify(new URL('../public/entry-loader.js', import.meta.url).href));
source += '\nexport { handlePublicLoader, handleFfaPublicLoader, handleFfaProtectedLoader, buildLoader, handleProtectedLoader, handleVerify, handleSecurityReport, resetOwnHwid, sha256Hex, hashDevice, buildBootstrapSource };';
const api = await import('data:text/javascript;base64,' + Buffer.from(source).toString('base64'));
async function fixture() {
  const db = new DatabaseSync(':memory:');
  db.exec(await readFile(new URL('../schema.sql', import.meta.url), 'utf8'));
  const prepare = (sql) => {
    let args = [];
    const stmt = { bind(...values) { args = values; return stmt; }, async first() { return db.prepare(sql).get(...args) || null; }, async run() { const r = db.prepare(sql).run(...args); return { meta: { changes: Number(r.changes) } }; }, async all() { return { results: db.prepare(sql).all(...args) }; } }; return stmt;
  };
  const env = { HWID_PEPPER: 'test-pepper', DB: { prepare, async batch(statements) { const out = []; for (const s of statements) out.push(await s.run()); return out; } } };
  db.prepare('INSERT INTO guilds (guild_id,created_at,updated_at) VALUES (?,0,0)').run('g');
  const keyHash = await api.sha256Hex('valid-key');
  db.prepare("INSERT INTO licenses (id,guild_id,key_hash,discord_id,created_at,updated_at) VALUES ('l','g',?,'u',0,0)").run(keyHash);
  db.prepare("INSERT INTO scripts (id,guild_id,loader_id,name,content,version,enabled,ffa_enabled,created_at,updated_at) VALUES ('s','g','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','Test','SECRET_PROTECTED_CONTENT','1',1,1,0,0)").run();
  return { db, env };
}
const request = (params) => new Request('https://auth.test/api/v1/loader?' + new URLSearchParams(params));
const report = (body) => new Request('https://auth.test/api/v1/security/report', { method: 'POST', body: JSON.stringify(body) });
test('missing key and missing HWID return no protected source', async () => {
  const { env } = await fixture();
  for (const params of [{}, {key:'valid-key'}, {key:'wrong',device_id:'a'}]) {
    const response = await api.handleProtectedLoader(request(params), env);
    assert.ok(response.status >= 400);
    assert.doesNotMatch(await response.text(), /SECRET_PROTECTED_CONTENT/);
  }
});
test('authenticated exposure report bans bound device, rejects other devices and survives HWID reset', async () => {
  const { db, env } = await fixture();
  let response = await api.handleProtectedLoader(request({key:'valid-key',device_id:'a',script_id:'s'}), env);
  assert.equal(response.status, 200);
  assert.equal(await response.text(), 'SECRET_PROTECTED_CONTENT');
  response = await api.handleSecurityReport(report({key:'valid-key',device_id:'someone-else',reason:'gui'}), env);
  assert.equal(response.status, 403);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM hwid_blacklists').get().n, 0);
  response = await api.handleSecurityReport(report({key:'valid-key',device_id:'a',reason:'gui'}), env);
  assert.equal(response.status, 200);
  response = await api.handleProtectedLoader(request({key:'valid-key',device_id:'a'}), env);
  assert.equal(response.status, 403);
  assert.match(await response.text(), /Blacklisted/);
  const result = await api.resetOwnHwid(env, {guild_id:'g'}, 'u', {waitUntil(){}});
  assert.match(await result.text(), /Blacklisted/);
  db.prepare("UPDATE licenses SET hwid_hash = NULL WHERE id = 'l'").run();
  response = await api.handleProtectedLoader(request({key:'valid-key',device_id:'b'}), env);
  assert.equal(response.status, 403);
  const secondHash = await api.sha256Hex('second-key');
  db.prepare("INSERT INTO licenses (id,guild_id,key_hash,created_at,updated_at) VALUES ('l2','g',?,0,0)").run(secondHash);
  response = await api.handleProtectedLoader(request({key:'second-key',device_id:'a'}), env);
  assert.equal(response.status, 403);
});
test('concurrent first binds only release code to the winning device', async () => {
  const { env } = await fixture();
  const responses = await Promise.all(['a','b'].map(device_id => api.handleProtectedLoader(request({key:'valid-key',device_id,script_id:'s'}), env)));
  assert.deepEqual(responses.map(r=>r.status).sort(), [200,403]);
});
test('reset default is five minutes and bootstrap is syntactically generated', () => {
  assert.equal(hwidCooldownSeconds({}),300);
  assert.equal(hwidCooldownSeconds({HWID_RESET_COOLDOWN_MINUTES:'5'}),300);
  assert.equal(hwidCooldownSeconds({HWID_RESET_COOLDOWN_MINUTES:'bad'}),300);
  const lua=api.buildBootstrapSource('https://auth.test','s');
  assert.match(lua,/https:\/\/auth.test\/api\/v1\/security\/report/);
  assert.match(lua,/__ea_protected_source=s/);
  assert.doesNotMatch(lua,/\$\{/);
});

test('FFA is keyless, requires a device, respects the switch and returns protected source', async () => {
  const {db,env}=await fixture();
  let response=await api.handleFfaPublicLoader(new Request('https://auth.test/files/v4/ffa/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.lua'),env,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
  assert.equal(response.status,403);
  assert.equal(await response.text(),'Blacklisted');
  response=await api.handleFfaPublicLoader(new Request('https://auth.test/files/v4/ffa/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.lua',{headers:{'x-eternal-device':'ffa-device'}}),env,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
  assert.equal(response.status,200);
  const bootstrap=await response.text();
  assert.match(bootstrap,/api\/v1\/ffa-loader/);
  assert.doesNotMatch(bootstrap,/You need a script_key/);
  response=await api.handleFfaProtectedLoader(new Request('https://auth.test/api/v1/ffa-loader?script_id=s&device_id=ffa-device'),env);
  assert.equal(response.status,200);
  assert.equal(await response.text(),'SECRET_PROTECTED_CONTENT');
  db.prepare("UPDATE scripts SET ffa_enabled=0 WHERE id='s'").run();
  response=await api.handleFfaProtectedLoader(new Request('https://auth.test/api/v1/ffa-loader?script_id=s&device_id=ffa-device'),env);
  assert.equal(response.status,403);
  assert.equal(await response.text(),'Blacklisted');
});

test('user reset reports remaining seconds within five-minute cooldown', async () => {
  const {db,env}=await fixture();
  db.prepare("UPDATE licenses SET last_hwid_reset=? WHERE id='l'").run(Math.floor(Date.now()/1000)-60);
  const response=await api.resetOwnHwid(env,{guild_id:'g'},'u',{waitUntil(){}});
  assert.match(await response.text(), /second\(s\)/);
});
