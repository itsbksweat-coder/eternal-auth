import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { DatabaseSync } from 'node:sqlite';
import { hwidCooldownSeconds } from '../src/device-security.js';
let source = await readFile(new URL('../src/index.js', import.meta.url), 'utf8');
source = source.replace('import { DurableObject } from "cloudflare:workers";', 'class DurableObject {}');
for (const file of ['dm-responder.js', 'device-security.js']) source = source.replace(`"./${file}"`, JSON.stringify(new URL(`../src/${file}`, import.meta.url).href));
source = source.replace('"../public/entry-loader.js"', JSON.stringify(new URL('../public/entry-loader.js', import.meta.url).href));
source += '\nexport { handleAdminApi, handlePublicLoader, handleFfaPublicLoader, handleFfaProtectedLoader, handleFfaSecurityReport, createFfaReportToken, buildLoader, handleProtectedLoader, handleVerify, handleSecurityReport, resetOwnHwid, sha256Hex, hashDevice, buildBootstrapSource };';
const api = await import('data:text/javascript;base64,' + Buffer.from(source).toString('base64'));
async function fixture() {
  const db = new DatabaseSync(':memory:');
  db.exec(await readFile(new URL('../schema.sql', import.meta.url), 'utf8'));
  const prepare = (sql) => {
    let args = [];
    const stmt = { bind(...values) { args = values; return stmt; }, async first() { return db.prepare(sql).get(...args) || null; }, async run() { const r = db.prepare(sql).run(...args); return { meta: { changes: Number(r.changes) } }; }, async all() { return { results: db.prepare(sql).all(...args) }; } }; return stmt;
  };
  const env = { HWID_PEPPER: 'test-pepper', CONFIG_SECRET: 'test-config-secret', DB: { prepare, async batch(statements) { const out = []; for (const s of statements) out.push(await s.run()); return out; } } };
  db.prepare('INSERT INTO guilds (guild_id,created_at,updated_at) VALUES (?,0,0)').run('123456789012345678');
  const keyHash = await api.sha256Hex('valid-key');
  db.prepare("INSERT INTO licenses (id,guild_id,key_hash,discord_id,created_at,updated_at) VALUES ('l','123456789012345678',?,'u',0,0)").run(keyHash);
  db.prepare("INSERT INTO scripts (id,guild_id,loader_id,name,content,version,enabled,ffa_enabled,created_at,updated_at) VALUES ('s','123456789012345678','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','Test','SECRET_PROTECTED_CONTENT','1',1,1,0,0)").run();
  db.prepare("INSERT INTO panels (id,guild_id,name,script_id,active,created_at,updated_at) VALUES ('p','123456789012345678','Main Panel','s',1,0,0)").run();
  return { db, env };
}
const TEST_IP = '203.0.113.10';
const directRequest = (params, extraHeaders = {}) => new Request('https://auth.test/api/v1/loader?' + new URLSearchParams(params), {
  method: 'POST',
  headers: {'x-eternal-execute':'1','cf-connecting-ip':TEST_IP,...extraHeaders},
});
const report = (body) => new Request('https://auth.test/api/v1/security/report', { method: 'POST', body: JSON.stringify(body) });

function ticketFromBootstrap(lua) {
  return lua.match(/\["X-Eternal-Ticket"\]=\"([^\"]+)\"/)?.[1] || null;
}

async function secureProtectedResponse(env, { key='valid-key', deviceId='a', scriptId='s', loaderId='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', ip=TEST_IP } = {}) {
  const stage1 = new Request(`https://auth.test/files/v4/loaders/${loaderId}.lua`, {
    headers: {
      authorization: `Bearer ${key}`,
      'x-eternal-device': deviceId,
      'x-eternal-execute': '1',
      'cf-connecting-ip': ip,
    },
  });
  const bootstrapResponse = await api.handlePublicLoader(stage1, env, loaderId, {waitUntil(){}});
  if (bootstrapResponse.status !== 200) return bootstrapResponse;
  const bootstrap = await bootstrapResponse.text();
  const ticket = ticketFromBootstrap(bootstrap);
  assert.ok(ticket, 'bootstrap should contain a signed loader ticket');
  const stage2 = new Request(`https://auth.test/api/v1/loader?script_id=${encodeURIComponent(scriptId)}`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${key}`,
      'x-eternal-device': deviceId,
      'x-eternal-ticket': ticket,
      'x-eternal-execute': '1',
      'cf-connecting-ip': ip,
    },
  });
  return api.handleProtectedLoader(stage2, env);
}

async function secureFfaResponse(env, { deviceId='ffa-device', scriptId='s', loaderId='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', ip=TEST_IP } = {}) {
  const stage1 = new Request(`https://auth.test/files/v4/ffa/${loaderId}.lua`, {
    headers: {
      'x-eternal-device': deviceId,
      'x-eternal-execute': '1',
      'cf-connecting-ip': ip,
    },
  });
  const bootstrapResponse = await api.handleFfaPublicLoader(stage1, env, loaderId);
  if (bootstrapResponse.status !== 200) return bootstrapResponse;
  const bootstrap = await bootstrapResponse.text();
  const ticket = ticketFromBootstrap(bootstrap);
  assert.ok(ticket, 'FFA bootstrap should contain a signed loader ticket');
  const stage2 = new Request(`https://auth.test/api/v1/ffa-loader?script_id=${encodeURIComponent(scriptId)}`, {
    method: 'POST',
    headers: {
      'x-eternal-device': deviceId,
      'x-eternal-ticket': ticket,
      'x-eternal-execute': '1',
      'cf-connecting-ip': ip,
    },
  });
  return api.handleFfaProtectedLoader(stage2, env);
}
test('missing key and missing HWID return no protected source', async () => {
  const { env } = await fixture();
  for (const params of [{}, {key:'valid-key'}, {key:'wrong',device_id:'a'}]) {
    const response = await api.handleProtectedLoader(directRequest(params), env);
    assert.ok(response.status >= 400);
    assert.doesNotMatch(await response.text(), /SECRET_PROTECTED_CONTENT/);
  }
});
test('client security reports are informational and never create HWID bans', async () => {
  const { db, env } = await fixture();
  let response = await secureProtectedResponse(env,{key:'valid-key',deviceId:'a',scriptId:'s'});
  assert.equal(response.status, 200);
  assert.equal(await response.text(), 'SECRET_PROTECTED_CONTENT');

  response = await api.handleSecurityReport(report({key:'valid-key',device_id:'someone-else',reason:'gui'}), env);
  assert.equal(response.status, 403);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM hwid_blacklists').get().n, 0);

  for (const reason of ['gui','clipboard','file','console','network','integrity','environment','http_spy','hwid_spoof']) {
    response = await api.handleSecurityReport(report({key:'valid-key',device_id:'a',reason}), env);
    assert.equal(response.status, 200, reason);
    const body = await response.json();
    assert.equal(body.persistent, false, reason);
    assert.equal(db.prepare('SELECT COUNT(*) AS n FROM hwid_blacklists').get().n, 0, reason);
    assert.equal(db.prepare("SELECT status FROM licenses WHERE id='l'").get().status, 'active', reason);
  }

  response = await secureProtectedResponse(env,{key:'valid-key',deviceId:'a',scriptId:'s'});
  assert.equal(response.status, 200);
  assert.equal(await response.text(), 'SECRET_PROTECTED_CONTENT');
});

test('heuristic security reports never create persistent HWID bans', async () => {
  const {db,env}=await fixture();
  let response=await secureProtectedResponse(env,{key:'valid-key',deviceId:'a',scriptId:'s'});
  assert.equal(response.status,200);
  for (const reason of ['integrity','environment','http_spy','hwid_spoof']) {
    response=await api.handleSecurityReport(report({key:'valid-key',device_id:'a',reason}),env);
    assert.equal(response.status,200,reason);
    const body=await response.json();
    assert.equal(body.persistent,false,reason);
    assert.equal(db.prepare('SELECT COUNT(*) AS n FROM hwid_blacklists').get().n,0,reason);
    assert.equal(db.prepare("SELECT status FROM licenses WHERE id='l'").get().status,'active',reason);
  }
});

test('concurrent first binds only release code to the winning device', async () => {
  const { env } = await fixture();
  const responses = await Promise.all(['a','b'].map(deviceId => secureProtectedResponse(env,{key:'valid-key',deviceId,scriptId:'s'})));
  assert.deepEqual(responses.map(r=>r.status).sort(), [200,403]);
});
test('reset default is five minutes and bootstrap is compatibility-only', () => {
  assert.equal(hwidCooldownSeconds({}),300);
  assert.equal(hwidCooldownSeconds({HWID_RESET_COOLDOWN_MINUTES:'5'}),300);
  assert.equal(hwidCooldownSeconds({HWID_RESET_COOLDOWN_MINUTES:'bad'}),300);
  const lua=api.buildBootstrapSource('https://auth.test','s');
  assert.match(lua,/https:\/\/auth\.test\/api\/v1\/loader\?script_id=s/);
  assert.match(lua,/X-Eternal-Ticket/);
  assert.match(lua,/X-Eternal-Execute/);
  assert.match(lua,/loadstring\(body\)/);
  assert.match(lua,/body=nil/);
  assert.doesNotMatch(lua,/api\/v1\/security\/report/);
  assert.doesNotMatch(lua,/__ea_block|__ea_capture_source|hookfunction|hookmetamethod|TextBox|setclipboard|decompile|getscriptbytecode/);
  assert.doesNotMatch(lua,/\$\{/);
});

test('FFA is keyless, requires a device, respects the switch and returns protected source', async () => {
  const {db,env}=await fixture();
  let response=await api.handleFfaPublicLoader(new Request('https://auth.test/files/v4/ffa/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.lua'),env,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
  assert.equal(response.status,200);
  assert.match(await response.text(),/Eternal Auth FFA loader/);
  response=await api.handleFfaPublicLoader(new Request('https://auth.test/files/v4/ffa/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.lua',{headers:{'x-eternal-device':'ffa-device','x-eternal-execute':'1'}}),env,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
  assert.equal(response.status,200);
  const bootstrap=await response.text();
  assert.match(bootstrap,/api\/v1\/ffa-loader/);
  assert.match(bootstrap,/X-Eternal-Ticket/);
  assert.match(bootstrap,/X-Eternal-Execute/);
  assert.match(bootstrap,/loadstring\(body\)/);
  assert.doesNotMatch(bootstrap,/api\/v1\/ffa\/security\/report|__ea_block|http_spy|hookmetamethod/);
  assert.doesNotMatch(bootstrap,/You need a script_key/);
  response=await secureFfaResponse(env,{deviceId:'ffa-device',scriptId:'s'});
  assert.equal(response.status,200);
  assert.equal(await response.text(),'SECRET_PROTECTED_CONTENT');
  db.prepare("UPDATE scripts SET ffa_enabled=0 WHERE id='s'").run();
  response=await secureFfaResponse(env,{deviceId:'ffa-device',scriptId:'s'});
  assert.equal(response.status,403);
  assert.equal(await response.text(),'Access denied');
});

test('legacy first-stage requests receive only a compatibility launcher, never protected source', async () => {
  const {db,env}=await fixture();
  const probe=new Request('https://auth.test/files/v4/loaders/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.lua',{headers:{authorization:'Bearer valid-key','x-eternal-device':'probe-device'}});
  const response=await api.handlePublicLoader(probe,env,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',{waitUntil(){}});
  assert.equal(response.status,200);
  const source=await response.text();
  assert.match(source,/X-Eternal-Execute/);
  assert.match(source,/Eternal Auth loader compile error/);
  assert.doesNotMatch(source,/__ea_hook_score|__ea_hwid_spoofed|__ea_spy_env_detected/);
  assert.doesNotMatch(source,/SECRET_PROTECTED_CONTENT/);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM hwid_blacklists').get().n,0);
});

test('old automatic HWID bans self-recover on a valid request', async () => {
  const {db,env}=await fixture();
  const hash=await api.hashDevice(env,'legacy-device');
  for (const reason of ['loader_probe','integrity','environment','http_spy','hwid_spoof','gui','clipboard','file','console','network']) {
    db.prepare("DELETE FROM hwid_blacklists").run();
    db.prepare("UPDATE licenses SET hwid_hash=?,status='security_blacklisted' WHERE id='l'").run(hash);
    db.prepare("INSERT INTO hwid_blacklists (guild_id,hwid_hash,reason,license_id,created_at) VALUES ('123456789012345678',?,?, 'l',0)").run(hash,reason);
    const response=await secureProtectedResponse(env,{key:'valid-key',deviceId:'legacy-device',scriptId:'s'});
    assert.equal(response.status,200,reason);
    assert.equal(await response.text(),'SECRET_PROTECTED_CONTENT',reason);
    assert.equal(db.prepare('SELECT COUNT(*) AS n FROM hwid_blacklists').get().n,0,reason);
    assert.equal(db.prepare("SELECT status FROM licenses WHERE id='l'").get().status,'active',reason);
  }
});

test('admin can remove an FFA HWID blacklist by pasting the raw device ID', async () => {
  const {db,env}=await fixture();
  const hash=await api.hashDevice(env,'my-raw-hwid');
  db.prepare("INSERT INTO hwid_blacklists (guild_id,hwid_hash,reason,license_id,created_at) VALUES ('123456789012345678',?,'http_spy','ffa:s',0)").run(hash);
  const request=new Request('https://auth.test/api/admin/hwid-blacklists',{method:'DELETE',body:JSON.stringify({guild_id:'123456789012345678',device_id:'my-raw-hwid'})});
  const response=await api.handleAdminApi(request,env,new URL(request.url),{waitUntil(){}});
  assert.equal(response.status,200);
  assert.equal((await response.json()).removed,true);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM hwid_blacklists').get().n,0);
});

test('admin script responses never expose protected content', async () => {
  const {env}=await fixture();
  let req=new Request('https://auth.test/api/admin/scripts?guild_id=123456789012345678');
  let response=await api.handleAdminApi(req,env,new URL(req.url),{waitUntil(){}});
  assert.equal(response.status,200);
  let body=await response.json();
  assert.equal(body.scripts.length,1);
  assert.equal(body.scripts[0].content,undefined);
  assert.equal(body.scripts[0].content_size,'SECRET_PROTECTED_CONTENT'.length);

  req=new Request('https://auth.test/api/admin/config?guild_id=123456789012345678');
  response=await api.handleAdminApi(req,env,new URL(req.url),{waitUntil(){}});
  assert.equal(response.status,200);
  body=await response.json();
  assert.equal(body.script.content,undefined);
  assert.equal(body.script.content_size,'SECRET_PROTECTED_CONTENT'.length);
});

test('panel-scoped license cannot load a script attached to another panel', async () => {
  const {db,env}=await fixture();
  db.prepare("UPDATE licenses SET panel_id='p' WHERE id='l'").run();
  db.prepare("INSERT INTO scripts (id,guild_id,loader_id,name,content,version,enabled,ffa_enabled,created_at,updated_at) VALUES ('s2','123456789012345678','bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','Other','OTHER_SECRET','1',1,0,0,0)").run();
  db.prepare("INSERT INTO panels (id,guild_id,name,script_id,active,created_at,updated_at) VALUES ('p2','123456789012345678','Other Panel','s2',1,0,0)").run();
  let response=await api.handlePublicLoader(new Request('https://auth.test/files/v4/loaders/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.lua',{headers:{authorization:'Bearer valid-key','x-eternal-device':'panel-device','x-eternal-execute':'1'}}),env,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',{waitUntil(){}});
  assert.equal(response.status,200);
  response=await api.handlePublicLoader(new Request('https://auth.test/files/v4/loaders/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.lua',{headers:{authorization:'Bearer valid-key','x-eternal-device':'panel-device','x-eternal-execute':'1'}}),env,'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',{waitUntil(){}});
  assert.equal(response.status,403);
  assert.equal(await response.text(),'Access denied');
});

test('Get Script output is two lines and each script receives its own loader URL', () => {
  const guild={base_url:'https://auth.test',loader_id:'projectloader'};
  const first=api.buildLoader('', 'EA-FIRST', guild, {loader_id:'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'});
  const second=api.buildLoader('', 'EA-SECOND', guild, {loader_id:'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'});
  assert.equal(first.split('\n').length,2);
  assert.match(first,/^script_key="EA-FIRST"\n/);
  assert.match(first,/game:HttpGet\("https:\/\/auth\.test\/files\/v4\/loaders\/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\.lua"\)/);
  assert.match(first,/type\(loadstring\)~="function"/);
  assert.match(first,/Eternal Auth loader compile error/);
  assert.match(second,/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\.lua/);
  assert.notEqual(first,second);
  assert.doesNotMatch(first,/X-Eternal-Execute|local e=/);
});

test('FFA signed reports are informational and never create HWID bans', async () => {
  const {db,env}=await fixture();
  const deviceHash=await api.hashDevice(env,'ffa-device');
  const token=await api.createFfaReportToken(env,'123456789012345678','s',deviceHash);

  let response=await api.handleFfaSecurityReport(new Request('https://auth.test/api/v1/ffa/security/report',{method:'POST',body:JSON.stringify({device_id:'other-device',reason:'gui',token})}),env);
  assert.equal(response.status,403);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM hwid_blacklists').get().n,0);

  response=await api.handleFfaSecurityReport(new Request('https://auth.test/api/v1/ffa/security/report',{method:'POST',body:JSON.stringify({device_id:'ffa-device',reason:'gui',token})}),env);
  assert.equal(response.status,200);
  const body=await response.json();
  assert.equal(body.persistent,false);
  assert.equal(body.status,'Observed');
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM hwid_blacklists').get().n,0);

  response=await secureFfaResponse(env,{deviceId:'ffa-device',scriptId:'s'});
  assert.equal(response.status,200);
  assert.equal(await response.text(),'SECRET_PROTECTED_CONTENT');
});

test('protected source requires signed ticket and ticket is bound to client IP', async () => {
  const {env}=await fixture();
  let response=await api.handleProtectedLoader(directRequest({key:'valid-key',device_id:'a',script_id:'s'}),env);
  assert.equal(response.status,403);

  const stage1=new Request('https://auth.test/files/v4/loaders/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.lua',{
    headers:{authorization:'Bearer valid-key','x-eternal-device':'a','x-eternal-execute':'1','cf-connecting-ip':TEST_IP}
  });
  const bootstrapResponse=await api.handlePublicLoader(stage1,env,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',{waitUntil(){}});
  assert.equal(bootstrapResponse.status,200);
  const ticket=ticketFromBootstrap(await bootstrapResponse.text());
  assert.ok(ticket);
  response=await api.handleProtectedLoader(new Request('https://auth.test/api/v1/loader?script_id=s',{
    method:'POST',
    headers:{
      authorization:'Bearer valid-key',
      'x-eternal-device':'a',
      'x-eternal-ticket':ticket,
      'x-eternal-execute':'1',
      'cf-connecting-ip':'198.51.100.77'
    }
  }),env);
  assert.equal(response.status,403);
});

test('user reset reports remaining seconds within five-minute cooldown', async () => {
  const {db,env}=await fixture();
  db.prepare("UPDATE licenses SET last_hwid_reset=? WHERE id='l'").run(Math.floor(Date.now()/1000)-60);
  const response=await api.resetOwnHwid(env,{guild_id:'123456789012345678'},'u',{waitUntil(){}});
  assert.match(await response.text(), /second\(s\)/);
});
