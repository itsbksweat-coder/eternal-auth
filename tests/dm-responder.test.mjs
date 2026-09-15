import test from 'node:test';
import assert from 'node:assert/strict';
import { DmResponder } from '../src/dm-responder.js';
const msg = (extra = {}) => ({ id: '123', channel_id: '456', author: { id: '789' }, content: 'help', ...extra });
test('replies privately, disables mentions, suppresses duplicates and bot loops', async () => {
  let time = 100000, calls = [];
  const responder = new DmResponder({ DISCORD_BOT_TOKEN: 'test-token' }, async (url, options) => {
    calls.push({ url, body: JSON.parse(options.body) }); return new Response('{}');
  }, () => time);
  assert.equal(await responder.handle(msg({ guild_id: '1' })), false);
  assert.equal(await responder.handle(msg({ author: { id: '789', bot: true } })), false);
  assert.equal(await responder.handle(msg()), true);
  assert.equal(await responder.handle(msg()), false);
  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0].body.allowed_mentions, { parse: [] });
  assert.match(calls[0].body.content, /linked server/);
  time += 10001;
  assert.equal(await responder.handle(msg({ content: 'status' })), true);
  assert.match(calls[1].body.content, /connection only/);
});
test('backs off on Discord rate limits and contains network failures', async () => {
  let time = 100000, calls = 0;
  const responder = new DmResponder({}, async () => { calls++; return new Response('{"retry_after":30}', { status: 429 }); }, () => time);
  assert.equal(await responder.handle(msg()), false);
  assert.equal(await responder.handle(msg({ author: { id: '999' } })), false);
  assert.equal(calls, 1);
  time += 30001;
  responder.request = async () => { throw new Error('network'); };
  assert.equal(await responder.handle(msg()), false);
  assert.equal(responder.pending, 0);
  assert.equal(responder.lastError, 'Discord DM request failed');
});
