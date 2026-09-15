# Eternal Auth v1.8.9 — panel-scoped licenses

This full project is based on your latest recovered v1.8.6 package. It has not been deployed or tested against your live Cloudflare account or Roblox executor.

## Changes

- Every script now has an independent **FFA** switch in the dashboard. When enabled, **Copy FFA** creates a keyless launcher and Discord `/ffa` returns it. `/ffa script:<name>` selects between multiple FFA scripts.
- FFA launchers still require a device identifier and reject HWIDs already security-blacklisted in that project. Turning FFA off immediately makes both FFA layers return `Blacklisted`.

- Cloudflare Worker serves the dashboard, Discord interactions and authentication API.
- The existing single SQLite Durable Object maintains Discord online presence; new DIRECT_MESSAGES handling replies to help, script, redeem, hwid and status. Other DMs get a brief command guide. These are deterministic replies, not an AI chat service. License-changing actions stay in the linked server.
- Missing key or device ID is rejected before protected code is returned. Public loader URLs still return the small bootstrap required to start authentication; they never contain the protected script.
- Detected supported source-output attempts return `Blacklisted`, block the output and report the bound device to the server. GUI text is replaced with `Blacklisted`.
- The report requires the license key and its already-bound device. Reports cannot specify another license or a target guild. D1 records an HMAC of the HWID, not the raw identifier. Bans apply across keys in that project.
- Security bans survive normal HWID resets. Ordinary user resets have a five-minute cooldown between successful resets; they do not wait five minutes to finish. Owner force-reset remains an explicit administrative action.
- The missing panel migration path and first-device binding race are fixed.

## Upgrade your existing deployment on Windows

1. Extract this ZIP. Check that `wrangler.jsonc` identifies your existing `eternal-auth` Worker and `eternal-auth-db` database. It retains database ID `25c635e7-31ba-4beb-b838-b48e078738f9` from the recovered package. Do not use that ID for a different account.
2. Double-click `DEPLOY-WINDOWS.cmd`. Sign in to the Cloudflare account that owns the Worker when Wrangler opens your browser.
3. The script installs dependencies, runs local tests, exports a timestamped database backup, applies the additive v1.8.7, v1.8.8, and v1.8.9 migrations, then deploys. It stops on any error. It does not change your plan or rotate existing secrets.
4. Visit `/api/health`, sign in to the dashboard and check Gateway status. The existing five-minute cron also wakes the bot. Send the bot `help` in a DM and verify the reply and online indicator.
5. Run `npm run commands` once so Discord registers the new `/ffa` command. Confirm the existing Discord Interactions Endpoint remains `https://eternal-auth.xyzcheatz.workers.dev/discord/interactions`.

The upgrade script targets an existing v1.8.6 deployment. If live is older, inspect its schema and apply the applicable earlier migrations before this upgrade. Do not initialize or replace a populated database blindly.

## Fresh deployment

Create a free Worker and D1 database in your own Cloudflare account, update the database ID in `wrangler.jsonc`, initialize the fresh database with `schema.sql`, and configure Worker secrets: `DISCORD_PUBLIC_KEY`, `DISCORD_BOT_TOKEN`, `DISCORD_APPLICATION_ID`, `LICENSE_KEY_SECRET`, `HWID_PEPPER`, `CONFIG_SECRET`, plus `ADMIN_PASSWORD` for first login. Use independent random cryptographic values for signing/encryption secrets. Keep them private. Follow the original README for command registration and linking your server. The ZIP contains no credentials.

## Limits and recovery

Code delivered to a user-controlled runtime can be recovered. This is especially true in FFA mode because there is no secret credential. These client guards are best-effort: preinstalled hooks, unsupported output functions, small or encoded fragments, or blocked report traffic can evade them. A local `Blacklisted` response does not prove the server received the report. The keyed backend only persists bans after an authenticated report reaches it. Device IDs supplied by an executor or local file are not tamper-proof hardware attestation. Changing the device-ID method may require an ordinary HWID reset for existing customers.

The source detector matches delivered-source text instead of treating all large strings as stolen code. Every intercepted clipboard writer call now attempts to write exactly `Blacklisted` and triggers the existing blacklist report, even for ordinary text. This also affects legitimate copy buttons in protected scripts. Clipboard replacement requires a working executor clipboard function; reporting still requires network access. No test claims that arbitrary Roblox output is impossible.

Owner recovery is available through authenticated admin API endpoints: `GET /api/admin/hwid-blacklists` lists bans; `DELETE /api/admin/hwid-blacklists` with JSON `guild_id` and `hwid_hash` removes the selected ban. Use a logged-in same-origin admin session. A normal reset does not remove security bans. Standard Discord-user blacklists remain separate.

## Free hosting budget

Cloudflare currently includes 100,000 Worker requests/day, 5 million D1 rows read/day, 100,000 rows written/day and 5 GB D1 storage. One continuously active 128 MB Durable Object uses about 11,059 GB-s/day against 13,000 GB-s/day included. Other Durable Objects share that account allowance. Outgoing Discord WebSockets do not hibernate. Remain on the Free plan; exceeding free quotas can interrupt service. This is not an unlimited or guaranteed-uptime service. No VPS, Docker or always-running home PC is needed after deployment.

Sources checked September 11, 2026:
- https://developers.cloudflare.com/workers/platform/pricing/
- https://developers.cloudflare.com/durable-objects/platform/pricing/
- https://developers.cloudflare.com/durable-objects/best-practices/websockets/
- https://docs.discord.com/developers/events/gateway

## Validation performed

JavaScript syntax checks and local Node tests cover the keyed and FFA endpoints with an in-memory SQLite database, including missing credentials, FFA on/off behavior, cross-device report rejection, persistent bans, competing initial bindings, reset cooldown and DM rate limits. Cloudflare deployment, Discord delivery and executor hooks require live validation after authorization. Node 24 is recommended for the test suite.
