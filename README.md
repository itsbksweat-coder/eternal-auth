# Current version: v1.8.7

Read **START-HERE.md** for this release, deployment, five-minute resets, DM replies, and the limits of code-exposure detection. Older release notes below describe historical behavior.

# Eternal Auth v1.8.6 — Seven-Layer Leak Guard

This build adds seven client-side leak-deterrence layers before the protected script is fetched/executed:

1. filters source-like strings from `print` / `warn`;
2. filters executor console output (`rconsole*`, `console*`);
3. disables common clipboard writers (`setclipboard`, `toclipboard`, etc.);
4. blocks source-like data passed to `writefile` / `appendfile`;
5. blocks source-like text assignments to Roblox `TextBox`, `TextLabel`, and `TextButton` when metamethod hooks are available;
6. blocks common executor HTTP request calls when the outgoing body looks like source code;
7. runs an integrity watchdog and kicks if high-value guards are replaced.

The detector is intentionally selective for most sinks so normal small UI strings, logging, and file/network use are less likely to break. Clipboard writers remain fully disabled.

**Important:** client-delivered Lua can never be made impossible to recover on a hostile executor. These layers raise the effort required and stop common copy/dump paths, but sensitive logic should still live server-side whenever possible.

No new D1 migration is required when upgrading from v1.8.6.

---

# Eternal Auth v1.7.4 — Fast Loader

This build keeps the v1.7.x backend and native kick behavior, while optimizing the execution path.

## Loader speed changes

- Public loader bootstrap is cached at Cloudflare edge for 5 minutes.
- License, blacklist and requested-script lookup are combined into one D1 query on the normal execution path.
- License-key hashing and HWID hashing run in parallel.
- Execution logging is moved off the critical response path with `ctx.waitUntil()`.
- Expired-blacklist cleanup is moved off the critical response path.
- HWID writes happen only on the first bind; normal launches do not wait on an HWID write.
- Lua bootstrap is smaller and does fewer filesystem/environment operations.
- All license, HWID, blacklist, expiry, script-enabled and clipboard protections remain enabled.

No new D1 migration is required when upgrading from v1.7.3.

---

# Eternal Auth v1.7.4 — Full Backend Persistence

Cloudflare-hosted Eternal Auth with:

- Cloudflare Worker API + dashboard
- D1 licenses, server keys, blacklists, logs, and scripts
- free-plan Durable Object Discord Gateway presence
- global Discord slash commands and panel buttons
- multiple protected scripts per Discord project
- one loader URL per script
- HWID binding / reset flow
- browser-safe loader page
- clipboard guard before protected code executes
- in-game auth / HWID / disabled-script error modal

## v1.7 backend persistence

Eternal Auth now keeps the dashboard state on the backend instead of relying on browser storage. The D1 database stores project/guild configuration, scripts, licenses, HWID hashes, blacklists, stock keys, server setup-key metadata, audit logs, admin UI state, admin credential hashes, admin sessions, and a persisted Gateway status snapshot. Newly generated server setup keys are additionally encrypted with `CONFIG_SECRET` before being stored so they can be copied again from the admin dashboard without keeping plaintext in D1.

The admin password is **not stored in plaintext**. On the first successful login after the v1.7 migration, Eternal Auth uses the existing `ADMIN_PASSWORD` Worker Secret once to create a PBKDF2-SHA256 password hash with a random salt in D1. After that, D1 is the source of truth for admin login. You can change the password from the new **Backend** page.

For an existing v1.6.x database, run:

```cmd
npm install
npm run db:migrate:v1.7
npm run deploy
```

Then sign in once with your existing admin password. After that first successful login, `ADMIN_PASSWORD` is only a bootstrap fallback and can be removed from Cloudflare if you want:

```cmd
npx wrangler secret delete ADMIN_PASSWORD
```

`SESSION_SECRET` is no longer needed in v1.7 because admin sessions are opaque random tokens whose hashes and expiry are stored in D1.

Secrets that should remain Cloudflare Worker Secrets are `DISCORD_BOT_TOKEN`, `DISCORD_PUBLIC_KEY`, `DISCORD_APPLICATION_ID`, `LICENSE_KEY_SECRET`, `HWID_PEPPER`, and `CONFIG_SECRET`. They are backend-only and never sent to the dashboard.

## v1.6.1: multiple scripts

Each Discord project can now contain as many scripts as you need. Every script has its own:

- script ID
- loader ID + loader URL
- name
- version
- enabled / disabled state
- protected Lua source

In the dashboard, open **Script** and use **Upload Script Files**. Scripts are file-only: select one or multiple text/script files and one Eternal Auth script is created per file. Replacing protected source also requires uploading a replacement file.

When a licensed user runs `/script` or presses **Get Script** and there is more than one enabled script, Discord shows a script selector. After they choose one, Eternal Auth sends their personal key with that script's loader URL.

## Upgrade from v1.5 or older

Keep your existing Cloudflare secrets and D1 database ID. Because v1.6 changes the `scripts` table from one script per guild to multiple scripts, run the migration before deployment:

```powershell
npm install
npm run db:migrate:v1.6
npm run deploy
```

The migration preserves your old script as the first script in the project. It does not remove licenses, server keys, blacklists, guild settings, or audit logs.

## Fresh install

Create the D1 database and put its ID into `wrangler.jsonc`, then run:

```powershell
npm install
npm run db:init
npx wrangler deploy --secrets-file .secrets
```

For later deployments:

```powershell
npm run deploy
```

## Worker secrets

Keep these backend-only Cloudflare Worker Secrets:

```text
DISCORD_PUBLIC_KEY
DISCORD_BOT_TOKEN
DISCORD_APPLICATION_ID
LICENSE_KEY_SECRET
HWID_PEPPER
CONFIG_SECRET
```

For an existing install, keep `ADMIN_PASSWORD` long enough to complete the first successful v1.7 login. Eternal Auth will hash it into D1; after that it is optional and can be deleted from Worker Secrets.

Existing installs may still have `SETUP_KEY`; v1.7 does not rely on it for the one-time server-key flow.

## Discord endpoint

Set the Discord Developer Portal **Interactions Endpoint URL** to:

```text
https://YOUR-WORKER.workers.dev/discord/interactions
```

Global commands are registered with:

```powershell
node --env-file=.commands.env ./scripts/register-commands.mjs
```

For global / multi-server registration, `.commands.env` should contain:

```env
DISCORD_APPLICATION_ID=YOUR_APPLICATION_ID
DISCORD_BOT_TOKEN=YOUR_BOT_TOKEN
```

Do not include `DISCORD_GUILD_ID` for global registration.

## Loader behavior

A user's loader looks like:

```lua
script_key="EA-...";
loadstring(game:HttpGet("https://YOUR-WORKER.workers.dev/files/v4/loaders/SCRIPT_LOADER_ID.lua"))()
```

The selected public loader tells Eternal Auth which protected script to return. The user's license remains project-wide, so the same valid Eternal Auth license can access any enabled script in that Discord project.

## FFA mode

Each script has an independent **FFA** switch in the dashboard. Enable it and save metadata, then use **Copy FFA** or Discord `/ffa`. If several scripts have FFA enabled, use `/ffa script:<exact name>`.

FFA does not require or issue a license key. It still requires a device identifier and rejects devices already present in the project's security blacklist. Disabling FFA immediately closes its bootstrap and protected-source endpoints. Because FFA has no secret credential, it cannot provide the same access control as the keyed loader and should only be used for code you intend anyone to run.

## v1.6.1 — file-only script uploads

The dashboard no longer creates blank scripts or lets protected source be pasted into a textarea. New protected scripts must be created by uploading a supported text-based file. Replacing existing protected source also requires choosing a replacement file.

Common accepted extensions include `.txt`, `.lua`, `.luau`, `.md`, `.cfg`, `.ini`, `.json`, `.js`, `.ts`, `.xml`, `.yaml`, `.yml`, `.py`, `.rb`, `.sh`, `.ps1`, `.bat`, `.cmd`, `.toml`, `.conf`, and `.log`.

If you already migrated to v1.6.0, no additional D1 migration is required for v1.6.1. If you are upgrading from an older release, run the existing v1.6 migration before deploying.


## v1.7.4 HTTP 500 fix

v1.7.4 self-initializes the admin persistence tables before `/api/admin/login` and all `/api/admin/*` requests. It also checks the live `server_setup_keys` schema before adding `key_enc`, so a partially applied or repeated migration no longer causes a duplicate-column failure.

After copying your existing D1 `database_id` into `wrangler.jsonc`, normally you only need:

```powershell
npm install
npm run deploy
```

Then visit `/api/health`. A healthy backend returns JSON containing `"backend":"ready"`.

If you still get a server error, run:

```powershell
npm run gateway:tail
```

and reproduce the request once. The Worker will log the underlying D1/runtime exception without exposing your secrets in the browser.

## v1.8.6 Luarmor-style `/setpanel` default

`/setpanel` now uses the Luarmor-style option order by default:

1. `loader_script` — required attachment (`.lua`, `.luau`, `.txt`, and other text files)
2. `manager_role` — required role
3. `buyer_role` — required role

Every invocation creates a new persistent panel. The newest panel becomes the guild-level default for non-panel commands, while older panels keep their own loader template and roles.

The uploaded loader file should contain `{{KEY}}` and `{{LOADER_URL}}`. Eternal Auth can also normalize a standard `script_key = "KEY"` plus `/files/v4/loaders/...lua` loadstring automatically.


## v1.8.6 - loadstring-only panels

`/setpanel` loader attachments now only need the actual Eternal Auth loadstring (or bare loader URL). Eternal Auth automatically prepends `script_key="{{KEY}}";` when saving the panel. A panel is pinned to the script identified by that loader URL, so **Get Script** returns that script directly instead of opening the multi-script selector. The web dashboard now displays and copies the full `loadstring(game:HttpGet("..."))()` form rather than a bare loader URL.


## v1.8.6 panel flow
`/setpanel` now uses a 3-step Luarmor-style flow: upload loader + choose roles, select a project, then type the embed title, description, and hex color in a Discord modal. The final public panel uses a `Sent by <user>` footer with Discord's timestamp and includes Redeem Key, Get Script, Get Role, Reset HWID, and Get Stats buttons.
