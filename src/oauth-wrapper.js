import baseWorker, { EternalGateway } from "./index.js";

export { EternalGateway };

const DISCORD_API = "https://discord.com/api/v10";
const STATE_COOKIE = "eternal_discord_oauth_state";
const BOT_PERMISSIONS = "268553220";
const DASHBOARD_OWNER_ID = "1167590082878902435";
const MODERATION_GUILDS = new Map([
  ["1249019782632570971", "WakeHub"],
  ["1539142072232050690", "CleanHub"],
]);

// Existing ODY status source.
const ODY_GUILD_ID = "1422601105149264006";
const ODY_CHANNEL_ID = "1487787555427455067";

const PAIR_TTL_SECONDS = 10 * 60;
const SESSION_TTL_SECONDS = 7 * 24 * 60 * 60;

function unixNow() {
  return Math.floor(Date.now() / 1000);
}

function randomHex(bytes = 24) {
  const data = new Uint8Array(bytes);
  crypto.getRandomValues(data);
  return Array.from(data, (b) => b.toString(16).padStart(2, "0")).join("");
}

function randomUserCode() {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const data = new Uint8Array(8);
  crypto.getRandomValues(data);
  const chars = Array.from(data, (b) => alphabet[b % alphabet.length]).join("");
  return `${chars.slice(0, 4)}-${chars.slice(4)}`;
}

function normalizeUserCode(value) {
  return String(value || "").toUpperCase().replace(/[^A-Z0-9]/g, "");
}

function getCookie(request, name) {
  const raw = request.headers.get("cookie") || "";
  for (const item of raw.split(";")) {
    const [key, ...rest] = item.trim().split("=");
    if (key === name) return decodeURIComponent(rest.join("="));
  }
  return null;
}

function safeEqual(a, b) {
  a = String(a || "");
  b = String(b || "");
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[c]));
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}

async function readJson(request) {
  try { return await request.json(); }
  catch { return {}; }
}

async function dashboardAdminAuthorized(request, env, ctx) {
  const url = new URL(request.url);
  const headers = new Headers();
  const cookie = request.headers.get("cookie");
  if (cookie) headers.set("cookie", cookie);
  const check = await baseWorker.fetch(new Request(`${url.origin}/api/admin/state`, {
    method: "GET",
    headers,
  }), env, ctx);
  return check.ok;
}

async function discordBotApi(env, path, options = {}) {
  if (!env.DISCORD_BOT_TOKEN) {
    return new Response(JSON.stringify({ message: "DISCORD_BOT_TOKEN is not configured" }), {
      status: 500,
      headers: { "content-type": "application/json" },
    });
  }
  const headers = new Headers(options.headers || {});
  headers.set("authorization", `Bot ${env.DISCORD_BOT_TOKEN}`);
  headers.set("user-agent", "EternalAuth-ServerCleanup/1.0");
  if (options.body && !headers.has("content-type")) headers.set("content-type", "application/json");
  return fetch(`${DISCORD_API}${path}`, { ...options, headers });
}

async function executeModeration(request, env, action) {
  const body = await readJson(request);
  const guildId = String(body.guild_id || "").trim();
  const userId = String(body.user_id || "").trim();

  if (!MODERATION_GUILDS.has(guildId)) {
    return json({ ok: false, error: "Choose WakeHub or CleanHub." }, 400);
  }
  if (!/^\d{5,25}$/.test(userId)) {
    return json({ ok: false, error: "Enter a valid Discord user ID." }, 400);
  }
  if (action === "ban" && userId === DASHBOARD_OWNER_ID) {
    return json({ ok: false, error: "The Eternal Auth owner account is protected from dashboard bans." }, 400);
  }

  const path = `/guilds/${guildId}/bans/${userId}`;
  const options = action === "ban"
    ? {
        method: "PUT",
        headers: { "x-audit-log-reason": "Eternal Auth dashboard ban" },
        body: JSON.stringify({ delete_message_seconds: 0 }),
      }
    : {
        method: "DELETE",
        headers: { "x-audit-log-reason": "Eternal Auth dashboard unban" },
      };

  const response = await discordBotApi(env, path, options);
  if (!response.ok) {
    const data = await response.json().catch(() => ({}));
    const detail = data?.message ? `: ${data.message}` : "";
    return json({
      ok: false,
      error: `Discord HTTP ${response.status}${detail}. Make sure Eternal Auth has Ban Members permission and its role is high enough.`,
    }, response.status >= 400 && response.status < 500 ? response.status : 502);
  }

  return json({
    ok: true,
    action,
    guild_id: guildId,
    guild_name: MODERATION_GUILDS.get(guildId),
    user_id: userId,
  });
}

async function reconnectDashboardGateway(env) {
  try {
    const id = env.GATEWAY.idFromName("eternal-auth-primary-gateway");
    const gateway = env.GATEWAY.get(id);
    const response = await gateway.fetch("https://gateway.internal/reconnect", { method: "POST" });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) return json({ ok: false, error: data.error || `Gateway HTTP ${response.status}` }, 502);
    return json({ ok: true, gateway: data });
  } catch (error) {
    return json({ ok: false, error: `Gateway reconnect failed: ${String(error?.message || error)}` }, 500);
  }
}

async function adminUtilityRoute(request, env, ctx) {
  const url = new URL(request.url);
  const isModeration =
    url.pathname === "/api/admin/moderation/ban" ||
    url.pathname === "/api/admin/moderation/unban";
  const isReconnect = url.pathname === "/api/admin/gateway/reconnect-now";

  if (!isModeration && !isReconnect) return null;

  if (!await dashboardAdminAuthorized(request, env, ctx)) {
    return json({ ok: false, error: "Unauthorized" }, 401);
  }

  if (url.pathname === "/api/admin/moderation/ban" && request.method === "POST") {
    return executeModeration(request, env, "ban");
  }
  if (url.pathname === "/api/admin/moderation/unban" && request.method === "POST") {
    return executeModeration(request, env, "unban");
  }
  if (url.pathname === "/api/admin/gateway/reconnect-now" && request.method === "POST") {
    return reconnectDashboardGateway(env);
  }

  return json({ ok: false, error: "Method not allowed" }, 405);
}

function page(title, body, status = 200, cookie = null) {
  const headers = new Headers({
    "content-type": "text/html; charset=utf-8",
    "cache-control": "no-store",
  });
  if (cookie) headers.append("set-cookie", cookie);
  return new Response(`<!doctype html>
<html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(title)}</title>
<style>
body{margin:0;background:#05070c;color:#f7f8fb;font-family:-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif;display:grid;min-height:100vh;place-items:center}
.card{width:min(520px,calc(100vw - 40px));background:#0b1220;border:1px solid #1d2a42;border-radius:20px;padding:24px;box-shadow:0 20px 80px #0009}
h1{margin:0 0 10px;font-size:25px}.muted{color:#9ca8bb;line-height:1.5}.ok{color:#6ee7a2}.err{color:#ff9292}
input{box-sizing:border-box;width:100%;padding:14px 16px;border-radius:12px;border:1px solid #2b3d60;background:#08101d;color:white;font-size:20px;text-align:center;letter-spacing:2px;text-transform:uppercase}
button{width:100%;margin-top:12px;padding:14px;border:0;border-radius:12px;background:#315efb;color:white;font-size:16px;font-weight:700}
.code{font-size:28px;font-weight:800;letter-spacing:3px;margin:18px 0;text-align:center}
</style></head><body><div class="card"><h1>${escapeHtml(title)}</h1>${body}</div></body></html>`, { status, headers });
}

function redirect(location, cookie = null) {
  const headers = new Headers({ location, "cache-control": "no-store" });
  if (cookie) headers.append("set-cookie", cookie);
  return new Response(null, { status: 302, headers });
}

function callbackUrl(url) {
  return `${url.origin}/discord/oauth/callback`;
}

function stateCookie(value) {
  return `${STATE_COOKIE}=${encodeURIComponent(value)}; Max-Age=600; Path=/discord/oauth/; HttpOnly; Secure; SameSite=Lax`;
}

function clearStateCookie() {
  return `${STATE_COOKIE}=; Max-Age=0; Path=/discord/oauth/; HttpOnly; Secure; SameSite=Lax`;
}

async function putRuntime(env, key, value) {
  await env.DB.prepare(
    `INSERT INTO runtime_state (key, value_json, updated_at) VALUES (?, ?, ?)
     ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at`
  ).bind(key, JSON.stringify(value), unixNow()).run();
}

async function getRuntime(env, key) {
  const row = await env.DB.prepare(
    "SELECT value_json FROM runtime_state WHERE key = ? LIMIT 1"
  ).bind(key).first();
  if (!row?.value_json) return null;
  try { return JSON.parse(row.value_json); } catch { return null; }
}

async function deleteRuntime(env, key) {
  await env.DB.prepare("DELETE FROM runtime_state WHERE key = ?").bind(key).run();
}

async function beginDevicePair(request, env) {
  const deviceCode = randomHex(32);
  const userCode = randomUserCode();
  const compact = normalizeUserCode(userCode);
  const expiresAt = unixNow() + PAIR_TTL_SECONDS;

  await Promise.all([
    putRuntime(env, `ody_pair:${deviceCode}`, {
      status: "pending",
      user_code: userCode,
      expires_at: expiresAt,
    }),
    putRuntime(env, `ody_pair_code:${compact}`, {
      device_code: deviceCode,
      expires_at: expiresAt,
    }),
  ]);

  const origin = new URL(request.url).origin;
  return json({
    ok: true,
    device_code: deviceCode,
    user_code: userCode,
    verification_uri: `${origin}/discord/connect`,
    verification_uri_complete: `${origin}/discord/connect?code=${encodeURIComponent(userCode)}`,
    expires_in: PAIR_TTL_SECONDS,
    interval: 3,
  });
}

async function pairFromUserCode(env, rawCode) {
  const compact = normalizeUserCode(rawCode);
  if (compact.length !== 8) return null;
  const mapping = await getRuntime(env, `ody_pair_code:${compact}`);
  if (!mapping?.device_code || Number(mapping.expires_at || 0) <= unixNow()) return null;
  const pair = await getRuntime(env, `ody_pair:${mapping.device_code}`);
  if (!pair || Number(pair.expires_at || 0) <= unixNow()) return null;
  return { deviceCode: mapping.device_code, pair };
}

async function connectPage(request, env) {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  if (code) return startOAuthForPair(request, env, code);

  if (request.method === "POST") {
    const form = await request.formData();
    return startOAuthForPair(request, env, form.get("code"));
  }

  return page(
    "Connect ODY",
    `<p class="muted">Enter the one-time code shown in the ODY app on your other device.</p>
     <form method="post" action="/discord/connect">
       <input name="code" inputmode="text" autocomplete="one-time-code" maxlength="9" placeholder="ABCD-EFGH" required>
       <button type="submit">Continue with Discord</button>
     </form>
     <p class="muted">This pairs ODY with your Discord authorization. It does not copy your Discord password, cookie, or normal user token into the app.</p>`
  );
}

async function startOAuthForPair(request, env, code) {
  const found = await pairFromUserCode(env, code);
  if (!found) {
    return page("Invalid or expired code", '<p class="err">Open ODY and generate a new pairing code, then try again.</p>', 400);
  }
  if (!env.DISCORD_APPLICATION_ID) {
    return page("Discord login unavailable", '<p class="err">DISCORD_APPLICATION_ID is not configured.</p>', 500);
  }

  const url = new URL(request.url);
  const state = randomHex(24);
  await putRuntime(env, `ody_oauth_state:${state}`, {
    device_code: found.deviceCode,
    expires_at: unixNow() + 600,
  });

  const auth = new URL("https://discord.com/oauth2/authorize");
  auth.search = new URLSearchParams({
    client_id: env.DISCORD_APPLICATION_ID,
    response_type: "code",
    redirect_uri: callbackUrl(url),
    scope: "identify bot applications.commands",
    permissions: BOT_PERMISSIONS,
    integration_type: "0",
    state,
    prompt: "consent",
  }).toString();

  return redirect(auth.toString(), stateCookie(state));
}

async function finishOAuth(request, env) {
  const url = new URL(request.url);
  const error = url.searchParams.get("error");
  if (error) {
    return page("Discord authorization cancelled", '<p class="muted">No changes were made. You can try the pairing code again.</p>', 400, clearStateCookie());
  }

  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const cookieState = getCookie(request, STATE_COOKIE);
  const stateData = state ? await getRuntime(env, `ody_oauth_state:${state}`) : null;

  if (!code || !state || !cookieState || !safeEqual(state, cookieState) || !stateData?.device_code || Number(stateData.expires_at || 0) <= unixNow()) {
    return page("Discord authorization failed", '<p class="err">The login request expired or had an invalid state. Start again from ODY.</p>', 400, clearStateCookie());
  }

  if (!env.DISCORD_CLIENT_SECRET) {
    return page("Discord authorization is not configured", '<p class="err">DISCORD_CLIENT_SECRET is missing from Worker secrets.</p>', 500, clearStateCookie());
  }

  const tokenResponse = await fetch(`${DISCORD_API}/oauth2/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: env.DISCORD_APPLICATION_ID,
      client_secret: env.DISCORD_CLIENT_SECRET,
      grant_type: "authorization_code",
      code,
      redirect_uri: callbackUrl(url),
    }),
  });
  const oauth = await tokenResponse.json().catch(() => ({}));
  if (!tokenResponse.ok || !oauth.access_token) {
    return page("Discord authorization failed", `<p class="err">Discord could not complete the login (HTTP ${tokenResponse.status}).</p>`, 502, clearStateCookie());
  }

  const userResponse = await fetch(`${DISCORD_API}/users/@me`, {
    headers: { authorization: `Bearer ${oauth.access_token}` },
  });
  const user = await userResponse.json().catch(() => ({}));
  if (!userResponse.ok || !user.id) {
    return page("Discord authorization failed", '<p class="err">Discord did not return the authorized account.</p>', 502, clearStateCookie());
  }

  // We deliberately do not persist Discord's user access/refresh token. ODY gets
  // only an opaque Eternal Auth session token for its own backend requests.
  const appToken = randomHex(32);
  const sessionExpiresAt = unixNow() + SESSION_TTL_SECONDS;
  await Promise.all([
    putRuntime(env, `ody_session:${appToken}`, {
      user_id: String(user.id),
      username: String(user.username || "Discord User"),
      expires_at: sessionExpiresAt,
    }),
    putRuntime(env, `ody_pair:${stateData.device_code}`, {
      status: "authorized",
      user_id: String(user.id),
      username: String(user.username || "Discord User"),
      app_token: appToken,
      expires_at: unixNow() + PAIR_TTL_SECONDS,
    }),
    deleteRuntime(env, `ody_oauth_state:${state}`),
  ]);

  return page(
    "ODY connected",
    `<p class="ok">Approved as <strong>${escapeHtml(user.username || "Discord User")}</strong>.</p>
     <p class="muted">Your other device should connect automatically within a few seconds. You can return to ODY now.</p>`,
    200,
    clearStateCookie(),
  );
}

async function deviceStatus(request, env) {
  const url = new URL(request.url);
  const deviceCode = url.searchParams.get("device_code") || "";
  if (!/^[a-f0-9]{64}$/i.test(deviceCode)) return json({ ok: false, error: "invalid_device_code" }, 400);

  const pair = await getRuntime(env, `ody_pair:${deviceCode}`);
  if (!pair || Number(pair.expires_at || 0) <= unixNow()) {
    return json({ ok: false, status: "expired" }, 410);
  }

  if (pair.status !== "authorized") {
    return json({ ok: true, status: "pending" });
  }

  return json({
    ok: true,
    status: "authorized",
    app_token: pair.app_token,
    user: { id: pair.user_id, username: pair.username },
    expires_in: SESSION_TTL_SECONDS,
  });
}

async function requireOdySession(request, env) {
  const auth = request.headers.get("authorization") || "";
  const match = auth.match(/^Bearer\s+([a-f0-9]{64})$/i);
  if (!match) return null;
  const session = await getRuntime(env, `ody_session:${match[1]}`);
  if (!session || Number(session.expires_at || 0) <= unixNow()) return null;
  return session;
}

function flattenDiscordMessage(message) {
  const parts = [];
  if (message?.content) parts.push(message.content);
  for (const embed of message?.embeds || []) {
    if (embed.title) parts.push(embed.title);
    if (embed.description) parts.push(embed.description);
    if (embed.author?.name) parts.push(embed.author.name);
    for (const field of embed.fields || []) {
      if (field.name) parts.push(field.name);
      if (field.value) parts.push(field.value);
    }
    if (embed.footer?.text) parts.push(embed.footer.text);
  }
  return parts.join("\n").trim();
}

async function odyStatus(request, env) {
  const session = await requireOdySession(request, env);
  if (!session) return json({ ok: false, error: "not_authorized" }, 401);
  if (!env.DISCORD_BOT_TOKEN) return json({ ok: false, error: "bot_token_not_configured" }, 500);

  const response = await fetch(`${DISCORD_API}/channels/${ODY_CHANNEL_ID}/messages?limit=50`, {
    headers: {
      authorization: `Bot ${env.DISCORD_BOT_TOKEN}`,
      "user-agent": "EternalAuth-ODY/1.0",
    },
  });
  const messages = await response.json().catch(() => null);
  if (!response.ok || !Array.isArray(messages)) {
    return json({
      ok: false,
      error: "bot_cannot_read_status_channel",
      discord_status: response.status,
      guild_id: ODY_GUILD_ID,
      channel_id: ODY_CHANNEL_ID,
    }, response.status === 403 || response.status === 404 ? 403 : 502);
  }

  let statusText = "";
  for (const message of messages) {
    const text = flattenDiscordMessage(message);
    if (/\b(FARMER|PRO)\b/i.test(text) && /expires?\s+in/i.test(text)) {
      statusText = text;
      break;
    }
  }

  return json({
    ok: true,
    authorized_as: session.username,
    status_text: statusText,
    found: Boolean(statusText),
  });
}

async function oauthRoute(request, env) {
  const url = new URL(request.url);

  if (url.pathname === "/discord/device/start" && request.method === "POST") {
    return beginDevicePair(request, env);
  }
  if (url.pathname === "/discord/device/status" && request.method === "GET") {
    return deviceStatus(request, env);
  }
  if (url.pathname === "/discord/connect" && (request.method === "GET" || request.method === "POST")) {
    return connectPage(request, env);
  }
  if (url.pathname === "/discord/oauth/start" && request.method === "GET") {
    return connectPage(request, env);
  }
  if (url.pathname === "/discord/oauth/callback" && request.method === "GET") {
    return finishOAuth(request, env);
  }
  if (url.pathname === "/api/ody/status" && request.method === "GET") {
    return odyStatus(request, env);
  }
  return null;
}

export default {
  async fetch(request, env, ctx) {
    const oauthResponse = await oauthRoute(request, env);
    if (oauthResponse) return oauthResponse;
    const utilityResponse = await adminUtilityRoute(request, env, ctx);
    if (utilityResponse) return utilityResponse;
    return baseWorker.fetch(request, env, ctx);
  },

  async scheduled(controller, env, ctx) {
    if (typeof baseWorker.scheduled === "function") {
      return baseWorker.scheduled(controller, env, ctx);
    }
  },
};
