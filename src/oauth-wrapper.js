import baseWorker, { EternalGateway } from "./index.js";

export { EternalGateway };

const DISCORD_API = "https://discord.com/api/v10";
const STATE_COOKIE = "eternal_discord_oauth_state";

// Eternal Auth currently sends channel messages/embeds/files, reads message
// history, and adds/removes the configured buyer role. This requests only the
// bot permissions needed for those existing features, not Administrator.
const BOT_PERMISSIONS = "268553216";

function randomState() {
  const bytes = new Uint8Array(24);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
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

function page(title, body, status = 200, setCookie = null) {
  const headers = new Headers({
    "content-type": "text/html; charset=utf-8",
    "cache-control": "no-store",
  });
  if (setCookie) headers.append("set-cookie", setCookie);
  return new Response(`<!doctype html>
<html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(title)}</title>
<style>body{margin:0;background:#070a11;color:#f7f8fb;font-family:-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif;display:grid;min-height:100vh;place-items:center}.card{width:min(520px,calc(100vw - 40px));background:#0d1320;border:1px solid #202a3d;border-radius:18px;padding:24px;box-shadow:0 18px 70px #0008}h1{margin:0 0 10px;font-size:24px}.muted{color:#9ca8bb;line-height:1.5}.ok{color:#6ee7a2}</style></head><body><div class="card"><h1>${escapeHtml(title)}</h1>${body}</div></body></html>`, { status, headers });
}

function redirect(location, cookie) {
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

async function startOAuth(request, env) {
  if (!env.DISCORD_APPLICATION_ID) {
    return page("Discord login unavailable", '<p class="muted">DISCORD_APPLICATION_ID is not configured.</p>', 500);
  }

  const url = new URL(request.url);
  const state = randomState();
  const auth = new URL("https://discord.com/oauth2/authorize");
  auth.search = new URLSearchParams({
    client_id: env.DISCORD_APPLICATION_ID,
    response_type: "code",
    redirect_uri: callbackUrl(url),
    scope: "identify guilds bot applications.commands",
    permissions: BOT_PERMISSIONS,
    integration_type: "0",
    state,
    prompt: "consent",
  }).toString();

  return redirect(auth.toString(), stateCookie(state));
}

async function finishOAuth(request, env) {
  const url = new URL(request.url);
  if (url.searchParams.get("error")) {
    return page("Discord authorization cancelled", '<p class="muted">No changes were made.</p>', 400, clearStateCookie());
  }

  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const expectedState = getCookie(request, STATE_COOKIE);
  if (!code || !state || !expectedState || !safeEqual(state, expectedState)) {
    return page("Discord authorization failed", '<p class="muted">The login request expired or had an invalid state. Start it again.</p>', 400, clearStateCookie());
  }

  if (!env.DISCORD_CLIENT_SECRET) {
    return page("Discord authorization is not configured", '<p class="muted">DISCORD_CLIENT_SECRET is missing from the Worker secrets.</p>', 500, clearStateCookie());
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
  const token = await tokenResponse.json().catch(() => ({}));
  if (!tokenResponse.ok || !token.access_token) {
    return page("Discord authorization failed", `<p class="muted">Discord could not complete the login (HTTP ${tokenResponse.status}).</p>`, 502, clearStateCookie());
  }

  const userResponse = await fetch(`${DISCORD_API}/users/@me`, {
    headers: { authorization: `Bearer ${token.access_token}` },
  });
  const user = await userResponse.json().catch(() => ({}));
  if (!userResponse.ok || !user.id) {
    return page("Discord authorization failed", '<p class="muted">Discord did not return the authorized account.</p>', 502, clearStateCookie());
  }

  const guildId = url.searchParams.get("guild_id");
  return page(
    "Discord connected",
    `<p class="ok">Signed in as <strong>${escapeHtml(user.username)}</strong>.</p><p class="muted">Eternal Auth was authorized for the selected Discord server${guildId ? ` (${escapeHtml(guildId)})` : ""}. The bot itself stays logged in with DISCORD_BOT_TOKEN; your personal Discord access token is not stored.</p><p class="muted">You can close this page and return to the app.</p>`,
    200,
    clearStateCookie(),
  );
}

async function oauthRoute(request, env) {
  const url = new URL(request.url);
  if ((url.pathname === "/discord/connect" || url.pathname === "/discord/oauth/start") && request.method === "GET") {
    return startOAuth(request, env);
  }
  if (url.pathname === "/discord/oauth/callback" && request.method === "GET") {
    return finishOAuth(request, env);
  }
  return null;
}

export default {
  async fetch(request, env, ctx) {
    const oauthResponse = await oauthRoute(request, env);
    if (oauthResponse) return oauthResponse;
    return baseWorker.fetch(request, env, ctx);
  },

  async scheduled(controller, env, ctx) {
    if (typeof baseWorker.scheduled === "function") {
      return baseWorker.scheduled(controller, env, ctx);
    }
  },
};
