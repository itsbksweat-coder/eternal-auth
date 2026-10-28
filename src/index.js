import { authenticatedLauncher, ffaLauncher, ffaBootstrapLua } from "../public/entry-loader.js";
import { DurableObject } from "cloudflare:workers";
import { DmResponder } from "./dm-responder.js";
import { deviceBlocked, bindDevice, hwidCooldownSeconds } from "./device-security.js";
import { obfuscateLua } from "./lua-obfuscator.js";

const enc = new TextEncoder();
const dec = new TextDecoder();

const JSON_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store",
};

const PERSISTENT_SECURITY_REASONS = new Set([
  "gui",
  "clipboard",
  "file",
  "console",
  "network",
  "clipboard_source",
  "loadstring_hook",
  "scrape_rate_abuse",
  "tampering",
  "http_spy",
]);

const NON_PERSISTENT_SECURITY_REASONS = new Set([
  "loader_probe",
  "integrity",
  "environment",
  "hwid_spoof",
]);

const EPHEMERAL = 1 << 6;
const ADMINISTRATOR = 1n << 3n;

// Hot-path caches. Cloudflare isolates are reused between requests, so these
// avoid repeated D1 reads during rapid Discord interaction flows. Every cache
// entry has a short TTL and all paths still fall back to D1 when an isolate is
// cold or a request lands on a different isolate.
const HOT_CACHE_TTL_MS = 30_000;
const guildHotCache = new Map();
const scriptHotCache = new Map();
const draftHotCache = new Map();
const panelHotCache = new Map();

function cacheGet(map, key) {
  const hit = map.get(key);
  if (!hit) return null;
  if (hit.expiresAt <= Date.now()) { map.delete(key); return null; }
  return hit.value;
}
function cachePut(map, key, value, ttl = HOT_CACHE_TTL_MS) {
  map.set(key, { value, expiresAt: Date.now() + ttl });
  return value;
}
function cacheDelete(map, key) { map.delete(key); }

// Voltra Auth v1.4 Free Gateway
//
// This single SQLite-backed Durable Object opens one outbound WebSocket to
// Discord's Gateway using non-privileged GUILDS and DIRECT_MESSAGES intents.
// It maintains online presence and replies to DMs; slash commands/buttons continue to
// be handled by /discord/interactions in the Worker below.
//
// A single continuously-active 128 MB Durable Object consumes about 11,060
// GB-s/day, which is below Cloudflare's current 13,000 GB-s/day Free allowance.
export class EternalGateway extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.ctx = ctx;
    this.env = env;
    this.ws = null;
    this.connectPromise = null;
    this.reconnectTimer = null;
    this.heartbeatTimer = null;
    this.firstHeartbeatTimer = null;
    this.sequence = null;
    this.sessionId = null;
    this.resumeGatewayUrl = null;
    this.awaitingHeartbeatAck = false;
    this.ready = false;
    this.userId = null;
    this.userTag = null;
    this.guildIds = new Set();
    this.startedAt = Date.now();
    this.connectedAt = null;
    this.readyAt = null;
    this.lastHeartbeatAt = null;
    this.lastHeartbeatAckAt = null;
    this.lastError = null;
    this.reconnectAttempts = 0;
    this.fatal = false;
    this.dmResponder = new DmResponder(env);
  }

  async fetch(request) {
    const url = new URL(request.url);

    if (url.pathname === "/wake" || url.pathname === "/status") {
      if (!this.fatal && !this.isSocketOpen()) {
        try {
          await this.ensureConnected();
        } catch (error) {
          this.lastError = String(error?.message || error);
        }
      }
      return new Response(JSON.stringify(this.status()), {
        status: 200,
        headers: JSON_HEADERS,
      });
    }

    if (url.pathname === "/reconnect" && request.method === "POST") {
      this.fatal = false;
      this.lastError = null;
      this.disconnectSocket(4000, "Manual Voltra Auth reconnect");
      await this.ensureConnected(true);
      return new Response(JSON.stringify(this.status()), {
        status: 200,
        headers: JSON_HEADERS,
      });
    }

    return new Response("Not found", { status: 404 });
  }

  status() {
    return {
      ok: true,
      mode: "durable-object-free",
      gateway_ready: this.ready,
      dm_replies_enabled: true,
      dm_replies_sent: this.dmResponder.sent,
      dm_last_error: this.dmResponder.lastError,
      discord_status: this.ready ? "online" : (this.connectPromise || this.isSocketOpen() ? "connecting" : "offline"),
      user_id: this.userId,
      user_tag: this.userTag,
      guilds: this.guildIds.size,
      ws_status: this.ws?.readyState ?? null,
      started_at: new Date(this.startedAt).toISOString(),
      connected_at: this.connectedAt ? new Date(this.connectedAt).toISOString() : null,
      ready_at: this.readyAt ? new Date(this.readyAt).toISOString() : null,
      uptime_seconds: Math.floor((Date.now() - this.startedAt) / 1000),
      last_heartbeat_at: this.lastHeartbeatAt ? new Date(this.lastHeartbeatAt).toISOString() : null,
      last_heartbeat_ack_at: this.lastHeartbeatAckAt ? new Date(this.lastHeartbeatAckAt).toISOString() : null,
      reconnect_attempts: this.reconnectAttempts,
      fatal: this.fatal,
      last_error: this.lastError,
    };
  }

  isSocketOpen() {
    return !!this.ws && (this.ws.readyState === 0 || this.ws.readyState === 1);
  }

  async ensureConnected(force = false) {
    if (!this.env.DISCORD_BOT_TOKEN) {
      this.fatal = true;
      throw new Error("DISCORD_BOT_TOKEN is not configured");
    }

    if (!force && this.isSocketOpen()) return;
    if (this.connectPromise) return this.connectPromise;

    this.connectPromise = this.openGateway()
      .catch((error) => {
        this.lastError = String(error?.message || error);
        throw error;
      })
      .finally(() => {
        this.connectPromise = null;
      });

    return this.connectPromise;
  }

  async openGateway() {
    this.clearReconnectTimer();
    this.clearHeartbeat();
    this.ready = false;

    const base = this.sessionId && this.resumeGatewayUrl
      ? this.resumeGatewayUrl
      : "https://gateway.discord.gg";
    const gatewayUrl = `${String(base).replace(/\/$/, "")}/?v=10&encoding=json`;

    const response = await fetch(gatewayUrl, {
      headers: { Upgrade: "websocket" },
    });

    const ws = response.webSocket;
    if (!ws) {
      throw new Error(`Discord Gateway refused WebSocket upgrade (HTTP ${response.status})`);
    }

    ws.accept();
    this.ws = ws;
    this.connectedAt = Date.now();
    this.lastError = null;

    ws.addEventListener("message", (event) => {
      if (this.ws !== ws) return;
      try {
        this.handleGatewayMessage(event.data);
      } catch (error) {
        this.lastError = `Gateway message error: ${String(error?.message || error)}`;
        console.error(this.lastError);
      }
    });

    ws.addEventListener("close", (event) => {
      if (this.ws !== ws) return;
      this.handleGatewayClose(event.code, event.reason || "");
    });

    ws.addEventListener("error", () => {
      if (this.ws !== ws) return;
      this.lastError = "Discord Gateway WebSocket error";
    });
  }

  handleGatewayMessage(raw) {
    const text = typeof raw === "string" ? raw : dec.decode(raw);
    const payload = JSON.parse(text);

    if (payload.s != null) this.sequence = payload.s;

    switch (payload.op) {
      case 0:
        this.handleDispatch(payload.t, payload.d || {});
        break;

      case 1:
        // Discord can request an immediate heartbeat.
        this.sendGateway({ op: 1, d: this.sequence });
        this.awaitingHeartbeatAck = true;
        this.lastHeartbeatAt = Date.now();
        break;

      case 7:
        this.lastError = "Discord requested a reconnect";
        this.reconnect(false);
        break;

      case 9: {
        const canResume = payload.d === true;
        if (!canResume) this.clearSession();
        this.lastError = canResume ? "Discord invalidated the session; resuming" : "Discord invalidated the session; identifying again";
        this.reconnect(false, 2500 + Math.floor(Math.random() * 2500));
        break;
      }

      case 10:
        this.startHeartbeat(Number(payload.d?.heartbeat_interval || 45000));
        if (this.sessionId && this.sequence != null) this.sendResume();
        else this.sendIdentify();
        break;

      case 11:
        this.awaitingHeartbeatAck = false;
        this.lastHeartbeatAckAt = Date.now();
        break;

      default:
        break;
    }
  }

  handleDispatch(type, data) {
    if (type === "MESSAGE_CREATE") {
      this.ctx.waitUntil(this.dmResponder.handle(data));
      return;
    }
    if (type === "READY") {
      this.sessionId = data.session_id || null;
      this.resumeGatewayUrl = data.resume_gateway_url || null;
      this.userId = data.user?.id || null;
      const username = data.user?.username || null;
      const discriminator = data.user?.discriminator;
      this.userTag = username
        ? (discriminator && discriminator !== "0" ? `${username}#${discriminator}` : username)
        : null;
      this.guildIds = new Set((data.guilds || []).map((g) => g.id).filter(Boolean));
      this.ready = true;
      this.readyAt = Date.now();
      this.reconnectAttempts = 0;
      this.lastError = null;
      console.log(`Voltra Auth Free Gateway READY as ${this.userTag || this.userId} in ${this.guildIds.size} guild(s).`);
      return;
    }

    if (type === "RESUMED") {
      this.ready = true;
      this.readyAt = Date.now();
      this.reconnectAttempts = 0;
      this.lastError = null;
      console.log("Voltra Auth Free Gateway session resumed.");
      return;
    }

    if (type === "GUILD_CREATE" && data.id) {
      this.guildIds.add(data.id);
      return;
    }

    if (type === "GUILD_DELETE" && data.id) {
      this.guildIds.delete(data.id);
    }
  }

  sendIdentify() {
    this.sendGateway({
      op: 2,
      d: {
        token: this.env.DISCORD_BOT_TOKEN,
        intents: 1 | (1 << 12),
        properties: {
          os: "linux",
          browser: "Voltra Auth",
          device: "Voltra Auth",
        },
        presence: {
          since: null,
          activities: [{ name: "Voltra Auth", type: 3 }],
          status: "online",
          afk: false,
        },
      },
    });
  }

  sendResume() {
    this.sendGateway({
      op: 6,
      d: {
        token: this.env.DISCORD_BOT_TOKEN,
        session_id: this.sessionId,
        seq: this.sequence,
      },
    });
  }

  sendGateway(payload) {
    if (!this.ws || this.ws.readyState !== 1) return false;
    this.ws.send(JSON.stringify(payload));
    return true;
  }

  startHeartbeat(intervalMs) {
    this.clearHeartbeat();
    const interval = Math.max(5000, intervalMs || 45000);
    const jitter = Math.floor(Math.random() * interval);

    this.firstHeartbeatTimer = setTimeout(() => {
      this.firstHeartbeatTimer = null;
      this.sendHeartbeat();
      this.heartbeatTimer = setInterval(() => this.sendHeartbeat(), interval);
    }, jitter);
  }

  sendHeartbeat() {
    if (!this.ws || this.ws.readyState !== 1) return;

    if (this.awaitingHeartbeatAck) {
      this.lastError = "Discord heartbeat ACK was missed; reconnecting";
      this.reconnect(false);
      return;
    }

    this.awaitingHeartbeatAck = true;
    this.lastHeartbeatAt = Date.now();
    this.sendGateway({ op: 1, d: this.sequence });
  }

  handleGatewayClose(code, reason) {
    this.clearHeartbeat();
    this.ws = null;
    this.ready = false;
    this.awaitingHeartbeatAck = false;
    this.lastError = `Discord Gateway closed (${code || 1006})${reason ? `: ${reason}` : ""}`;

    const fatalCodes = new Set([4004, 4010, 4011, 4012, 4013, 4014]);
    if (fatalCodes.has(code)) {
      this.fatal = true;
      console.error(`Voltra Auth Gateway stopped reconnecting after fatal close ${code}.`);
      return;
    }

    if (code === 4007 || code === 4009) this.clearSession();
    this.scheduleReconnect();
  }

  reconnect(clearSession = false, delayMs = null) {
    if (clearSession) this.clearSession();
    this.clearHeartbeat();
    const old = this.ws;
    this.ws = null;
    this.ready = false;
    try {
      if (old && (old.readyState === 0 || old.readyState === 1)) old.close(4000, "Voltra Auth reconnect");
    } catch {}
    this.scheduleReconnect(delayMs);
  }

  scheduleReconnect(delayMs = null) {
    if (this.fatal || this.reconnectTimer) return;
    this.reconnectAttempts += 1;
    const backoff = delayMs ?? Math.min(60000, 5000 * Math.max(1, this.reconnectAttempts));
    const jitter = Math.floor(Math.random() * 1500);
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.ensureConnected().catch((error) => {
        this.lastError = String(error?.message || error);
        this.scheduleReconnect();
      });
    }, backoff + jitter);
  }

  disconnectSocket(code = 1000, reason = "Closing") {
    this.clearHeartbeat();
    this.clearReconnectTimer();
    const old = this.ws;
    this.ws = null;
    this.ready = false;
    try {
      if (old && (old.readyState === 0 || old.readyState === 1)) old.close(code, reason);
    } catch {}
  }

  clearSession() {
    this.sessionId = null;
    this.resumeGatewayUrl = null;
    this.sequence = null;
  }

  clearHeartbeat() {
    if (this.firstHeartbeatTimer) clearTimeout(this.firstHeartbeatTimer);
    if (this.heartbeatTimer) clearInterval(this.heartbeatTimer);
    this.firstHeartbeatTimer = null;
    this.heartbeatTimer = null;
    this.awaitingHeartbeatAck = false;
  }

  clearReconnectTimer() {
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    this.reconnectTimer = null;
  }
}

function gatewayInstance(env) {
  const id = env.GATEWAY.idFromName("eternal-auth-primary-gateway");
  return env.GATEWAY.get(id);
}

async function ensureGatewayPresence(env) {
  const gateway = gatewayInstance(env);
  const response = await gateway.fetch("https://gateway.internal/wake", { method: "POST" });
  const data = await response.json();
  if (!response.ok) {
    throw new Error(data?.error || `Gateway status HTTP ${response.status}`);
  }
  try {
    await env.DB.prepare(
      `INSERT INTO runtime_state (key, value_json, updated_at) VALUES ('gateway', ?, ?)
       ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at`
    ).bind(JSON.stringify(data), now()).run();
  } catch (error) {
    console.warn("Could not persist Gateway snapshot:", error);
  }
  return data;
}

async function serveWebsiteAsset(request, env) {
  if (!env?.ASSETS || typeof env.ASSETS.fetch !== "function") {
    console.error("Voltra Auth ASSETS binding is unavailable");
    return new Response(
      "<!doctype html><meta charset=\"utf-8\"><title>Voltra Auth</title><h1>Voltra Auth site assets are unavailable.</h1>",
      {
        status: 503,
        headers: {
          "content-type": "text/html; charset=utf-8",
          "cache-control": "no-store",
        },
      },
    );
  }

  try {
    const url = new URL(request.url);
    const accept = (request.headers.get("accept") || "").toLowerCase();
    const wantsHtml = request.method === "GET" && (accept.includes("text/html") || accept.includes("application/xhtml+xml"));
    const looksLikeFile = /\/[^/]+\.[a-z0-9]{1,12}$/i.test(url.pathname);

    // Dedicated login page at /login — served from public/login.html.
    if (wantsHtml && (url.pathname === "/login" || url.pathname === "/login/")) {
      const loginUrl = new URL("/login.html", request.url);
      const loginResp = await env.ASSETS.fetch(new Request(loginUrl, { method: "GET", headers: request.headers }));
      return withSecurityHeaders(loginResp);
    }

    // Server-side gate: for a browser navigating to a page route (not an asset
    // file, not /login, not an api/files endpoint), bounce them to /login if
    // they do not already have a valid admin session. Keeps the dashboard
    // behind the cookie even before any JS runs.
    if (wantsHtml && !looksLikeFile && !url.pathname.startsWith("/api/") && !url.pathname.startsWith("/files/") && !url.pathname.startsWith("/discord/")) {
      let session = null;
      try { session = await verifyAdminSession(request, env); } catch {}
      if (!session) {
        return withSecurityHeaders(new Response(null, {
          status: 302,
          headers: { location: "/login", "cache-control": "no-store" },
        }));
      }
    }

    let response = await env.ASSETS.fetch(request);

    // SPA/browser fallback: if a normal page route is not a concrete asset,
    // serve the real Voltra Auth index instead of surfacing a Worker 500/404.
    if (response.status === 404 && wantsHtml && !looksLikeFile) {
      const indexUrl = new URL("/index.html", request.url);
      response = await env.ASSETS.fetch(new Request(indexUrl, {
        method: "GET",
        headers: request.headers,
      }));
    }

    return withSecurityHeaders(response);
  } catch (error) {
    console.error("Voltra Auth asset serving failed", error);
    return new Response(
      "<!doctype html><meta charset=\"utf-8\"><title>Voltra Auth</title><h1>Voltra Auth website could not load.</h1><p>Please try again in a moment.</p>",
      {
        status: 503,
        headers: {
          "content-type": "text/html; charset=utf-8",
          "cache-control": "no-store",
        },
      },
    );
  }
}

export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);

      // Hide Voltra Auth source/auth pages only when they are opened as a
      // real browser document. Executor HTTP requests keep their normal behavior.
      if (
        isBrowserNavigation(request) &&
        (
          url.pathname.startsWith("/api/v1/") ||
          url.pathname.startsWith("/files/v4/")
        )
      ) {
        return new Response("", {
          status: 200,
          headers: {
            "content-type": "text/html; charset=utf-8",
            "cache-control": "no-store",
            "x-content-type-options": "nosniff",
          },
        });
      }

      if (request.method === "OPTIONS" && url.pathname.startsWith("/api/v1/")) {
        return new Response(null, {
          status: 204,
          headers: {
            "access-control-allow-origin": "*",
            "access-control-allow-methods": "GET,POST,OPTIONS",
            "access-control-allow-headers": "content-type,authorization,x-eternal-device,x-eternal-legacy-device,x-eternal-ticket,x-eternal-execute",
            "access-control-max-age": "86400",
          },
        });
      }

      if (url.pathname === "/discord/interactions" && request.method === "POST") {
        return handleDiscordInteraction(request, env, ctx);
      }

      if (url.pathname === "/api/v1/security/report" && request.method === "POST") {
        const limit = await rateCheck(env, "sec-report", clientIp(request), 20, 300);
        if (!limit.allowed) {
          return json(
            { ok: false, error: "Too many reports from this address." },
            429,
            { "retry-after": String(limit.retry_after || 60) },
          );
        }
        return handleSecurityReport(request, env);
      }

      if (url.pathname === "/api/v1/ffa/security/report" && request.method === "POST") {
        const limit = await rateCheck(env, "sec-report-ffa", clientIp(request), 20, 300);
        if (!limit.allowed) {
          return json(
            { ok: false, error: "Too many reports from this address." },
            429,
            { "retry-after": String(limit.retry_after || 60) },
          );
        }
        return handleFfaSecurityReport(request, env);
      }

      if (url.pathname === "/api/v1/verify" && request.method === "POST") {
        return handleVerify(request, env);
      }

      if (url.pathname === "/api/v1/bootstrap" && request.method === "GET") {
        const id = url.searchParams.get("loader_id") || "";
        if (!/^[a-f0-9]{32}$/i.test(id)) return deniedSource();
        return handlePublicLoader(request, env, id.toLowerCase(), ctx);
      }

      const publicLoaderMatch = url.pathname.match(/^\/files\/v4\/loaders\/([a-f0-9]{32})\.lua$/i);
      if (publicLoaderMatch && request.method === "GET") {
        return handlePublicLoader(request, env, publicLoaderMatch[1].toLowerCase(), ctx);
      }

      const ffaLoaderMatch = url.pathname.match(/^\/files\/v4\/ffa\/([a-f0-9]{32})\.lua$/i);
      if (ffaLoaderMatch && request.method === "GET") {
        return handleFfaPublicLoader(request, env, ffaLoaderMatch[1].toLowerCase());
      }

      if (url.pathname === "/api/v1/loader" && request.method === "POST") {
        return handleProtectedLoader(request, env, ctx);
      }

      if (url.pathname === "/api/v1/ffa-loader" && request.method === "POST") {
        return handleFfaProtectedLoader(request, env);
      }

      if (url.pathname === "/api/admin/login" && request.method === "POST") {
        await ensureAdminAuthSchema(env);
        const limit = await rateCheck(env, "login", clientIp(request), 5, 600);
        if (!limit.allowed) {
          return json(
            { ok: false, error: "Too many login attempts. Try again later." },
            429,
            { "retry-after": String(limit.retry_after || 60) },
          );
        }
        return handleAdminLogin(request, env);
      }

      if (url.pathname === "/api/admin/logout" && request.method === "POST") {
        await ensureAdminAuthSchema(env);
        return handleAdminLogout(request, env);
      }

      if (url.pathname.startsWith("/api/admin/")) {
        try {
          await ensureBackendPersistenceSchema(env);
          const session = await verifyAdminSession(request, env);
          if (!session) return json({ ok: false, error: "Unauthorized" }, 401);

          // Dedicated endpoint for the dashboard JS to pick up its CSRF token
          // after a page reload (the token lives only in memory client-side).
          if (url.pathname === "/api/admin/csrf" && request.method === "GET") {
            return handleAdminCsrf(request, session);
          }

          // Any state-changing admin call must carry a matching CSRF header.
          // GET/HEAD/OPTIONS are read-only and don't need the check.
          const method = request.method.toUpperCase();
          if (method !== "GET" && method !== "HEAD" && method !== "OPTIONS") {
            const csrfError = await requireCsrf(request, session);
            if (csrfError) return csrfError;
          }

          return await handleAdminApi(request, env, url, ctx);
        } catch (error) {
          console.error("Admin API failed", url.pathname, error);
          const detail = String(error?.message || error || "Unknown backend error").slice(0, 240);
          return json({ ok: false, error: `Backend error on ${url.pathname}: ${detail}` }, 500);
        }
      }

      if (url.pathname === "/api/health" && request.method === "GET") {
        try {
          await ensureBackendPersistenceSchema(env);
          await env.DB.prepare("SELECT 1 AS ok").first();
          return json({ ok: true, service: "Voltra Auth", backend: "ready" });
        } catch (error) {
          console.error("Health check failed:", error);
          return json({ ok: false, error: "Backend initialization failed" }, 503);
        }
      }

      return serveWebsiteAsset(request, env);
    } catch (error) {
      console.error(error);
      return json({ ok: false, error: "Internal server error" }, 500);
    }
  },

  async scheduled(controller, env, ctx) {
    ctx.waitUntil(
      ensureGatewayPresence(env).catch((error) => {
        console.error("Gateway keepalive failed:", error);
      }),
    );
  },
};

function json(body, status = 200, extraHeaders = {}) {
  return withSecurityHeaders(new Response(JSON.stringify(body), {
    status,
    headers: { ...JSON_HEADERS, ...extraHeaders },
  }));
}

function publicJson(body, status = 200) {
  return json(body, status, {
    "access-control-allow-origin": "*",
  });
}

// Strict HTTP security headers.
// Note: style-src keeps 'unsafe-inline' because the dashboard still uses a few
// inline width hints (progress bars) and the moderation page has a scoped
// <style> block. Scripts stay strict ('self' only) and inline event handlers
// are not used.
const CSP_POLICY = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: https://cdn.discordapp.com",
  "font-src 'self' data:",
  "connect-src 'self'",
  "frame-ancestors 'none'",
  "base-uri 'none'",
  "form-action 'self'",
  "object-src 'none'",
  "upgrade-insecure-requests",
].join("; ");

function withSecurityHeaders(response) {
  const headers = new Headers(response.headers);
  headers.set("content-security-policy", CSP_POLICY);
  headers.set("strict-transport-security", "max-age=31536000; includeSubDomains; preload");
  headers.set("x-content-type-options", "nosniff");
  headers.set("x-frame-options", "DENY");
  headers.set("referrer-policy", "no-referrer");
  headers.set(
    "permissions-policy",
    "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()"
  );
  headers.set("cross-origin-opener-policy", "same-origin");
  headers.set("cross-origin-resource-policy", "same-origin");
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

async function readJson(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

// Rate limiter backed by the primary Gateway Durable Object. All Worker
// requests target one DO instance, so this is a single global counter per key.
// Returns { allowed, remaining, retry_after }. Fails open on DO errors so a
// transient outage never locks admins out, but logs the failure.
async function rateCheck(env, kind, identifier, limit, windowSeconds) {
  try {
    const id = env.GATEWAY.idFromName("eternal-auth-primary-gateway");
    const gateway = env.GATEWAY.get(id);
    const response = await gateway.fetch("https://gateway.internal/rate-check", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ kind, id: identifier, limit, window: windowSeconds }),
    });
    if (!response.ok) {
      console.warn("rateCheck non-ok", kind, response.status);
      return { allowed: true, remaining: limit, retry_after: 0 };
    }
    return await response.json();
  } catch (error) {
    console.warn("rateCheck failed", kind, error);
    return { allowed: true, remaining: limit, retry_after: 0 };
  }
}

function clientIp(request) {
  return (
    request.headers.get("cf-connecting-ip") ||
    request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
    "unknown"
  );
}

// Auto-blacklist a key + HWID + Discord user when the loader rate limit is
// breached. The pattern (many /api/v1/loader hits in a short window with the
// same key) is the signature of a diff-style dump attack; no legitimate
// executor needs to re-fetch the authenticated loader multiple times per
// minute. Logs the breach and deletes the license so the key dies instantly.
async function autoBlacklistForScrape({ env, request, key, deviceId, reason = "scrape_rate_abuse" }) {
  try {
    if (!env?.DB || !key) return;
    const keyHash = await sha256Hex(key);
    const row = await env.DB.prepare(
      "SELECT id, guild_id, discord_id, hwid_hash FROM licenses WHERE key_hash = ? LIMIT 1"
    ).bind(keyHash).first();
    if (!row) return;

    const timestamp = now();
    const ip = clientIp(request);
    const detail = { reason, ip, hwid_hint: row.hwid_hash ? String(row.hwid_hash).slice(0, 8) : null };

    if (row.discord_id) {
      await env.DB.prepare(
        `INSERT INTO blacklists (guild_id, discord_id, reason, expires_at, created_at)
         VALUES (?, ?, ?, -1, ?)
         ON CONFLICT(guild_id, discord_id) DO UPDATE SET reason = excluded.reason, expires_at = -1`
      ).bind(row.guild_id, row.discord_id, reason, timestamp).run();
    }

    if (row.hwid_hash) {
      await env.DB.prepare(
        `INSERT INTO hwid_blacklists (guild_id, hwid_hash, reason, license_id, created_at)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(guild_id, hwid_hash) DO UPDATE SET reason = excluded.reason`
      ).bind(row.guild_id, row.hwid_hash, reason, row.id, timestamp).run();
    } else if (deviceId) {
      // Even if the license never bound an HWID yet, the attacker just told us
      // their device via the X-Eternal-Device header on the breached request.
      try {
        const hwidHash = await hashDevice(env, deviceId);
        if (hwidHash) {
          await env.DB.prepare(
            `INSERT INTO hwid_blacklists (guild_id, hwid_hash, reason, license_id, created_at)
             VALUES (?, ?, ?, ?, ?)
             ON CONFLICT(guild_id, hwid_hash) DO UPDATE SET reason = excluded.reason`
          ).bind(row.guild_id, hwidHash, reason, row.id, timestamp).run();
        }
      } catch {}
    }

    await env.DB.prepare("DELETE FROM licenses WHERE id = ?").bind(row.id).run();
    await audit(env, row.guild_id, "auto.scrape_blacklist", "server", row.discord_id || row.id, detail);
    console.warn("Auto-blacklist for scrape", row.guild_id, row.discord_id, detail);
  } catch (error) {
    console.error("autoBlacklistForScrape failed", error);
  }
}

function now() {
  return Math.floor(Date.now() / 1000);
}

function cleanText(value, max = 1000) {
  if (value == null) return null;
  return String(value).trim().slice(0, max);
}

const SCRIPT_UPLOAD_EXTENSIONS = new Set([
  "txt", "lua", "luau", "md", "cfg", "ini", "json", "js", "ts", "xml", "yaml", "yml", "py", "rb", "sh", "ps1", "bat", "cmd", "toml", "conf", "log"
]);

function cleanScriptUploadFileName(value) {
  const name = cleanText(value, 255);
  if (!name || !name.includes(".")) return null;
  const ext = name.split(".").pop().toLowerCase();
  return SCRIPT_UPLOAD_EXTENSIONS.has(ext) ? name : null;
}

function bytesToHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(hex) {
  if (!hex || hex.length % 2 !== 0) throw new Error("Invalid hex");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function bytesToBase64Url(bytes) {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function base64UrlToBytes(value) {
  const normalized = value.replaceAll("-", "+").replaceAll("_", "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

async function sha256Hex(value) {
  const digest = await crypto.subtle.digest("SHA-256", enc.encode(value));
  return bytesToHex(new Uint8Array(digest));
}

async function hmacBytes(secret, value) {
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, enc.encode(value)));
}

async function safeEqualText(a, b) {
  const aHash = new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(String(a))));
  const bHash = new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(String(b))));
  if (typeof crypto.subtle.timingSafeEqual === "function") {
    return crypto.subtle.timingSafeEqual(aHash, bHash);
  }
  let diff = 0;
  for (let i = 0; i < aHash.length; i++) diff |= aHash[i] ^ bHash[i];
  return diff === 0;
}

const usedLoaderTickets = new Map();

async function loaderClientFingerprint(request) {
  const ip = request.headers.get("cf-connecting-ip") || "";
  const ua = request.headers.get("user-agent") || "";
  return sha256Hex(`${ip}\n${ua}`);
}

function pruneUsedLoaderTickets() {
  const time = Date.now();
  for (const [key, expiresAt] of usedLoaderTickets) {
    if (expiresAt <= time) usedLoaderTickets.delete(key);
  }
}

async function createLoaderTicket(env, request, { licenseId, scriptId, deviceHash, ffa = false }) {
  if (!env.CONFIG_SECRET) throw new Error("CONFIG_SECRET is not configured");
  const challenge = bytesToBase64Url(crypto.getRandomValues(new Uint8Array(18)));
  const claims = {
    l: String(licenseId || ""),
    s: String(scriptId || ""),
    d: String(deviceHash || ""),
    e: now() + 60,
    n: bytesToBase64Url(crypto.getRandomValues(new Uint8Array(12))),
    c: challenge,
    f: ffa ? 1 : 0,
  };
  const body = bytesToBase64Url(enc.encode(JSON.stringify(claims)));
  const signature = bytesToBase64Url(await hmacBytes(env.CONFIG_SECRET, `loader-ticket:${body}`));
  return {
    token: `${body}.${signature}`,
    challenge,
  };
}

async function verifyLoaderTicket(env, request, token, expected) {
  if (!env.CONFIG_SECRET || !token) return false;
  const parts = String(token).split(".");
  if (parts.length !== 2) return false;
  const [body, signature] = parts;
  const expectedSignature = bytesToBase64Url(await hmacBytes(env.CONFIG_SECRET, `loader-ticket:${body}`));
  if (!await safeEqualText(signature, expectedSignature)) return false;

  let claims;
  try {
    claims = JSON.parse(dec.decode(base64UrlToBytes(body)));
  } catch {
    return false;
  }

  if (!claims || Number(claims.e) < now()) return false;
  if (String(claims.l || "") !== String(expected.licenseId || "")) return false;
  if (String(claims.s || "") !== String(expected.scriptId || "")) return false;
  if (String(claims.d || "") !== String(expected.deviceHash || "")) return false;
  if (Number(claims.f || 0) !== (expected.ffa ? 1 : 0)) return false;

  // Every protected stage after the public loader must prove the previous
  // stage actually ran. The bootstrap receives the challenge reversed and
  // reverses it locally before sending it back.
  const stageProof = cleanText(request.headers.get("x-eternal-stage-proof"), 512);
  if (!claims.c || !stageProof) return false;
  if (!await safeEqualText(stageProof, String(claims.c))) return false;

  // Best-effort replay resistance across requests handled by the same Worker
  // isolate. The signed ticket is already short-lived and client-bound; this
  // additionally makes a captured ticket single-use on the common hot path.
  pruneUsedLoaderTickets();
  const replayKey = await sha256Hex(String(token));
  if (usedLoaderTickets.has(replayKey)) return false;
  usedLoaderTickets.set(replayKey, Date.now() + 30_000);
  return true;
}

async function configCryptoKey(env) {
  if (!env.CONFIG_SECRET) throw new Error("CONFIG_SECRET is not configured");
  const digest = await crypto.subtle.digest("SHA-256", enc.encode(env.CONFIG_SECRET));
  return crypto.subtle.importKey("raw", digest, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

async function encryptConfigSecret(env, value) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await configCryptoKey(env);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(value)));
  return `${bytesToBase64Url(iv)}.${bytesToBase64Url(ciphertext)}`;
}

async function decryptConfigSecret(env, stored) {
  const [ivText, cipherText] = String(stored || "").split(".");
  if (!ivText || !cipherText) throw new Error("Invalid encrypted config");
  const key = await configCryptoKey(env);
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64UrlToBytes(ivText) },
    key,
    base64UrlToBytes(cipherText)
  );
  return dec.decode(plain);
}

async function deriveLicenseKey(env, licenseId) {
  const bytes = await hmacBytes(env.LICENSE_KEY_SECRET, `license:${licenseId}`);
  return `EA-${bytesToBase64Url(bytes).slice(0, 40)}`;
}

async function hashDevice(env, deviceId) {
  const bytes = await hmacBytes(env.HWID_PEPPER, `device:${deviceId}`);
  return bytesToHex(bytes);
}

async function createFfaReportToken(env, guildId, scriptId, deviceHash) {
  const payload = bytesToBase64Url(enc.encode(JSON.stringify({
    g: String(guildId),
    s: String(scriptId),
    d: String(deviceHash),
    e: now() + 86400,
  })));
  const signature = bytesToHex(await hmacBytes(env.CONFIG_SECRET, `ffa-report:${payload}`));
  return `${payload}.${signature}`;
}

async function verifyFfaReportToken(env, token, deviceHash) {
  const [payload, signature, extra] = String(token || "").split(".");
  if (!payload || !signature || extra || !/^[a-f0-9]{64}$/i.test(signature)) return null;
  const expected = bytesToHex(await hmacBytes(env.CONFIG_SECRET, `ffa-report:${payload}`));
  if (!await safeEqualText(signature.toLowerCase(), expected)) return null;
  try {
    const claims = JSON.parse(dec.decode(base64UrlToBytes(payload)));
    if (!claims || claims.e < now() || claims.d !== deviceHash || !claims.g || !claims.s) return null;
    return claims;
  } catch {
    return null;
  }
}

function firstEightBytesToBigInt(bytes) {
  let out = 0n;
  for (let i = 0; i < 8; i++) out = (out << 8n) | BigInt(bytes[i] || 0);
  return out;
}

async function loaderMask(env) {
  const bytes = await hmacBytes(env.CONFIG_SECRET, "eternal-auth:loader-mask");
  return firstEightBytesToBigInt(bytes);
}

async function deriveLoaderId(env, guildId) {
  const snowflake = BigInt(guildId);
  const encoded = (snowflake ^ (await loaderMask(env))) & 0xffffffffffffffffn;
  const routePart = encoded.toString(16).padStart(16, "0");
  const tag = await hmacBytes(env.CONFIG_SECRET, `eternal-auth:loader-route:${routePart}`);
  return `${routePart}${bytesToHex(tag).slice(0, 16)}`;
}

async function guildIdFromLoaderId(env, loaderId) {
  if (!/^[a-f0-9]{32}$/i.test(loaderId || "")) return null;
  try {
    const routePart = loaderId.slice(0, 16).toLowerCase();
    const encoded = BigInt(`0x${routePart}`);
    const snowflake = encoded ^ (await loaderMask(env));
    const guildId = snowflake.toString(10);
    const expected = await deriveLoaderId(env, guildId);
    return (await safeEqualText(expected, loaderId.toLowerCase())) ? guildId : null;
  } catch {
    return null;
  }
}

async function ensureGuildLoaderId(env, guild) {
  if (!guild) return null;
  guild.loader_id = await deriveLoaderId(env, guild.guild_id);
  return guild;
}

function loaderUrlForGuild(guild) {
  if (!guild?.base_url || !guild?.loader_id) return null;
  return `${String(guild.base_url).replace(/\/$/, "")}/files/v4/loaders/${guild.loader_id}.lua`;
}

async function deriveScriptLoaderId(env, scriptId) {
  const tag = await hmacBytes(env.CONFIG_SECRET, `eternal-auth:script-loader:${scriptId}`);
  return bytesToHex(tag).slice(0, 32);
}

async function ensureScriptLoaderId(env, script) {
  if (!script) return null;
  if (!script.loader_id) {
    script.loader_id = await deriveScriptLoaderId(env, script.id);
    await env.DB.prepare("UPDATE scripts SET loader_id = ?, updated_at = ? WHERE id = ?")
      .bind(script.loader_id, now(), script.id)
      .run();
  }
  return script;
}

function loaderUrlForScript(guild, script) {
  if (!guild?.base_url || !script?.loader_id) return null;
  return `${String(guild.base_url).replace(/\/$/, "")}/files/v4/loaders/${script.loader_id}.lua`;
}

function ffaLoaderUrlForScript(guild, script) {
  if (!guild?.base_url || !script?.loader_id) return null;
  return `${String(guild.base_url).replace(/\/$/, "")}/files/v4/ffa/${script.loader_id}.lua`;
}

function safeScriptRecord(guild, script) {
  if (!script) return null;
  return {
    id: script.id,
    guild_id: script.guild_id,
    loader_id: script.loader_id,
    loader_url: guild ? loaderUrlForScript(guild, script) : null,
    ffa_loader_url: guild ? ffaLoaderUrlForScript(guild, script) : null,
    name: script.name,
    version: script.version,
    enabled: !!script.enabled,
    ffa_enabled: !!script.ffa_enabled,
    content_size: String(script.content || "").length,
    created_at: script.created_at,
    updated_at: script.updated_at,
  };
}


async function getScriptsForGuild(env, guildId, enabledOnly = false) {
  const cacheKey = `${guildId}:${enabledOnly ? "enabled" : "all"}`;
  const cached = cacheGet(scriptHotCache, cacheKey);
  if (cached) return cached.map((row) => ({ ...row }));

  const stmt = enabledOnly
    ? env.DB.prepare("SELECT * FROM scripts WHERE guild_id = ? AND enabled = 1 ORDER BY created_at ASC")
    : env.DB.prepare("SELECT * FROM scripts WHERE guild_id = ? ORDER BY created_at ASC");
  const result = await stmt.bind(guildId).all();
  const rows = result.results || [];
  await Promise.all(rows.map((row) => ensureScriptLoaderId(env, row)));
  cachePut(scriptHotCache, cacheKey, rows.map((row) => ({ ...row })));
  return rows;
}

async function ensureDefaultScript(env, guildId) {
  let script = await env.DB.prepare("SELECT * FROM scripts WHERE guild_id = ? ORDER BY created_at ASC LIMIT 1")
    .bind(guildId)
    .first();
  if (!script) {
    const timestamp = now();
    const id = crypto.randomUUID();
    const loaderId = await deriveScriptLoaderId(env, id);
    await env.DB.prepare(
      `INSERT INTO scripts (id, guild_id, loader_id, name, version, enabled, content, created_at, updated_at)
       VALUES (?, ?, ?, 'Voltra Auth Script', '1.0.0', 1, '', ?, ?)`
    ).bind(id, guildId, loaderId, timestamp, timestamp).run();
    script = await env.DB.prepare("SELECT * FROM scripts WHERE id = ?").bind(id).first();
  }
  return ensureScriptLoaderId(env, script);
}

async function createLicense(env, { guildId, discordId = null, panelId = null, days = -1, note = null }) {
  const timestamp = now();
  const id = crypto.randomUUID();
  const rawKey = await deriveLicenseKey(env, id);
  const keyHash = await sha256Hex(rawKey);
  const authExpire = Number(days) > 0 ? timestamp + Number(days) * 86400 : -1;

  await env.DB.prepare(
    `INSERT INTO licenses
      (id, guild_id, key_hash, discord_id, panel_id, status, auth_expire, note, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?, ?)`
  )
    .bind(id, guildId, keyHash, discordId, panelId, authExpire, note, timestamp, timestamp)
    .run();

  return { id, key: rawKey, auth_expire: authExpire };
}

async function findLicenseByKey(env, rawKey) {
  const keyHash = await sha256Hex(rawKey);
  return env.DB.prepare("SELECT * FROM licenses WHERE key_hash = ? LIMIT 1").bind(keyHash).first();
}

async function createServerSetupKey(env, { intendedGuildId = null, expiresInHours = 24, note = null }) {
  const timestamp = now();
  const id = crypto.randomUUID();
  const random = crypto.getRandomValues(new Uint8Array(20));
  const rawKey = `EA-SRV-${bytesToHex(random).toUpperCase()}`;
  const keyHash = await sha256Hex(rawKey.toUpperCase());
  const hours = Math.max(1, Math.min(24 * 30, Number(expiresInHours || 24)));
  const expiresAt = timestamp + Math.floor(hours * 3600);
  const hint = `${rawKey.slice(0, 14)}…${rawKey.slice(-6)}`;
  const keyEnc = await encryptConfigSecret(env, rawKey);

  await env.DB.prepare(
    `INSERT INTO server_setup_keys
      (id, key_hash, key_hint, key_enc, intended_guild_id, note, expires_at, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(id, keyHash, hint, keyEnc, intendedGuildId || null, note || null, expiresAt, timestamp)
    .run();

  return { id, key: rawKey, key_hint: hint, intended_guild_id: intendedGuildId || null, note: note || null, expires_at: expiresAt, created_at: timestamp };
}

async function consumeServerSetupKey(env, rawKey, guildId, discordId) {
  const normalized = String(rawKey || "").trim().toUpperCase();
  if (!/^EA-SRV-[A-F0-9]{40}$/.test(normalized)) return { ok: false, error: "Invalid Voltra Auth server key." };

  const keyHash = await sha256Hex(normalized);
  const row = await env.DB.prepare(
    `SELECT * FROM server_setup_keys WHERE key_hash = ? LIMIT 1`
  ).bind(keyHash).first();

  if (!row) return { ok: false, error: "Invalid Voltra Auth server key." };
  if (row.used_at) return { ok: false, error: "That Voltra Auth server key has already been used." };
  if (Number(row.expires_at) > 0 && Number(row.expires_at) <= now()) {
    return { ok: false, error: "That Voltra Auth server key has expired." };
  }
  if (row.intended_guild_id && String(row.intended_guild_id) !== String(guildId)) {
    return { ok: false, error: "That server key was created for a different Discord server." };
  }

  const usedAt = now();
  const result = await env.DB.prepare(
    `UPDATE server_setup_keys
     SET used_at = ?, used_by_guild_id = ?, used_by_discord_id = ?
     WHERE id = ? AND used_at IS NULL`
  ).bind(usedAt, guildId, discordId, row.id).run();

  if (!result?.meta?.changes) return { ok: false, error: "That Voltra Auth server key has already been used." };
  return { ok: true, row: { ...row, used_at: usedAt, used_by_guild_id: guildId, used_by_discord_id: discordId } };
}

async function findLicenseForDiscord(env, guildId, discordId) {
  return env.DB.prepare(
    `SELECT * FROM licenses
     WHERE guild_id = ? AND discord_id = ? AND status = 'active'
     ORDER BY created_at DESC LIMIT 1`
  )
    .bind(guildId, discordId)
    .first();
}

// Does this Discord user already hold an active license for THIS specific
// panel? Used to prevent duplicate whitelists per panel while still allowing
// the same user to be whitelisted on multiple panels in the same project.
async function findLicenseForDiscordAndPanel(env, guildId, discordId, panelId) {
  return env.DB.prepare(
    `SELECT * FROM licenses
     WHERE guild_id = ? AND discord_id = ? AND panel_id = ? AND status = 'active'
     ORDER BY created_at DESC LIMIT 1`
  )
    .bind(guildId, discordId, panelId)
    .first();
}

async function findAnyLicenseForDiscord(env, guildId, discordId) {
  return env.DB.prepare(
    `SELECT * FROM licenses WHERE guild_id = ? AND discord_id = ? ORDER BY created_at DESC LIMIT 1`
  ).bind(guildId, discordId).first();
}

async function isBlacklisted(env, guildId, discordId) {
  if (!discordId) return null;
  const row = await env.DB.prepare(
    "SELECT * FROM blacklists WHERE guild_id = ? AND discord_id = ? LIMIT 1"
  )
    .bind(guildId, discordId)
    .first();
  if (!row) return null;
  if (row.expires_at !== -1 && row.expires_at <= now()) {
    await env.DB.prepare("DELETE FROM blacklists WHERE guild_id = ? AND discord_id = ?")
      .bind(guildId, discordId)
      .run();
    await env.DB.prepare("UPDATE licenses SET status = 'active', updated_at = ? WHERE guild_id = ? AND discord_id = ? AND status = 'blacklisted'")
      .bind(now(), guildId, discordId)
      .run();
    return null;
  }
  return row;
}

async function recoverLegacyLoaderProbe(env, license, deviceHash) {
  if (!license || !deviceHash) return false;
  const autoReasons = [
    "loader_probe","integrity","environment","http_spy","hwid_spoof",
    "gui","clipboard","file","console","network"
  ];
  const row = await env.DB.prepare(
    `SELECT reason FROM hwid_blacklists
      WHERE guild_id = ? AND hwid_hash = ?
        AND reason IN (${autoReasons.map(() => "?").join(",")})
      LIMIT 1`
  ).bind(license.guild_id, deviceHash, ...autoReasons).first();

  const autoBlockedStatus = license.status === "security_blacklisted";
  if (!row && !autoBlockedStatus) return false;

  await env.DB.batch([
    env.DB.prepare(
      `DELETE FROM hwid_blacklists
        WHERE guild_id = ? AND hwid_hash = ?
          AND reason IN (${autoReasons.map(() => "?").join(",")})`
    ).bind(license.guild_id, deviceHash, ...autoReasons),
    env.DB.prepare(
      "UPDATE licenses SET status = 'active', updated_at = ? WHERE guild_id = ? AND hwid_hash = ? AND status = 'security_blacklisted'"
    ).bind(now(), license.guild_id, deviceHash),
  ]);
  license.status = "active";
  return true;
}

async function validateLicense(env, license, deviceId = null, shouldBindDevice = true) {
  if (!license) return { ok: false, error: "Invalid key" };

  const requestedDeviceHash = deviceId ? await hashDevice(env, deviceId) : null;
  await recoverLegacyLoaderProbe(env, license, requestedDeviceHash);
  const stillDeviceBlocked = await deviceBlocked(env, license.guild_id, license.hwid_hash, requestedDeviceHash);
  if (license.status === "security_blacklisted" && requestedDeviceHash && !stillDeviceBlocked) {
    await env.DB.prepare("UPDATE licenses SET status = 'active', updated_at = ? WHERE id = ? AND status = 'security_blacklisted'")
      .bind(now(), license.id)
      .run();
    license.status = "active";
  }
  if (license.status === "security_blacklisted" || stillDeviceBlocked) return { ok: false, error: "Blacklisted" };

  const blocked = await isBlacklisted(env, license.guild_id, license.discord_id);
  if (blocked) return { ok: false, error: "License is blacklisted", reason: blocked.reason || null };

  // A temporary blacklist may have just expired and been cleared by isBlacklisted().
  if (license.status === "blacklisted") {
    await env.DB.prepare("UPDATE licenses SET status = 'active', updated_at = ? WHERE id = ? AND status = 'blacklisted'")
      .bind(now(), license.id)
      .run();
    license.status = "active";
  }

  if (license.status !== "active") return { ok: false, error: "License is disabled" };
  if (license.auth_expire !== -1 && license.auth_expire <= now()) {
    return { ok: false, error: "License expired" };
  }

  if (deviceId) {
    const deviceHash = requestedDeviceHash;
    if (!license.hwid_hash && shouldBindDevice) {
      if (!await bindDevice(env, license, deviceHash, now())) return { ok: false, error: "Device mismatch. Reset HWID first." };
      license.hwid_hash = deviceHash;
    } else if (license.hwid_hash && license.hwid_hash !== deviceHash) {
      return { ok: false, error: "Device mismatch. Reset HWID first." };
    }
  }

  return { ok: true };
}

async function handleSecurityReport(request, env) {
  const body = await readJson(request);
  const key = cleanText(body?.key, 256);
  const deviceId = cleanText(body?.device_id, 512);
  const reason = cleanText(body?.reason, 32);
  if (!key || !deviceId) return publicJson({ ok: false, error: "Missing key or HWID" }, 400);
  if (!PERSISTENT_SECURITY_REASONS.has(reason) && !NON_PERSISTENT_SECURITY_REASONS.has(reason)) return publicJson({ ok: false, error: "Invalid report" }, 400);
  const license = await findLicenseByKey(env, key);
  const hash = await hashDevice(env, deviceId);
  if (!license || !license.hwid_hash || license.hwid_hash !== hash) return publicJson({ ok: false, error: "Invalid key or HWID" }, 403);

  // Every persistent reason now blacklists the HWID + marks the license
  // security_blacklisted. The reason string is stored as-is so the
  // dashboard can show WHY the device was banned (tampering vs clipboard_source
  // vs http_spy vs loadstring_hook, etc.).
  if (PERSISTENT_SECURITY_REASONS.has(reason)) {
    const timestamp = now();
    const storedReason = reason === "clipboard_source" ? "clipboard_source_confirmed" : reason;
    await env.DB.batch([
      env.DB.prepare(
        "INSERT OR REPLACE INTO hwid_blacklists (guild_id, hwid_hash, reason, license_id, created_at) VALUES (?, ?, ?, ?, ?)"
      ).bind(license.guild_id, hash, storedReason, license.id, timestamp),
      env.DB.prepare(
        "UPDATE licenses SET status = 'security_blacklisted', updated_at = ? WHERE guild_id = ? AND (hwid_hash = ? OR id = ?)"
      ).bind(timestamp, license.guild_id, hash, license.id),
    ]);
    license.status = "security_blacklisted";
    return publicJson({ ok: true, status: "Blacklisted", persistent: true, reason: storedReason });
  }

  return publicJson({ ok: true, status: "Observed", persistent: false });
}

async function handleFfaSecurityReport(request, env) {
  const body = await readJson(request);
  const deviceId = cleanText(body?.device_id, 512);
  const reason = cleanText(body?.reason, 32);
  const token = cleanText(body?.token, 2048);
  if (!deviceId || !token) return publicJson({ ok: false, error: "Missing report proof or HWID" }, 400);
  if (!PERSISTENT_SECURITY_REASONS.has(reason) && !NON_PERSISTENT_SECURITY_REASONS.has(reason)) return publicJson({ ok: false, error: "Invalid report" }, 400);

  const hash = await hashDevice(env, deviceId);
  const claims = await verifyFfaReportToken(env, token, hash);
  if (!claims) return publicJson({ ok: false, error: "Invalid report proof" }, 403);
  const script = await env.DB.prepare("SELECT id, guild_id, enabled, ffa_enabled FROM scripts WHERE id = ? AND guild_id = ? LIMIT 1")
    .bind(String(claims.s), String(claims.g))
    .first();
  if (!script || !script.enabled || !script.ffa_enabled) return publicJson({ ok: false, error: "FFA access is disabled" }, 403);

  if (PERSISTENT_SECURITY_REASONS.has(reason)) {
    const timestamp = now();
    const storedReason = reason === "clipboard_source" ? "clipboard_source_confirmed" : reason;
    await env.DB.batch([
      env.DB.prepare(
        "INSERT OR REPLACE INTO hwid_blacklists (guild_id, hwid_hash, reason, license_id, created_at) VALUES (?, ?, ?, ?, ?)"
      ).bind(script.guild_id, hash, storedReason, `ffa:${script.id}`, timestamp),
      env.DB.prepare(
        "UPDATE licenses SET status = 'security_blacklisted', updated_at = ? WHERE guild_id = ? AND hwid_hash = ?"
      ).bind(timestamp, script.guild_id, hash),
    ]);
    return publicJson({ ok: true, status: "Blacklisted", persistent: true, reason: storedReason });
  }

  return publicJson({ ok: true, status: "Observed", persistent: false });
}

async function handleVerify(request, env) {
  const body = await readJson(request);
  const key = cleanText(body?.key, 256);
  const deviceId = cleanText(body?.device_id, 512);
  const scriptId = cleanText(body?.script_id, 128);
  if (!key) return publicJson({ ok: false, error: "Missing key" }, 400);
  if (!deviceId) return publicJson({ ok: false, error: "Missing HWID" }, 400);

  const license = await findLicenseByKey(env, key);
  const valid = await validateLicense(env, license, deviceId, true);
  if (!valid.ok) return publicJson(valid, 403);

  await env.DB.prepare("INSERT INTO executions (guild_id, license_id, occurred_at) VALUES (?, ?, ?)")
    .bind(license.guild_id, license.id, now())
    .run();

  let script = null;
  if (scriptId) {
    script = await env.DB.prepare("SELECT id, name, version, enabled FROM scripts WHERE id = ? AND guild_id = ? LIMIT 1")
      .bind(scriptId, license.guild_id)
      .first();
  } else {
    script = await env.DB.prepare("SELECT id, name, version, enabled FROM scripts WHERE guild_id = ? ORDER BY created_at ASC LIMIT 1")
      .bind(license.guild_id)
      .first();
  }

  if (script && !script.enabled) return publicJson({ ok: false, error: "Script is disabled" }, 503);
  if (license.panel_id) {
    const panel = await getPanel(env, license.guild_id, license.panel_id);
    if (!panel || !script || panel.script_id !== script.id) return publicJson({ ok: false, error: "License is not assigned to this panel" }, 403);
  }

  return publicJson({
    ok: true,
    expires_at: license.auth_expire,
    lifetime: license.auth_expire === -1,
    note: license.note || null,
    script: script ? { id: script.id, name: script.name, version: script.version } : null,
  });
}

async function handleProtectedLoader(request, env, ctx) {
  const url = new URL(request.url);
  const { key, deviceId, legacyDeviceId } = sourceCredentials(request);
  const scriptId = cleanText(url.searchParams.get("script_id"), 128);
  const loaderTicket = cleanText(request.headers.get("x-eternal-ticket"), 4096);

  if (!hasLoaderExecutionIntent(request)) return deniedSource("Execution request missing");
  if (!loaderTicket) return deniedSource("Loader ticket missing");

  if (!key) return deniedSource("Missing key");
  if (!deviceId) return deniedSource("Missing HWID");

  // Per-key rate limit on the authenticated loader. A legitimate executor
  // calls this once per game join (minutes between calls). Any key hitting
  // this endpoint more than a handful of times in 60s is almost certainly
  // a dump workflow doing diff attacks across obfuscated outputs. On breach
  // we auto-blacklist the license, the HWID (if bound), and the Discord
  // user — see autoBlacklistForScrape below.
  const keyFingerprint = (await sha256Hex(key)).slice(0, 24);
  const keyRate = await rateCheck(env, "loader-key", keyFingerprint, 4, 60);
  if (!keyRate.allowed) {
    const banCtx = { env, request, key, deviceId, reason: "scrape_rate_abuse" };
    if (ctx?.waitUntil) ctx.waitUntil(autoBlacklistForScrape(banCtx)); else await autoBlacklistForScrape(banCtx);
    return blacklistedSource();
  }

  // Fast path: hash the license key and HWID in parallel, then fetch the
  // license, blacklist state and requested script in one D1 query.
  const [keyHash, deviceHash] = await Promise.all([
    sha256Hex(key),
    deviceId ? hashDevice(env, deviceId) : Promise.resolve(null),
  ]);

  let row = null;
  if (scriptId) {
    row = await env.DB.prepare(`
      SELECT
        l.*,
        b.reason AS ea_blacklist_reason,
        b.expires_at AS ea_blacklist_expires_at,
        s.id AS ea_script_id,
        s.name AS ea_script_name,
        s.version AS ea_script_version,
        s.enabled AS ea_script_enabled,
        s.content AS ea_script_content
      FROM licenses l
      LEFT JOIN blacklists b
        ON b.guild_id = l.guild_id AND b.discord_id = l.discord_id
      LEFT JOIN scripts s
        ON s.id = ? AND s.guild_id = l.guild_id
      WHERE l.key_hash = ?
      LIMIT 1
    `).bind(scriptId, keyHash).first();
  } else {
    row = await env.DB.prepare(`
      SELECT
        l.*,
        b.reason AS ea_blacklist_reason,
        b.expires_at AS ea_blacklist_expires_at
      FROM licenses l
      LEFT JOIN blacklists b
        ON b.guild_id = l.guild_id AND b.discord_id = l.discord_id
      WHERE l.key_hash = ?
      LIMIT 1
    `).bind(keyHash).first();
  }

  if (!row) {
    return deniedSource("Invalid key");
  }

  await migrateLegacyDeviceBinding(env, row, deviceId, legacyDeviceId);
  const effectiveDeviceHash = await hashDevice(env, deviceId);
  await recoverLegacyLoaderProbe(env, row, effectiveDeviceHash);
  if (row.status === "security_blacklisted" || await deviceBlocked(env, row.guild_id, effectiveDeviceHash, row.hwid_hash)) {
    return blacklistedSource();
  }
  const timestamp = now();
  const blacklistExpiry = row.ea_blacklist_expires_at == null ? null : Number(row.ea_blacklist_expires_at);
  const hasActiveBlacklist = blacklistExpiry != null && (blacklistExpiry === -1 || blacklistExpiry > timestamp);

  if (hasActiveBlacklist) {
    return blacklistedSource();
  }

  // Expired temporary blacklist cleanup is not part of the critical loader
  // response path. Let Cloudflare finish it after the protected source is sent.
  if (blacklistExpiry != null && blacklistExpiry !== -1 && blacklistExpiry <= timestamp) {
    const cleanup = env.DB.batch([
      env.DB.prepare("DELETE FROM blacklists WHERE guild_id = ? AND discord_id = ? AND expires_at != -1 AND expires_at <= ?")
        .bind(row.guild_id, row.discord_id, timestamp),
      env.DB.prepare("UPDATE licenses SET status = 'active', updated_at = ? WHERE id = ? AND status = 'blacklisted'")
        .bind(timestamp, row.id),
    ]);
    if (ctx?.waitUntil) ctx.waitUntil(cleanup); else await cleanup;
    if (row.status === "blacklisted") row.status = "active";
  }

  if (row.status !== "active") {
    const message = row.status === "disabled"
      ? "The script you are trying to access has been disabled by its owner."
      : `Voltra Auth: License is ${row.status || "disabled"}`;
    return deniedSource();
  }

  if (Number(row.auth_expire) !== -1 && Number(row.auth_expire) <= timestamp) {
    return deniedSource();
  }

  if (effectiveDeviceHash) {
    if (!row.hwid_hash) {
      // Only the first device bind requires an awaited write. Normal executions
      // skip this write completely.
      if (!await bindDevice(env, row, effectiveDeviceHash, timestamp)) return deniedSource("HWID bind failed");
      row.hwid_hash = effectiveDeviceHash;
    } else if (row.hwid_hash !== effectiveDeviceHash) {
      return deniedSource("HWID mismatch");
    }
  }

  let script = null;
  if (scriptId) {
    if (row.ea_script_id) {
      script = {
        id: row.ea_script_id,
        name: row.ea_script_name,
        version: row.ea_script_version,
        enabled: row.ea_script_enabled,
        content: row.ea_script_content,
      };
    }
  } else {
    // Backward-compatible direct calls without a script_id use the first script.
    script = await env.DB.prepare("SELECT * FROM scripts WHERE guild_id = ? ORDER BY created_at ASC LIMIT 1")
      .bind(row.guild_id)
      .first();
  }

  if (!script || !script.enabled || !script.content) {
    return deniedSource();
  }
  if (row.panel_id) {
    const assignedPanel = await getPanel(env, row.guild_id, row.panel_id);
    if (!assignedPanel) return deniedSource("Assigned panel is unavailable");
    if (assignedPanel.script_id !== script.id) return deniedSource("Key is assigned to a different script");
  }

  if (!await verifyLoaderTicket(env, request, loaderTicket, {
    licenseId: row.id,
    scriptId: script.id,
    deviceHash: effectiveDeviceHash,
    ffa: false,
  })) return deniedSource("Loader ticket invalid or expired");

  const executionLog = env.DB.prepare("INSERT INTO executions (guild_id, license_id, occurred_at) VALUES (?, ?, ?)")
    .bind(row.guild_id, row.id, timestamp)
    .run();
  if (ctx?.waitUntil) ctx.waitUntil(executionLog); else await executionLog;

  // Per-license obfuscated Lua. The watermark is unique per license id so
  // a leaked copy identifies the user; the heavy transform is cached per
  // (script, updated_at, license) in-isolate so hot path hits are O(copy).
  const protectedPayload = await obfuscateForLicense(
    env, script.content, row.id, script.id, script.ea_script_updated_at || script.updated_at,
  );

  return new Response(protectedPayload, {
    status: 200,
    headers: {
      "content-type": "text/plain; charset=utf-8",
      "cache-control": "no-store, no-cache, must-revalidate",
      pragma: "no-cache",
      "x-eternal-auth": "protected",
      "x-eternal-script-id": script.id,
    },
  });
}

// Per-isolate cache of obfuscated Lua, keyed by (scriptId, scriptUpdatedAt,
// licenseId). The watermark is still unique per license (so leaked copies
// identify the user) but the expensive tokenize/encrypt/minify pass only
// runs on cache miss. TTL is a safety floor; stale script content naturally
// invalidates because scripts.updated_at bumps on admin edit.
const OBFUSCATION_CACHE_TTL_MS = 10 * 60 * 1000;
const OBFUSCATION_CACHE_MAX = 128;
const obfuscationCache = new Map();

async function obfuscateForLicense(env, source, licenseId, scriptId, scriptUpdatedAt) {
  const canCache = scriptId != null && licenseId != null;
  const cacheKey = canCache ? `${scriptId}:${scriptUpdatedAt || 0}:${licenseId}` : null;

  if (cacheKey) {
    const hit = obfuscationCache.get(cacheKey);
    if (hit && hit.expiresAt > Date.now()) return hit.value;
    if (hit) obfuscationCache.delete(cacheKey);
  }

  let watermark = "";
  try {
    if (env?.CONFIG_SECRET && licenseId != null) {
      const bytes = await hmacBytes(env.CONFIG_SECRET, `license-watermark:${licenseId}`);
      watermark = bytesToHex(bytes.subarray(0, 8));
    }
  } catch {}

  let output;
  try {
    output = obfuscateLua(source, { watermark });
  } catch (error) {
    console.warn("Lua obfuscation failed, serving raw", error);
    output = source;
  }

  if (cacheKey) {
    if (obfuscationCache.size >= OBFUSCATION_CACHE_MAX) {
      // Evict the oldest entry (insertion-ordered Map).
      const oldest = obfuscationCache.keys().next().value;
      if (oldest !== undefined) obfuscationCache.delete(oldest);
    }
    obfuscationCache.set(cacheKey, { value: output, expiresAt: Date.now() + OBFUSCATION_CACHE_TTL_MS });
  }

  return output;
}


function isBrowserNavigation(request) {
  const mode = (request.headers.get("sec-fetch-mode") || "").toLowerCase();
  const dest = (request.headers.get("sec-fetch-dest") || "").toLowerCase();
  const fetchUser = (request.headers.get("sec-fetch-user") || "").toLowerCase();
  return mode === "navigate" || dest === "document" || fetchUser === "?1";
}

function hasLoaderExecutionIntent(request) {
  return request.headers.get("x-eternal-execute") === "1" && !isBrowserNavigation(request);
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  })[c]);
}

function loaderBrowserPage(loaderUrl) {
  const snippet = `script_key = "KEY"; -- A key might be required, if not, delete this line.\nloadstring(game:HttpGet("${loaderUrl}"))()`;
  const safeSnippet = escapeHtml(snippet);
  return new Response(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Voltra Auth • Loadstring</title>
<style>
  :root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;min-height:100vh;background:#181d31;color:#f4f6ff;font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;display:grid;place-items:center}.wrap{width:min(830px,calc(100% - 32px));text-align:center}.title{font-weight:800;font-size:21px;margin:0 0 20px}.card{position:relative;background:#111626;border:1px solid rgba(255,255,255,.035);border-radius:12px;padding:20px 78px 20px 18px;box-shadow:0 16px 40px rgba(0,0,0,.2);text-align:left;overflow:auto}.card pre{margin:0;white-space:pre;min-width:max-content;font:14px/1.6 ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono",monospace}.copy{position:absolute;right:12px;top:11px;border:1px solid #42507a;background:#27345d;color:#fff;border-radius:9px;padding:8px 14px;font-weight:700;cursor:pointer}.copy:hover{background:#324173}.note{font-size:12px;margin-top:17px;color:#d5d9e6}.brand{color:#8ba6ff}.comment{color:#6fbd73}.kw{color:#8ec5ff}.str{color:#ff8c7a}
</style>
</head>
<body>
<main class="wrap">
  <h1 class="title">📜 Loadstring</h1>
  <section class="card">
    <button class="copy" id="copyBtn" type="button">Copy</button>
    <pre id="code">${safeSnippet}</pre>
  </section>
  <div class="note">Contents can not be displayed in browser • <span class="brand">Voltra Auth</span></div>
</main>
<script>
  document.getElementById('copyBtn').addEventListener('click', async () => {
    const b=document.getElementById('copyBtn');
    try{await navigator.clipboard.writeText(document.getElementById('code').innerText);b.textContent='Copied';setTimeout(()=>b.textContent='Copy',1200)}catch{b.textContent='Copy failed'}
  });
</script>
</body>
</html>`, {
    status: 200,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store, no-cache, must-revalidate",
      "x-content-type-options": "nosniff",
      "x-frame-options": "DENY",
      "referrer-policy": "no-referrer",
      "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
    },
  });
}

function protectedBrowserPage(origin) {
  return new Response(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Voltra Auth</title><style>:root{color-scheme:dark}body{margin:0;min-height:100vh;background:#181d31;color:#f4f6ff;font-family:Inter,system-ui,sans-serif;display:grid;place-items:center}.box{text-align:center}.box h1{font-size:22px}.box p{color:#b9c0d4}</style></head><body><div class="box"><h1>🔒 Voltra Auth</h1><p>Protected source cannot be displayed in a browser.</p><p>${escapeHtml(origin)}</p></div></body></html>`, {
    status: 200,
    headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "x-frame-options": "DENY", "x-content-type-options": "nosniff" },
  });
}

function buildRobloxKickSource(message) {
  return `local Players = game:GetService("Players")
local player = Players.LocalPlayer
if player then
    player:Kick(${JSON.stringify(message)})
end`;
}


async function handlePublicLoader(request, env, loaderId, ctx) {
  const credentials = sourceCredentials(request);
  if (!credentials.key || !credentials.deviceId) {
    const cleanUrl = `${new URL(request.url).origin}/files/v4/loaders/${loaderId}.lua`;
    return new Response(authenticatedLauncher(cleanUrl), {
      status: 200,
      headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "private, no-store, max-age=0", "x-content-type-options": "nosniff" },
    });
  }
  const license = await findLicenseByKey(env, credentials.key);
  if (!license) return deniedSource("Invalid key");

  await migrateLegacyDeviceBinding(
    env,
    license,
    credentials.deviceId,
    credentials.legacyDeviceId,
  );

  let script = await env.DB.prepare("SELECT * FROM scripts WHERE loader_id = ? LIMIT 1")
    .bind(loaderId)
    .first();

  // Older databases can contain a stale/null loader_id. Re-derive loader ids
  // only inside the authenticated license's project and repair the matching row.
  if (!script) {
    const candidates = await env.DB.prepare(
      "SELECT * FROM scripts WHERE guild_id = ? ORDER BY created_at ASC"
    ).bind(license.guild_id).all();

    for (const candidate of candidates.results || []) {
      const expectedLoaderId = await deriveScriptLoaderId(env, candidate.id);
      if (String(expectedLoaderId).toLowerCase() !== String(loaderId).toLowerCase()) continue;
      script = { ...candidate, loader_id: expectedLoaderId };
      if (candidate.loader_id !== expectedLoaderId) {
        await env.DB.prepare("UPDATE scripts SET loader_id = ?, updated_at = ? WHERE id = ?")
          .bind(expectedLoaderId, now(), candidate.id)
          .run();
        cacheDelete(scriptHotCache, `${candidate.guild_id}:all`);
        cacheDelete(scriptHotCache, `${candidate.guild_id}:enabled`);
      }
      break;
    }
  }

  // A copied loader URL can outlive a loader-id migration. Once the key is
  // authenticated, use the license's own panel/script mapping as the source of
  // truth instead of rejecting a valid license because the URL id is stale.
  if (!script && license.panel_id) {
    const assignedPanel = await env.DB.prepare(
      "SELECT * FROM panels WHERE id = ? AND guild_id = ? LIMIT 1"
    ).bind(license.panel_id, license.guild_id).first();

    if (assignedPanel && Number(assignedPanel.active || 0) === 1 && assignedPanel.script_id) {
      const assignedScript = await env.DB.prepare(
        "SELECT * FROM scripts WHERE id = ? AND guild_id = ? LIMIT 1"
      ).bind(assignedPanel.script_id, license.guild_id).first();
      if (assignedScript) script = await ensureScriptLoaderId(env, assignedScript);
    }
  }

  // Older unscoped/stock keys may not have a panel. If there is only one
  // enabled script in the licensed project, there is no ambiguity, so allow a
  // stale loader URL to resolve to that one script.
  if (!script && !license.panel_id) {
    const enabledScripts = await env.DB.prepare(
      "SELECT * FROM scripts WHERE guild_id = ? AND enabled = 1 ORDER BY created_at ASC LIMIT 2"
    ).bind(license.guild_id).all();
    const rows = enabledScripts.results || [];
    if (rows.length === 1) script = await ensureScriptLoaderId(env, rows[0]);
  }

  let guild = null;
  if (script) {
    // Do not use getGuild() here because it intentionally filters active=1,
    // which made disabled/legacy projects look like they did not exist.
    const rawGuild = await env.DB.prepare(
      "SELECT * FROM guilds WHERE guild_id = ? LIMIT 1"
    ).bind(script.guild_id).first();
    guild = rawGuild ? await ensureGuildLoaderId(env, rawGuild) : null;

    // If an old migration lost the guild row but the authenticated license and
    // script still agree on the project, rebuild the minimal project record.
    if (!guild && String(script.guild_id) === String(license.guild_id)) {
      const origin = new URL(request.url).origin;
      const timestamp = now();
      await env.DB.prepare(
        `INSERT OR IGNORE INTO guilds
          (guild_id, active, base_url, loader_template, created_at, updated_at)
         VALUES (?, 1, ?, ?, ?, ?)`
      ).bind(
        license.guild_id,
        origin,
        defaultLoaderTemplate(),
        timestamp,
        timestamp,
      ).run();
      cacheDelete(guildHotCache, license.guild_id);
      const repairedGuild = await env.DB.prepare(
        "SELECT * FROM guilds WHERE guild_id = ? LIMIT 1"
      ).bind(license.guild_id).first();
      guild = repairedGuild ? await ensureGuildLoaderId(env, repairedGuild) : null;
    }
  } else {
    // Backward compatibility for the old one-loader-per-guild URLs.
    const legacyGuildId = await guildIdFromLoaderId(env, loaderId);
    const rawGuild = legacyGuildId
      ? await env.DB.prepare("SELECT * FROM guilds WHERE guild_id = ? LIMIT 1").bind(legacyGuildId).first()
      : null;
    guild = rawGuild ? await ensureGuildLoaderId(env, rawGuild) : null;
    if (guild) {
      script = await env.DB.prepare("SELECT * FROM scripts WHERE guild_id = ? ORDER BY created_at ASC LIMIT 1")
        .bind(guild.guild_id)
        .first();
      if (script) script = await ensureScriptLoaderId(env, script);
    }
  }

  if (!script) return deniedSource("Script not found. Copy a fresh loader URL.");
  if (!guild) return deniedSource("Project record missing");
  if (!Number(guild.active)) return deniedSource("Project disabled");
  if (!script.enabled) return deniedSource("Script disabled");
  if (!script.content) return deniedSource("Script source is empty");
  if (license.guild_id !== guild.guild_id) return deniedSource("Key belongs to a different project");
  if (license.panel_id) {
    const assignedPanel = await getPanel(env, guild.guild_id, license.panel_id);
    if (!assignedPanel || assignedPanel.script_id !== script.id) return deniedSource();
  }
  const valid = await validateLicense(env, license, credentials.deviceId, true);
  if (!valid.ok) return valid.error === "Blacklisted" ? blacklistedSource() : deniedSource(valid.error);
  if (!hasLoaderExecutionIntent(request)) {
    const cleanUrl = `${new URL(request.url).origin}/files/v4/loaders/${loaderId}.lua`;
    return new Response(authenticatedLauncher(cleanUrl), {
      status: 200,
      headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "private, no-store, max-age=0", "x-content-type-options": "nosniff" },
    });
  }
  const deviceHash = await hashDevice(env, credentials.deviceId);
  const loaderGrant = await createLoaderTicket(env, request, {
    licenseId: license.id,
    scriptId: script.id,
    deviceHash,
    ffa: false,
  });
  return new Response(buildBootstrapSource(
    new URL(request.url).origin,
    script.id,
    false,
    "",
    loaderGrant.token,
    loaderGrant.challenge,
  ), {
    status: 200,
    headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "private, no-store, max-age=0", "vary": "Authorization, X-Eternal-Device", "x-content-type-options": "nosniff" },
  });
}

async function handleFfaPublicLoader(request, env, loaderId) {
  const { deviceId } = sourceCredentials(request);
  const cleanUrl = `${new URL(request.url).origin}/files/v4/ffa/${loaderId}.lua`;
  if (!deviceId) return new Response(ffaBootstrapLua(cleanUrl), {
    status: 200,
    headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "private, no-store, max-age=0", "x-content-type-options": "nosniff" },
  });
  const script = await env.DB.prepare("SELECT * FROM scripts WHERE loader_id = ? LIMIT 1")
    .bind(loaderId)
    .first();
  if (!script || !script.enabled || !script.ffa_enabled || !script.content) return deniedSource();
  const guild = await env.DB.prepare("SELECT * FROM guilds WHERE guild_id = ? LIMIT 1").bind(script.guild_id).first();
  if (!guild?.active) return deniedSource();
  const deviceHash = await hashDevice(env, deviceId);
  if (await deviceBlocked(env, guild.guild_id, deviceHash)) return blacklistedSource();
  // FFA requests have no account secret. Require the execution-only launcher
  // marker, but do not trust a caller-supplied raw HWID enough to blacklist it
  // until the signed in-runtime report proof is available.
  if (!hasLoaderExecutionIntent(request)) return new Response(ffaBootstrapLua(cleanUrl), {
    status: 200,
    headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "private, no-store, max-age=0", "x-content-type-options": "nosniff" },
  });
  const reportToken = await createFfaReportToken(env, guild.guild_id, script.id, deviceHash);
  const loaderGrant = await createLoaderTicket(env, request, {
    licenseId: "FFA",
    scriptId: script.id,
    deviceHash,
    ffa: true,
  });
  return new Response(buildBootstrapSource(
    new URL(request.url).origin,
    script.id,
    true,
    reportToken,
    loaderGrant.token,
    loaderGrant.challenge,
  ), {
    status: 200,
    headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "private, no-store, max-age=0", "vary": "X-Eternal-Device", "x-content-type-options": "nosniff" },
  });
}

async function handleFfaProtectedLoader(request, env) {
  const url = new URL(request.url);
  const { deviceId } = sourceCredentials(request);
  const scriptId = cleanText(url.searchParams.get("script_id"), 128);
  const loaderTicket = cleanText(request.headers.get("x-eternal-ticket"), 4096);
  if (!hasLoaderExecutionIntent(request) || !loaderTicket || !deviceId || !scriptId) return deniedSource();
  const script = await env.DB.prepare("SELECT * FROM scripts WHERE id = ? LIMIT 1")
    .bind(scriptId)
    .first();
  if (!script || !script.enabled || !script.ffa_enabled || !script.content) return deniedSource();
  const guild = await env.DB.prepare("SELECT * FROM guilds WHERE guild_id = ? LIMIT 1").bind(script.guild_id).first();
  if (!guild?.active) return deniedSource();
  const deviceHash = await hashDevice(env, deviceId);
  if (await deviceBlocked(env, guild.guild_id, deviceHash)) return blacklistedSource();
  if (!await verifyLoaderTicket(env, request, loaderTicket, {
    licenseId: "FFA",
    scriptId: script.id,
    deviceHash,
    ffa: true,
  })) return deniedSource();
  return new Response(script.content, {
    status: 200,
    headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "private, no-store, max-age=0", "vary": "X-Eternal-Device", "x-eternal-auth": "ffa", "x-eternal-script-id": script.id, "x-content-type-options": "nosniff" },
  });
}

function deniedSource(message = "Access denied") {
  return new Response(String(message || "Access denied"), {
    status: 403,
    headers: {
      "content-type": "text/plain; charset=utf-8",
      "cache-control": "private, no-store, max-age=0",
      "x-content-type-options": "nosniff",
    },
  });
}

function blacklistedSource() {
  return new Response("Blacklisted", {
    status: 403,
    headers: {
      "content-type": "text/plain; charset=utf-8",
      "cache-control": "private, no-store, max-age=0",
      "x-content-type-options": "nosniff",
    },
  });
}

function sourceCredentials(request) {
  const url = new URL(request.url);
  const bearer = (request.headers.get("authorization") || "").match(/^Bearer (.+)$/i);
  return {
    key: cleanText(bearer?.[1] || url.searchParams.get("key"), 256),
    deviceId: cleanText(request.headers.get("x-eternal-device") || url.searchParams.get("device_id"), 512),
    legacyDeviceId: cleanText(request.headers.get("x-eternal-legacy-device"), 512),
  };
}

async function migrateLegacyDeviceBinding(env, license, deviceId, legacyDeviceId) {
  if (!license?.id || !license.hwid_hash || !deviceId || !legacyDeviceId) return false;
  if (String(deviceId) === String(legacyDeviceId)) return false;

  const [currentHash, legacyHash] = await Promise.all([
    hashDevice(env, deviceId),
    hashDevice(env, legacyDeviceId),
  ]);
  if (license.hwid_hash !== legacyHash || currentHash === legacyHash) return false;

  const result = await env.DB.prepare(
    "UPDATE licenses SET hwid_hash = ?, updated_at = ? WHERE id = ? AND hwid_hash = ?"
  ).bind(currentHash, now(), license.id, legacyHash).run();

  if (result?.meta?.changes) {
    license.hwid_hash = currentHash;
    return true;
  }

  const refreshed = await env.DB.prepare("SELECT hwid_hash FROM licenses WHERE id = ? LIMIT 1")
    .bind(license.id)
    .first();
  if (refreshed?.hwid_hash === currentHash) {
    license.hwid_hash = currentHash;
    return true;
  }
  return false;
}


function buildBootstrapSource(origin, scriptId, ffa = false, ffaReportToken = "", loaderTicket = "", stageChallenge = "") {
  const apiUrl = `${String(origin).replace(/\/$/, "")}/api/v1/${ffa ? "ffa-loader" : "loader"}?script_id=${encodeURIComponent(scriptId)}`;
  const securityReportUrl = `${String(origin).replace(/\/$/, "")}/api/v1/${ffa ? "ffa/security/report" : "security/report"}`;
  const keySetup = ffa
    ? `local key="FFA"`
    : `local key=e.script_key or script_key
if not key or key=="" or tostring(key)=="KEY" then K("You need a script_key to access this script. No key found.") return end`;

  const reportLua = ffa
    ? `local __ea_report_token=${JSON.stringify(ffaReportToken)}
local function __ea_report_clipboard_source()
    pcall(function()
        req({
            Url=${JSON.stringify(securityReportUrl)},
            Method="POST",
            Headers={["content-type"]="application/json"},
            Body=H:JSONEncode({device_id=tostring(d),reason="clipboard_source",token=__ea_report_token})
        })
    end)
end`
    : `local function __ea_report_clipboard_source()
    pcall(function()
        req({
            Url=${JSON.stringify(securityReportUrl)},
            Method="POST",
            Headers={["content-type"]="application/json"},
            Body=H:JSONEncode({key=tostring(key),device_id=tostring(d),reason="clipboard_source"})
        })
    end)
end`;

  const reversedStageChallenge = String(stageChallenge || "").split("").reverse().join("");
  const protectedHeaders = ffa
    ? `local headers={["X-Eternal-Device"]=tostring(d),["X-Eternal-Legacy-Device"]=legacyDevice and tostring(legacyDevice) or "",["X-Eternal-Ticket"]=${JSON.stringify(loaderTicket)},["X-Eternal-Stage-Proof"]=__ea_stage_proof,["X-Eternal-Execute"]="1"}`
    : `local headers={Authorization="Bearer "..tostring(key),["X-Eternal-Device"]=tostring(d),["X-Eternal-Legacy-Device"]=legacyDevice and tostring(legacyDevice) or "",["X-Eternal-Ticket"]=${JSON.stringify(loaderTicket)},["X-Eternal-Stage-Proof"]=__ea_stage_proof,["X-Eternal-Execute"]="1"}`;

  return `-- Voltra Auth protected bootstrap
-- Anti-tamper: snapshot native fns at the very top. If any critical
-- primitive is already hooked at startup, or gets hooked while we run,
-- show the lockdown GUI, freeze the character, report to the server
-- (persistent "tampering" blacklist reason) and never load the source.
local __at_pcall=pcall
local __at_specs={
    {name="loadstring",get=function() return loadstring end,native=true},
    {name="load",get=function() return load end,native=true},
    {name="string.char",get=function() return string.char end,native=true},
    {name="string.gsub",get=function() return string.gsub end,native=true},
    {name="string.sub",get=function() return string.sub end,native=true},
    {name="string.match",get=function() return string.match end,native=true},
    {name="string.byte",get=function() return string.byte end,native=true},
    {name="table.concat",get=function() return table.concat end,native=true},
    {name="bit32.bxor",get=function() return bit32 and bit32.bxor end,native=true},
}
local function __at_is_native(fn)
    if type(fn)~="function" then return nil end
    if debug and type(debug.info)=="function" then
        local ok,src=__at_pcall(debug.info,fn,"s")
        if ok and type(src)=="string" then return src=="[C]" or src=="=[C]" end
    end
    if debug and type(debug.getinfo)=="function" then
        local ok,info=__at_pcall(debug.getinfo,fn,"S")
        if ok and type(info)=="table" then return info.what=="C" end
    end
    if type(iscclosure)=="function" then
        local ok,r=__at_pcall(iscclosure,fn)
        if ok then return r==true end
    end
    return nil
end
local function __at_has_upvalues(fn)
    if debug and type(debug.getupvalue)=="function" then
        local ok,name=__at_pcall(debug.getupvalue,fn,1)
        if ok then return name~=nil end
    end
    if type(getupvalues)=="function" then
        local ok,ups=__at_pcall(getupvalues,fn)
        if ok and type(ups)=="table" then return next(ups)~=nil end
    end
    return nil
end
local __at_originals={}
for _,spec in ipairs(__at_specs) do
    local ok,fn=__at_pcall(spec.get)
    if ok and type(fn)=="function" then
        __at_originals[spec.name]={fn=fn,native=__at_is_native(fn),ups=__at_has_upvalues(fn),spec=spec}
    end
end
local function __at_startup_breach()
    for name,snap in pairs(__at_originals) do
        if snap.spec.native==true then
            if snap.native==false then return name.." not native at startup" end
            if snap.ups==true then return name.." wrapped at startup" end
        end
    end
    return nil
end
local function __at_runtime_breach()
    for name,snap in pairs(__at_originals) do
        local ok,current=__at_pcall(snap.spec.get)
        if ok and current~=snap.fn then return name.." reference changed" end
        if ok and snap.spec.native==true then
            local n=__at_is_native(current)
            if n==false then return name.." became Lua" end
            local u=__at_has_upvalues(current)
            if snap.ups==false and u==true then return name.." gained upvalues" end
        end
    end
    return nil
end
local function __at_report(breach,keyForReport,deviceForReport)
    __at_pcall(function()
        local r=request or http_request or (syn and syn.request) or (http and http.request)
        if type(r)~="function" then return end
        r({
            Url=${JSON.stringify(securityReportUrl)},
            Method="POST",
            Headers={["content-type"]="application/json"},
            Body=game:GetService("HttpService"):JSONEncode(${ffa
              ? `{device_id=tostring(deviceForReport or "unknown"),reason="tampering",detail=tostring(breach or ""),token=__ea_report_token}`
              : `{key=tostring(keyForReport or ""),device_id=tostring(deviceForReport or "unknown"),reason="tampering",detail=tostring(breach or "")}`})
        })
    end)
end
local __at_locked=false
local function __at_lockdown(breach,keyForReport,deviceForReport)
    if __at_locked then return end
    __at_locked=true
    __at_report(breach,keyForReport,deviceForReport)
    __at_pcall(function()
        local Players=game:GetService("Players")
        local plr=Players.LocalPlayer
        local parent
        __at_pcall(function() if type(gethui)=="function" then parent=gethui() end end)
        if not parent and plr then
            __at_pcall(function() parent=plr:FindFirstChildOfClass("PlayerGui") or plr:WaitForChild("PlayerGui",1) end)
        end
        if not parent then parent=game:GetService("CoreGui") end
        local gui=Instance.new("ScreenGui")
        gui.Name="VoltraLockdown_"..tostring(math.random(1,99999999))
        gui.IgnoreGuiInset=true
        gui.ResetOnSpawn=false
        gui.DisplayOrder=2147483647
        gui.ZIndexBehavior=Enum.ZIndexBehavior.Sibling
        local block=Instance.new("Frame")
        block.Size=UDim2.new(1,0,1,0)
        block.BackgroundColor3=Color3.fromRGB(0,0,0)
        block.BorderSizePixel=0
        block.ZIndex=2147483647
        block.Parent=gui
        local label=Instance.new("TextLabel")
        label.AnchorPoint=Vector2.new(0.5,0.5)
        label.Position=UDim2.new(0.5,0,0.5,0)
        label.Size=UDim2.new(0.9,0,0.6,0)
        label.BackgroundTransparency=1
        label.Text="stop tryna crack my source corny skidder get blacklisted dumbass"
        label.TextColor3=Color3.fromRGB(255,40,40)
        label.Font=Enum.Font.GothamBlack
        label.TextScaled=true
        label.TextWrapped=true
        label.ZIndex=2147483647
        label.Parent=block
        gui.Parent=parent
        __at_pcall(function()
            gui.AncestryChanged:Connect(function()
                if not gui.Parent then __at_pcall(function() gui.Parent=parent end) end
            end)
        end)
        __at_pcall(function()
            local sg=game:GetService("StarterGui")
            sg:SetCoreGuiEnabled(Enum.CoreGuiType.All,false)
        end)
        __at_pcall(function()
            local UIS=game:GetService("UserInputService")
            UIS.MouseIconEnabled=false
            UIS.ModalEnabled=true
        end)
        task.spawn(function()
            while true do
                __at_pcall(function()
                    if plr and plr.Character then
                        for _,p in ipairs(plr.Character:GetDescendants()) do
                            if p:IsA("BasePart") then p.Anchored=true end
                        end
                        local h=plr.Character:FindFirstChildOfClass("Humanoid")
                        if h then h.WalkSpeed=0 h.JumpPower=0 h.PlatformStand=true end
                    end
                end)
                task.wait(0.1)
            end
        end)
        task.delay(4,function()
            __at_pcall(function() if plr then plr:Kick("Blacklisted. Tampering detected.") end end)
        end)
    end)
    while true do task.wait(60) end
end
-- (startup-breach check deferred below until after key+HWID collection so
-- the server-side security report can actually blacklist the device.)

local H=game:GetService("HttpService")
local P=game:GetService("Players")
local lp=P.LocalPlayer
local function K(m)
    if lp then pcall(function() lp:Kick(tostring(m or "Authentication failed.")) end) end
end

local e=(getgenv and getgenv()) or _G
${keySetup}

local legacyDevice
pcall(function()
    if type(gethwid)=="function" then
        local value=gethwid()
        if value and tostring(value)~="" then legacyDevice=tostring(value) end
    end
end)

local d
if readfile and writefile then
    local file="eternal_auth_device.txt"
    local ok,value=pcall(readfile,file)
    if ok and value and tostring(value)~="" then
        d=tostring(value)
    else
        d=H:GenerateGUID(false)
        pcall(writefile,file,d)
    end
end
if not d or tostring(d)=="" then d=legacyDevice end
if not d or tostring(d)=="" then K("Missing HWID") return end

local req=request or http_request or (syn and syn.request) or (http and http.request)
if type(req)~="function" then K("Voltra Auth requires an HTTP request function.") return end

-- Snapshot HTTP primitives for http_spy detection. If any of these get
-- hooked after startup, we blacklist with reason "http_spy".
local __at_http_originals={}
local function __at_snap_http(name,getter)
    local ok,fn=__at_pcall(getter)
    if ok and type(fn)=="function" then
        __at_http_originals[name]={fn=fn,ups=__at_has_upvalues(fn),getter=getter}
    end
end
__at_snap_http("request",function() return request end)
__at_snap_http("http_request",function() return http_request end)
__at_snap_http("syn.request",function() return syn and syn.request end)
__at_snap_http("http.request",function() return http and http.request end)
__at_snap_http("game.HttpGet",function() return game.HttpGet end)
__at_snap_http("game.HttpGetAsync",function() return game.HttpGetAsync end)
__at_snap_http("HttpService.RequestAsync",function() return H.RequestAsync end)
local function __at_http_breach()
    for name,snap in pairs(__at_http_originals) do
        local ok,current=__at_pcall(snap.getter)
        if ok and current~=snap.fn then return name.." reference changed" end
        if ok then
            local u=__at_has_upvalues(current)
            if snap.ups==false and u==true then return name.." gained upvalues" end
        end
    end
    return nil
end

-- Deferred startup check: now that we have key + HWID, if any native
-- primitive was already hooked at startup OR any HTTP primitive is
-- wrapped (not just at a later moment), fire the lockdown WITH the
-- credentials so the server blacklists the HWID persistently.
do
    local breach=__at_startup_breach()
    if breach then __at_lockdown(breach,key,d) return end
    local httpBreach=__at_http_breach()
    if httpBreach then
        __at_pcall(function()
            req({
                Url=${JSON.stringify(securityReportUrl)},
                Method="POST",
                Headers={["content-type"]="application/json"},
                Body=H:JSONEncode(${ffa
                  ? `{device_id=tostring(d),reason="http_spy",detail=tostring(httpBreach),token=__ea_report_token}`
                  : `{key=tostring(key),device_id=tostring(d),reason="http_spy",detail=tostring(httpBreach)}`})
            })
        end)
        __at_lockdown(httpBreach,key,d)
        return
    end
end

local u=${JSON.stringify(apiUrl)}
local __ea_stage_reverse=${JSON.stringify(reversedStageChallenge)}
local __ea_stage_proof=string.reverse(__ea_stage_reverse)
${protectedHeaders}
${reportLua}

-- Source-aware clipboard protection. Normal clipboard writes are untouched.
-- Only copying the actual protected source (or a substantial chunk of it)
-- creates a permanent HWID blacklist and replaces the clipboard contents.
local __ea_source=nil
local __ea_pending_clipboard={}
local __ea_clipboard_blacklisted=false

local function __ea_is_source_copy(value)
    if not __ea_source then return false end
    local candidate=tostring(value or "")
    local source=tostring(__ea_source or "")
    if candidate=="" or source=="" then return false end
    if candidate==source then return true end
    if #candidate>=128 and string.find(source,candidate,1,true) then return true end
    if #source>=128 and string.find(candidate,source,1,true) then return true end
    return false
end

local function __ea_blacklist_clipboard(original)
    if __ea_clipboard_blacklisted then return end
    __ea_clipboard_blacklisted=true
    __ea_report_clipboard_source()
    pcall(function() original("Blacklisted") end)
    K("Blacklisted")
end

local __ea_clipboard_seen={}
local __ea_clipboard_wrappers={}

local function __ea_make_clipboard_wrapper(original)
    local passthrough=original
    local wrapped
    wrapped=function(value,...)
        local text=tostring(value or "")
        if __ea_source then
            if __ea_is_source_copy(text) then
                __ea_blacklist_clipboard(passthrough)
                return nil
            end
        elseif #__ea_pending_clipboard<24 then
            table.insert(__ea_pending_clipboard,{fn=passthrough,value=text})
        end
        return passthrough(value,...)
    end
    return wrapped,function(fn) passthrough=fn end
end

local function __ea_wrap_clipboard(env,name)
    local ok,original=pcall(function() return rawget(env,name) end)
    if not ok or type(original)~="function" then return end

    local existing=__ea_clipboard_wrappers[original]
    if existing then
        pcall(function() env[name]=existing end)
        return
    end

    local wrapped,setPassthrough=__ea_make_clipboard_wrapper(original)
    local installed=false

    if type(hookfunction)=="function" and not __ea_clipboard_seen[original] then
        __ea_clipboard_seen[original]=true
        local hookOk,old=pcall(hookfunction,original,wrapped)
        if hookOk and type(old)=="function" then
            setPassthrough(old)
            installed=true
        end
    end

    __ea_clipboard_wrappers[original]=wrapped
    __ea_clipboard_wrappers[wrapped]=wrapped
    pcall(function() env[name]=wrapped end)
    return installed
end

local __ea_clipboard_envs={}
local __ea_clipboard_env_seen={}
local function __ea_add_clipboard_env(env)
    if type(env)=="table" and not __ea_clipboard_env_seen[env] then
        __ea_clipboard_env_seen[env]=true
        table.insert(__ea_clipboard_envs,env)
    end
end

__ea_add_clipboard_env(_G)
__ea_add_clipboard_env(e)
pcall(function() if type(getgenv)=="function" then __ea_add_clipboard_env(getgenv()) end end)
pcall(function() if type(getrenv)=="function" then __ea_add_clipboard_env(getrenv()) end end)
pcall(function() if type(getfenv)=="function" then __ea_add_clipboard_env(getfenv(0)) end end)

local __ea_clipboard_names={
    "setclipboard","toclipboard","writeclipboard",
    "set_clipboard","write_clipboard","setrbxclipboard",
    "copyclipboard","clipboardset","setclip"
}
local __ea_clipboard_child_names={
    "set","write","copy","setclipboard","toclipboard","writeclipboard",
    "set_clipboard","write_clipboard","setclip"
}

for _,env in ipairs(__ea_clipboard_envs) do
    for _,name in ipairs(__ea_clipboard_names) do
        __ea_wrap_clipboard(env,name)
    end
    for _,tableName in ipairs({"clipboard","Clipboard","syn"}) do
        local ok,t=pcall(function() return rawget(env,tableName) end)
        if ok and type(t)=="table" then
            for _,name in ipairs(__ea_clipboard_child_names) do
                __ea_wrap_clipboard(t,name)
            end
        end
    end
end

local ok,result=pcall(req,{Url=u,Method="POST",Headers=headers})
if not ok or not result then K("Voltra Auth connection failed.") return end

local status=tonumber(result.StatusCode or result.status_code or result.Status or 0)
local body=result.Body or result.body or ""
if status~=200 then
    if string.find(tostring(body),"Blacklisted",1,true) then
        K("Blacklisted")
    else
        local reason=tostring(body or "")
        if reason=="" then reason="Access denied" end
        K("Voltra Auth: "..reason)
    end
    return
end

__ea_source=tostring(body or "")
for _,pending in ipairs(__ea_pending_clipboard) do
    if __ea_is_source_copy(pending.value) then
        __ea_blacklist_clipboard(pending.fn)
        return
    end
end
__ea_pending_clipboard={}

-- loadstring-hook defense.
-- A hostile executor can replace loadstring() with a Lua wrapper that
-- captures the source string before compiling. We refuse to feed source
-- into anything but a verified native C closure.
local __ea_native_ls=nil
local __ea_ls_candidates={}
local function __ea_push_ls(fn)
    if type(fn)=="function" then table.insert(__ea_ls_candidates,fn) end
end
pcall(function() __ea_push_ls(rawget(_G,"loadstring")) end)
pcall(function() if type(getrenv)=="function" then __ea_push_ls(rawget(getrenv(),"loadstring")) end end)
pcall(function() if type(getgenv)=="function" then __ea_push_ls(rawget(getgenv(),"loadstring")) end end)
pcall(function() __ea_push_ls(rawget(_G,"load")) end)
pcall(function() if type(getrenv)=="function" then __ea_push_ls(rawget(getrenv(),"load")) end end)

local function __ea_is_native(fn)
    local native=true
    pcall(function()
        if type(iscclosure)=="function" then native=iscclosure(fn)
        elseif type(islclosure)=="function" then native=not islclosure(fn)
        end
    end)
    return native
end

local function __ea_has_hook_upvalues(fn)
    local hooked=false
    pcall(function()
        if type(getupvalues)=="function" then
            local ups=getupvalues(fn)
            if type(ups)=="table" and #ups>0 then hooked=true end
        end
    end)
    return hooked
end

-- Canary: pick the first candidate that actually compiles. This beats
-- the previous native-only pick which rejected executors whose working
-- loadstring is a Lua wrapper (and fell through to Roblox's native
-- loadstring, which throws "RobloxScript context"). Hooked-but-working
-- implementations still get caught by the __at_ anti-tamper watchdog
-- and the per-license watermark.
for _,fn in ipairs(__ea_ls_candidates) do
    local okCompile,compiled=pcall(fn,"return 42")
    if okCompile and type(compiled)=="function" then
        local okRun,val=pcall(compiled)
        if okRun and val==42 then
            __ea_native_ls=fn
            break
        end
    end
end

local function __ea_report_hook()
    pcall(function()
        req({
            Url=${JSON.stringify(securityReportUrl)},
            Method="POST",
            Headers={["content-type"]="application/json"},
            Body=H:JSONEncode(${ffa
              ? `{device_id=tostring(d),reason="loadstring_hook",token=__ea_report_token}`
              : `{key=tostring(key),device_id=tostring(d),reason="loadstring_hook"}`})
        })
    end)
end

if not __ea_native_ls then
    __ea_report_hook()
    body=nil
    pcall(function() result.Body="" result.body="" end)
    K("Script loader has been tampered with.")
    return
end

-- Hide the body behind a coroutine so a hooked error() can't exfiltrate the
-- bytecode via the thrown message. Compile in a scope that drops body as
-- its first act after fn capture.
local __ea_body=body
body=nil
pcall(function() result.Body="" result.body="" end)

-- Final anti-tamper gate: one more check right before we feed source
-- to the compiler. If anything was swapped since startup, lock down.
do
    local breach=__at_runtime_breach()
    if breach then
        __ea_body=nil
        pcall(function() result.Body="" result.body="" end)
        __at_lockdown(breach,key,d)
        return
    end
end

-- Compile defensively. Roblox throws "loadstring() is not available in
-- RobloxScript context." when the loader is run from a vanilla LocalScript
-- instead of an executor; we catch that here and kick with a readable
-- message rather than letting Roblox dump a raw stack trace.
local __ea_compile_ok,fn,compileErr=pcall(__ea_native_ls,__ea_body)
__ea_body=nil

if not __ea_compile_ok then
    local msg=tostring(fn or "")
    if string.find(msg,"RobloxScript",1,true) then
        K("Voltra Auth: this loader must be run from an executor (loadstring is disabled here).")
    else
        K("Voltra Auth loader compile error: "..msg:sub(1,180))
    end
    return
end

if type(fn)~="function" then
    K("Voltra Auth loader compile error: "..tostring(compileErr or "no function returned"):sub(1,180))
    return
end

-- Watchdog: re-check every 0.5s after we hand off. If someone hooks a
-- primitive mid-execution to dump decoded strings, we lock down.
task.spawn(function()
    while true do
        task.wait(0.5)
        local breach=__at_runtime_breach()
        if breach then __at_lockdown(breach,key,d) end
    end
end)

-- Run the compiled payload. pcall so a runtime error in the user's own
-- script doesn't leak a stack trace that references internal names.
local __ea_run_ok,__ea_run_err=pcall(fn)
if not __ea_run_ok then
    K("Voltra Auth: runtime error — "..tostring(__ea_run_err or ""):sub(1,180))
end`;
}

async function tryD1(label, operation) {
  try {
    return await operation();
  } catch (error) {
    console.error(`Voltra Auth D1 migration warning [${label}]`, error);
    return null;
  }
}

async function ensureAdminAuthSchema(env) {
  await env.DB.batch([
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS admin_credentials (
      id TEXT PRIMARY KEY,
      password_salt TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      iterations INTEGER NOT NULL DEFAULT 100000,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL
    )`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS admin_sessions (
      id TEXT PRIMARY KEY,
      token_hash TEXT NOT NULL UNIQUE,
      csrf_token TEXT,
      created_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      last_seen_at INTEGER NOT NULL
    )`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS admin_state (
      id TEXT PRIMARY KEY,
      last_guild_id TEXT,
      active_tab TEXT NOT NULL DEFAULT 'gateway',
      preferences_json TEXT NOT NULL DEFAULT '{}',
      updated_at INTEGER NOT NULL
    )`),
  ]);

  await tryD1("admin_sessions index", () =>
    env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_admin_sessions_expires ON admin_sessions(expires_at)").run()
  );
  await tryD1("admin_sessions csrf column", () =>
    env.DB.prepare("ALTER TABLE admin_sessions ADD COLUMN csrf_token TEXT").run()
  );

  await env.DB.prepare(
    `INSERT OR IGNORE INTO admin_state (id, active_tab, preferences_json, updated_at)
     VALUES ('primary', 'gateway', '{}', ?)`
  ).bind(now()).run();
}

let backendSchemaReadyPromise = null;

async function ensureBackendPersistenceSchema(env) {
  if (backendSchemaReadyPromise) return backendSchemaReadyPromise;

  backendSchemaReadyPromise = (async () => {
    await ensureAdminAuthSchema(env);

    // Create every current backend table if it is missing. CREATE TABLE IF NOT
    // EXISTS is safe on existing databases; legacy columns are repaired below.
    const creates = [
      `CREATE TABLE IF NOT EXISTS guilds (
        guild_id TEXT PRIMARY KEY,
        active INTEGER NOT NULL DEFAULT 1,
        manager_role_id TEXT,
        buyer_role_id TEXT,
        log_webhook_enc TEXT,
        base_url TEXT,
        loader_template TEXT,
        created_at INTEGER NOT NULL DEFAULT 0,
        updated_at INTEGER NOT NULL DEFAULT 0
      )`,
      `CREATE TABLE IF NOT EXISTS server_setup_keys (
        id TEXT PRIMARY KEY,
        key_hash TEXT NOT NULL UNIQUE,
        key_hint TEXT NOT NULL,
        key_enc TEXT,
        intended_guild_id TEXT,
        note TEXT,
        expires_at INTEGER NOT NULL DEFAULT -1,
        created_at INTEGER NOT NULL DEFAULT 0,
        used_at INTEGER,
        used_by_guild_id TEXT,
        used_by_discord_id TEXT
      )`,
      `CREATE TABLE IF NOT EXISTS licenses (
        id TEXT PRIMARY KEY,
        guild_id TEXT NOT NULL,
        key_hash TEXT NOT NULL UNIQUE,
        discord_id TEXT,
        panel_id TEXT,
        status TEXT NOT NULL DEFAULT 'active',
        auth_expire INTEGER NOT NULL DEFAULT -1,
        note TEXT,
        hwid_hash TEXT,
        last_hwid_reset INTEGER,
        created_at INTEGER NOT NULL DEFAULT 0,
        updated_at INTEGER NOT NULL DEFAULT 0
      )`,
      `CREATE TABLE IF NOT EXISTS blacklists (
        guild_id TEXT NOT NULL,
        discord_id TEXT NOT NULL,
        reason TEXT,
        expires_at INTEGER NOT NULL DEFAULT -1,
        created_at INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (guild_id, discord_id)
      )`,
      `CREATE TABLE IF NOT EXISTS redeem_codes (
        id TEXT PRIMARY KEY,
        guild_id TEXT NOT NULL,
        code_hash TEXT NOT NULL UNIQUE,
        days INTEGER NOT NULL DEFAULT -1,
        uses_left INTEGER NOT NULL DEFAULT 1,
        note TEXT,
        expires_at INTEGER NOT NULL DEFAULT -1,
        created_at INTEGER NOT NULL DEFAULT 0
      )`,
      `CREATE TABLE IF NOT EXISTS scripts (
        id TEXT PRIMARY KEY,
        guild_id TEXT NOT NULL,
        loader_id TEXT UNIQUE,
        name TEXT NOT NULL DEFAULT 'Voltra Auth Script',
        version TEXT NOT NULL DEFAULT '1.0.0',
        enabled INTEGER NOT NULL DEFAULT 1,
        ffa_enabled INTEGER NOT NULL DEFAULT 0,
        content TEXT NOT NULL DEFAULT '',
        created_at INTEGER NOT NULL DEFAULT 0,
        updated_at INTEGER NOT NULL DEFAULT 0
      )`,
      `CREATE TABLE IF NOT EXISTS executions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        guild_id TEXT NOT NULL,
        license_id TEXT NOT NULL,
        occurred_at INTEGER NOT NULL DEFAULT 0
      )`,
      `CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        guild_id TEXT,
        action TEXT NOT NULL DEFAULT '',
        actor_id TEXT,
        target TEXT,
        details TEXT,
        created_at INTEGER NOT NULL DEFAULT 0
      )`,
      `CREATE TABLE IF NOT EXISTS hwid_blacklists (
        guild_id TEXT NOT NULL,
        hwid_hash TEXT NOT NULL,
        reason TEXT NOT NULL DEFAULT 'manual',
        license_id TEXT NOT NULL DEFAULT '',
        created_at INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (guild_id, hwid_hash)
      )`,
      `CREATE TABLE IF NOT EXISTS runtime_state (
        key TEXT PRIMARY KEY,
        value_json TEXT NOT NULL,
        updated_at INTEGER NOT NULL DEFAULT 0
      )`,
      `CREATE TABLE IF NOT EXISTS panels (
        id TEXT PRIMARY KEY,
        guild_id TEXT NOT NULL,
        name TEXT NOT NULL DEFAULT 'Voltra Auth Panel',
        channel_id TEXT,
        manager_role_id TEXT,
        buyer_role_id TEXT,
        loader_template TEXT,
        active INTEGER NOT NULL DEFAULT 1,
        created_by TEXT,
        created_at INTEGER NOT NULL DEFAULT 0,
        updated_at INTEGER NOT NULL DEFAULT 0,
        embed_title TEXT,
        embed_description TEXT,
        embed_color INTEGER,
        script_id TEXT
      )`,
      `CREATE TABLE IF NOT EXISTS panel_drafts (
        id TEXT PRIMARY KEY,
        guild_id TEXT NOT NULL,
        channel_id TEXT,
        manager_role_id TEXT,
        buyer_role_id TEXT,
        loader_template TEXT NOT NULL DEFAULT '',
        uploaded_loader_url TEXT,
        selected_script_id TEXT,
        created_by TEXT NOT NULL DEFAULT '',
        created_at INTEGER NOT NULL DEFAULT 0,
        expires_at INTEGER NOT NULL DEFAULT 0
      )`,
    ];

    for (const sql of creates) {
      await env.DB.prepare(sql).run();
    }

    async function ensureColumns(table, definitions) {
      const info = await env.DB.prepare(`PRAGMA table_info(${table})`).all();
      const names = new Set((info?.results || []).map((row) => String(row.name)));
      for (const [name, definition] of Object.entries(definitions)) {
        if (names.has(name)) continue;
        await env.DB.prepare(`ALTER TABLE ${table} ADD COLUMN ${name} ${definition}`).run();
        names.add(name);
      }
    }

    await ensureColumns("guilds", {
      active: "INTEGER NOT NULL DEFAULT 1",
      manager_role_id: "TEXT",
      buyer_role_id: "TEXT",
      log_webhook_enc: "TEXT",
      base_url: "TEXT",
      loader_template: "TEXT",
      created_at: "INTEGER NOT NULL DEFAULT 0",
      updated_at: "INTEGER NOT NULL DEFAULT 0",
    });

    await ensureColumns("server_setup_keys", {
      key_hint: "TEXT NOT NULL DEFAULT ''",
      key_enc: "TEXT",
      intended_guild_id: "TEXT",
      note: "TEXT",
      expires_at: "INTEGER NOT NULL DEFAULT -1",
      created_at: "INTEGER NOT NULL DEFAULT 0",
      used_at: "INTEGER",
      used_by_guild_id: "TEXT",
      used_by_discord_id: "TEXT",
    });

    await ensureColumns("licenses", {
      discord_id: "TEXT",
      panel_id: "TEXT",
      status: "TEXT NOT NULL DEFAULT 'active'",
      auth_expire: "INTEGER NOT NULL DEFAULT -1",
      note: "TEXT",
      hwid_hash: "TEXT",
      last_hwid_reset: "INTEGER",
      created_at: "INTEGER NOT NULL DEFAULT 0",
      updated_at: "INTEGER NOT NULL DEFAULT 0",
    });

    await ensureColumns("blacklists", {
      reason: "TEXT",
      expires_at: "INTEGER NOT NULL DEFAULT -1",
      created_at: "INTEGER NOT NULL DEFAULT 0",
    });

    await ensureColumns("redeem_codes", {
      days: "INTEGER NOT NULL DEFAULT -1",
      uses_left: "INTEGER NOT NULL DEFAULT 1",
      note: "TEXT",
      expires_at: "INTEGER NOT NULL DEFAULT -1",
      created_at: "INTEGER NOT NULL DEFAULT 0",
    });

    await ensureColumns("scripts", {
      loader_id: "TEXT",
      name: "TEXT NOT NULL DEFAULT 'Voltra Auth Script'",
      version: "TEXT NOT NULL DEFAULT '1.0.0'",
      enabled: "INTEGER NOT NULL DEFAULT 1",
      ffa_enabled: "INTEGER NOT NULL DEFAULT 0",
      content: "TEXT NOT NULL DEFAULT ''",
      created_at: "INTEGER NOT NULL DEFAULT 0",
      updated_at: "INTEGER NOT NULL DEFAULT 0",
    });

    await ensureColumns("executions", {
      occurred_at: "INTEGER NOT NULL DEFAULT 0",
    });

    await ensureColumns("audit_logs", {
      guild_id: "TEXT",
      action: "TEXT NOT NULL DEFAULT ''",
      actor_id: "TEXT",
      target: "TEXT",
      details: "TEXT",
      created_at: "INTEGER NOT NULL DEFAULT 0",
    });

    await ensureColumns("hwid_blacklists", {
      reason: "TEXT NOT NULL DEFAULT 'manual'",
      license_id: "TEXT NOT NULL DEFAULT ''",
      created_at: "INTEGER NOT NULL DEFAULT 0",
    });

    await ensureColumns("panels", {
      name: "TEXT NOT NULL DEFAULT 'Voltra Auth Panel'",
      channel_id: "TEXT",
      manager_role_id: "TEXT",
      buyer_role_id: "TEXT",
      loader_template: "TEXT",
      active: "INTEGER NOT NULL DEFAULT 1",
      created_by: "TEXT",
      created_at: "INTEGER NOT NULL DEFAULT 0",
      updated_at: "INTEGER NOT NULL DEFAULT 0",
      embed_title: "TEXT",
      embed_description: "TEXT",
      embed_color: "INTEGER",
      script_id: "TEXT",
    });

    await ensureColumns("panel_drafts", {
      channel_id: "TEXT",
      manager_role_id: "TEXT",
      buyer_role_id: "TEXT",
      loader_template: "TEXT NOT NULL DEFAULT ''",
      uploaded_loader_url: "TEXT",
      selected_script_id: "TEXT",
      created_by: "TEXT NOT NULL DEFAULT ''",
      created_at: "INTEGER NOT NULL DEFAULT 0",
      expires_at: "INTEGER NOT NULL DEFAULT 0",
    });

    const indexes = [
      "CREATE INDEX IF NOT EXISTS idx_server_setup_keys_created ON server_setup_keys(created_at DESC)",
      "CREATE INDEX IF NOT EXISTS idx_licenses_guild_discord ON licenses(guild_id, discord_id)",
      "CREATE INDEX IF NOT EXISTS idx_licenses_guild_status ON licenses(guild_id, status)",
      "CREATE INDEX IF NOT EXISTS idx_licenses_guild_panel ON licenses(guild_id, panel_id, status)",
      "CREATE INDEX IF NOT EXISTS idx_redeem_codes_guild ON redeem_codes(guild_id)",
      "CREATE INDEX IF NOT EXISTS idx_scripts_guild ON scripts(guild_id, created_at)",
      "CREATE UNIQUE INDEX IF NOT EXISTS idx_scripts_loader_id ON scripts(loader_id)",
      "CREATE INDEX IF NOT EXISTS idx_executions_license_time ON executions(license_id, occurred_at DESC)",
      "CREATE INDEX IF NOT EXISTS idx_audit_logs_time ON audit_logs(created_at DESC)",
      "CREATE INDEX IF NOT EXISTS idx_panels_guild_active ON panels(guild_id, active, created_at DESC)",
      "CREATE INDEX IF NOT EXISTS idx_panel_drafts_expires ON panel_drafts(expires_at)",
    ];
    for (const sql of indexes) {
      await tryD1("index repair", () => env.DB.prepare(sql).run());
    }

    await env.DB.prepare(
      `INSERT OR IGNORE INTO admin_state (id, active_tab, preferences_json, updated_at)
       VALUES ('primary', 'gateway', '{}', ?)`
    ).bind(now()).run();

    return true;
  })().catch((error) => {
    backendSchemaReadyPromise = null;
    throw error;
  });

  return backendSchemaReadyPromise;
}

const ADMIN_PASSWORD_ITERATIONS = 100000;

async function deriveAdminPasswordHash(password, saltBytes, iterations = ADMIN_PASSWORD_ITERATIONS) {
  // Cloudflare Workers currently rejects PBKDF2 iteration counts above 100,000.
  const safeIterations = Math.max(1, Math.min(100000, Number(iterations) || ADMIN_PASSWORD_ITERATIONS));
  const material = await crypto.subtle.importKey(
    "raw",
    enc.encode(String(password)),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: saltBytes, iterations: safeIterations },
    material,
    256
  );
  return new Uint8Array(bits);
}

async function getAdminCredential(env) {
  return env.DB.prepare("SELECT * FROM admin_credentials WHERE id = 'primary' LIMIT 1").first();
}

async function bootstrapAdminCredential(env) {
  let row = await getAdminCredential(env);
  if (row) return row;
  if (!env.ADMIN_PASSWORD) return null;

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await deriveAdminPasswordHash(env.ADMIN_PASSWORD, salt, ADMIN_PASSWORD_ITERATIONS);
  const timestamp = now();
  await env.DB.prepare(
    `INSERT OR IGNORE INTO admin_credentials
      (id, password_salt, password_hash, iterations, created_at, updated_at)
     VALUES ('primary', ?, ?, ?, ?, ?)`
  ).bind(
    bytesToBase64Url(salt),
    bytesToBase64Url(hash),
    ADMIN_PASSWORD_ITERATIONS,
    timestamp,
    timestamp
  ).run();
  return getAdminCredential(env);
}

async function verifyAdminPassword(env, password) {
  const row = await bootstrapAdminCredential(env);
  if (!row) return false;
  const actual = await deriveAdminPasswordHash(
    password,
    base64UrlToBytes(row.password_salt),
    Number(row.iterations || ADMIN_PASSWORD_ITERATIONS)
  );
  const expected = base64UrlToBytes(row.password_hash);
  if (actual.length !== expected.length) return false;
  if (typeof crypto.subtle.timingSafeEqual === "function") {
    return crypto.subtle.timingSafeEqual(actual, expected);
  }
  let diff = 0;
  for (let i = 0; i < actual.length; i++) diff |= actual[i] ^ expected[i];
  return diff === 0;
}

// Session cookie obfuscation.
//
// The browser only ever sees opaque-looking cookies with random names and
// random-looking values. The *real* session identifier is one of them, but
// the server picks it by name — the others are decoys with freshly generated
// random values on every login. Nothing sensitive about the admin lives in
// the cookie: it is a lookup token whose SHA-256 is stored in admin_sessions
// and compared timing-safely. The source of truth for "is this session valid,
// what CSRF token does it have, when does it expire" is D1, not the cookie.
//
// Why no __Host- prefix anymore: the user wants the cookie to look like any
// other arbitrary cookie, not something that announces "admin session". We
// still manually set Secure + HttpOnly + SameSite=Strict + Path=/, so the
// only property we lose is the browser's enforcement that no other code can
// set a cookie with the same name without those flags — a tiny concern on a
// Workers subdomain where no sibling scripts share the origin.
const SESSION_COOKIE_NAME = "_vq7a3k2m";
const SESSION_COOKIE_REGEX = /(?:^|;\s*)_vq7a3k2m=([^;]+)/;
const DECOY_COOKIE_NAMES = ["_nb4p9x1", "_mt6c2w8", "_zh5r0d7", "_fj1k8e3"];
const SESSION_TTL_SECONDS = 12 * 3600;
const SESSION_IDLE_SECONDS = 2 * 3600;
const SESSION_COOKIE_FLAGS = "HttpOnly; Secure; SameSite=Strict; Path=/";

// Pull the admin session token from either the Authorization: Bearer header
// (sent by the dashboard JS from localStorage) or the obfuscated cookie
// (useful for the first-navigation server-side gate). Either works.
function adminSessionCookieToken(request) {
  const auth = request.headers.get("authorization") || "";
  const bearer = auth.match(/^\s*Bearer\s+([A-Za-z0-9._\-]+)\s*$/i);
  if (bearer) return bearer[1];
  const cookie = request.headers.get("cookie") || "";
  const match = cookie.match(SESSION_COOKIE_REGEX);
  return match ? match[1] : null;
}

// Build Set-Cookie headers: one real cookie plus a cluster of decoys that
// look identical in format. Pass sessionToken = "" to clear everything.
function sessionCookieHeaders(sessionToken) {
  const clearing = !sessionToken;
  const realValue = clearing ? "" : sessionToken;
  const maxAge = clearing ? 0 : SESSION_TTL_SECONDS;
  const headers = [[`${SESSION_COOKIE_NAME}=${realValue}; ${SESSION_COOKIE_FLAGS}; Max-Age=${maxAge}`]];
  for (const name of DECOY_COOKIE_NAMES) {
    const decoyValue = clearing ? "" : bytesToBase64Url(crypto.getRandomValues(new Uint8Array(32)));
    headers.push([`${name}=${decoyValue}; ${SESSION_COOKIE_FLAGS}; Max-Age=${maxAge}`]);
  }
  return headers.map((pair) => pair[0]);
}

async function createAdminSession(env) {
  const rawToken = bytesToBase64Url(crypto.getRandomValues(new Uint8Array(32)));
  const csrfToken = bytesToBase64Url(crypto.getRandomValues(new Uint8Array(32)));
  const tokenHash = await sha256Hex(rawToken);
  const timestamp = now();
  const expiresAt = timestamp + SESSION_TTL_SECONDS;
  await env.DB.prepare("DELETE FROM admin_sessions WHERE expires_at <= ?").bind(timestamp).run();
  await env.DB.prepare(
    `INSERT INTO admin_sessions (id, token_hash, csrf_token, created_at, expires_at, last_seen_at)
     VALUES (?, ?, ?, ?, ?, ?)`
  ).bind(crypto.randomUUID(), tokenHash, csrfToken, timestamp, expiresAt, timestamp).run();
  return { token: rawToken, csrf: csrfToken, expires_at: expiresAt };
}

async function verifyAdminSession(request, env) {
  const rawToken = adminSessionCookieToken(request);
  if (!rawToken) return false;
  const tokenHash = await sha256Hex(rawToken);
  const row = await env.DB.prepare(
    "SELECT * FROM admin_sessions WHERE token_hash = ? LIMIT 1"
  ).bind(tokenHash).first();
  if (!row) return false;
  const timestamp = now();
  if (Number(row.expires_at) <= timestamp) {
    await env.DB.prepare("DELETE FROM admin_sessions WHERE id = ?").bind(row.id).run();
    return false;
  }
  // Idle timeout: if the session has not been touched for SESSION_IDLE_SECONDS,
  // treat it as expired and revoke it. Hardens against stolen cookies left idle.
  const lastSeen = Number(row.last_seen_at || 0);
  if (lastSeen > 0 && timestamp - lastSeen >= SESSION_IDLE_SECONDS) {
    await env.DB.prepare("DELETE FROM admin_sessions WHERE id = ?").bind(row.id).run();
    return false;
  }
  if (timestamp - lastSeen >= 300) {
    await env.DB.prepare("UPDATE admin_sessions SET last_seen_at = ? WHERE id = ?")
      .bind(timestamp, row.id)
      .run();
  }
  return row;
}

async function handleAdminLogin(request, env) {
  const body = await readJson(request);
  const password = body?.password ?? "";
  if (!(await verifyAdminPassword(env, password))) {
    return json({ ok: false, error: "Invalid password" }, 401);
  }
  const session = await createAdminSession(env);
  // token is returned in the body so the browser stashes it in localStorage;
  // the cookie cluster is a convenience for the server-side navigation gate.
  return jsonWithCookies(
    { ok: true, backend_persisted: true, csrf: session.csrf, token: session.token, expires_at: session.expires_at },
    200,
    sessionCookieHeaders(session.token),
  );
}

async function handleAdminLogout(request, env) {
  const rawToken = adminSessionCookieToken(request);
  if (rawToken) {
    const tokenHash = await sha256Hex(rawToken);
    await env.DB.prepare("DELETE FROM admin_sessions WHERE token_hash = ?").bind(tokenHash).run();
  }
  return jsonWithCookies({ ok: true }, 200, sessionCookieHeaders(""));
}

// json() can only carry one set-cookie header via its extraHeaders map.
// Login and logout need to set several (one real + N decoys) in one response,
// so this helper constructs the Response manually and appends each cookie.
function jsonWithCookies(body, status, cookieHeaders) {
  const headers = new Headers({ ...JSON_HEADERS });
  for (const cookie of cookieHeaders || []) headers.append("set-cookie", cookie);
  return withSecurityHeaders(new Response(JSON.stringify(body), { status, headers }));
}

async function handleAdminCsrf(request, session) {
  if (!session?.csrf_token) {
    return json({ ok: false, error: "No CSRF token on this session" }, 500);
  }
  // Re-establish the cookie cluster on every csrf fetch. If the client just
  // authenticated via Authorization: Bearer (e.g. because cookies were
  // cleared), this re-stamps the cookies so the next page navigation hits
  // the server-side gate correctly. Also acts as a sliding renewal.
  const token = adminSessionCookieToken(request);
  if (token) {
    return jsonWithCookies({ ok: true, csrf: session.csrf_token }, 200, sessionCookieHeaders(token));
  }
  return json({ ok: true, csrf: session.csrf_token });
}

// Constant-time string compare for CSRF tokens.
async function csrfTokensMatch(a, b) {
  if (!a || !b) return false;
  const enc2 = new TextEncoder();
  const aHash = new Uint8Array(await crypto.subtle.digest("SHA-256", enc2.encode(String(a))));
  const bHash = new Uint8Array(await crypto.subtle.digest("SHA-256", enc2.encode(String(b))));
  if (typeof crypto.subtle.timingSafeEqual === "function") {
    return crypto.subtle.timingSafeEqual(aHash, bHash);
  }
  let diff = 0;
  for (let i = 0; i < aHash.length; i++) diff |= aHash[i] ^ bHash[i];
  return diff === 0;
}

async function requireCsrf(request, session) {
  if (!session?.csrf_token) {
    return json({ ok: false, error: "Session is missing CSRF token; sign in again." }, 403);
  }
  const header = request.headers.get("x-voltra-csrf") || "";
  const ok = await csrfTokensMatch(session.csrf_token, header);
  if (!ok) {
    return json({ ok: false, error: "CSRF token mismatch" }, 403);
  }
  return null;
}

async function getAdminState(env) {
  let row = await env.DB.prepare("SELECT * FROM admin_state WHERE id = 'primary' LIMIT 1").first();
  if (!row) {
    await env.DB.prepare(
      "INSERT INTO admin_state (id, last_guild_id, active_tab, preferences_json, updated_at) VALUES ('primary', NULL, 'gateway', '{}', ?)"
    ).bind(now()).run();
    row = await env.DB.prepare("SELECT * FROM admin_state WHERE id = 'primary' LIMIT 1").first();
  }
  let preferences = {};
  try { preferences = JSON.parse(row?.preferences_json || "{}"); } catch {}
  return {
    last_guild_id: row?.last_guild_id || null,
    active_tab: row?.active_tab || "gateway",
    preferences,
    updated_at: row?.updated_at || null,
  };
}

async function saveAdminState(env, body) {
  const current = await getAdminState(env);
  const lastGuildId = body?.last_guild_id === undefined
    ? current.last_guild_id
    : cleanText(body.last_guild_id, 64) || null;
  const allowedTabs = new Set(["gateway", "serverkeys", "licenses", "stock", "blacklists", "panels", "script", "logs", "backend"]);
  const requestedTab = cleanText(body?.active_tab, 32);
  const activeTab = requestedTab && allowedTabs.has(requestedTab) ? requestedTab : current.active_tab;
  const preferences = body?.preferences && typeof body.preferences === "object" && !Array.isArray(body.preferences)
    ? body.preferences
    : current.preferences;
  const preferencesJson = JSON.stringify(preferences).slice(0, 16000);
  await env.DB.prepare(
    `INSERT INTO admin_state (id, last_guild_id, active_tab, preferences_json, updated_at)
     VALUES ('primary', ?, ?, ?, ?)
     ON CONFLICT(id) DO UPDATE SET
       last_guild_id = excluded.last_guild_id,
       active_tab = excluded.active_tab,
       preferences_json = excluded.preferences_json,
       updated_at = excluded.updated_at`
  ).bind(lastGuildId, activeTab, preferencesJson, now()).run();
  return getAdminState(env);
}

async function handleAdminApi(request, env, url, ctx) {
  if (url.pathname === "/api/admin/discord/resync-panels" && request.method === "POST") {
    if (!env.DISCORD_BOT_TOKEN) return json({ ok: false, error: "DISCORD_BOT_TOKEN is not configured" }, 503);
    const body = await readJson(request);
    const guildId = cleanText(body?.guild_id, 64);
    if (!guildId) return json({ ok: false, error: "guild_id is required" }, 400);

    const result = await env.DB.prepare(
      `SELECT id, name, channel_id, embed_title, embed_description, embed_color, created_at, updated_at, script_id
       FROM panels WHERE guild_id = ? AND active = 1 AND channel_id IS NOT NULL`
    ).bind(guildId).all();
    const panels = result.results || [];
    if (!panels.length) return json({ ok: true, resent: 0, failed: 0, panels: [] });

    let resent = 0;
    const failed = [];
    for (const panel of panels) {
      const title = String(panel.embed_title || panel.name || "Voltra Auth").slice(0, 256);
      const description = String(panel.embed_description || "Click a button below to use this panel.").slice(0, 4000);
      const color = Number(panel.embed_color) || 0x4169ff;
      const timestamp = Number(panel.updated_at || panel.created_at || now()) * 1000;
      const sent = await discordApi(env, `/channels/${panel.channel_id}/messages`, {
        method: "POST",
        body: JSON.stringify({
          embeds: [{
            title,
            description,
            color,
            footer: { text: "Resynced from the Voltra Auth dashboard" },
            timestamp: new Date(timestamp).toISOString(),
          }],
          components: panelComponents(panel.id),
          allowed_mentions: { parse: [] },
        }),
      });
      if (!sent?.id) {
        failed.push({ id: panel.id, name: panel.name, channel_id: panel.channel_id });
        continue;
      }
      await env.DB.prepare("UPDATE panels SET message_id = ?, updated_at = ? WHERE id = ?")
        .bind(sent.id, now(), panel.id).run().catch(() => {});
      resent += 1;
    }
    return json({ ok: true, resent, failed: failed.length, failures: failed });
  }

  if (url.pathname === "/api/admin/discord/sync-commands" && request.method === "POST") {
    if (!env.DISCORD_APPLICATION_ID || !env.DISCORD_BOT_TOKEN) return json({ ok: false, error: "Discord application secrets are not configured" }, 503);
    const endpoint = `https://discord.com/api/v10/applications/${env.DISCORD_APPLICATION_ID}/commands`;
    const headers = { authorization: `Bot ${env.DISCORD_BOT_TOKEN}`, "content-type": "application/json" };
    // Full authoritative command list. A PUT with this body wipes and
    // replaces every global command, so the signature is always in sync
    // with the Worker code, never partially migrated from a previous version.
    const commands = voltraAuthDiscordCommands();
    const updateResponse = await fetch(endpoint, { method: "PUT", headers, body: JSON.stringify(commands) });
    if (!updateResponse.ok) {
      const errText = await updateResponse.text().catch(() => "");
      return json({ ok: false, error: `Discord command update failed (${updateResponse.status}): ${errText.slice(0, 240)}` }, 502);
    }
    const updated = await updateResponse.json();
    return json({ ok: true, commands: updated.length });
  }

  if (url.pathname === "/api/admin/state" && request.method === "GET") {
    return json({ ok: true, state: await getAdminState(env) });
  }

  if (url.pathname === "/api/admin/state" && request.method === "PUT") {
    const body = await readJson(request);
    return json({ ok: true, state: await saveAdminState(env, body || {}) });
  }

  if (url.pathname === "/api/admin/account/password" && request.method === "POST") {
    const body = await readJson(request);
    const currentPassword = body?.current_password ?? "";
    const newPassword = String(body?.new_password ?? "");
    if (!(await verifyAdminPassword(env, currentPassword))) {
      return json({ ok: false, error: "Current admin password is incorrect" }, 401);
    }
    if (newPassword.length < 12 || newPassword.length > 256) {
      return json({ ok: false, error: "New admin password must be 12-256 characters" }, 400);
    }
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const hash = await deriveAdminPasswordHash(newPassword, salt, ADMIN_PASSWORD_ITERATIONS);
    await env.DB.prepare(
      `UPDATE admin_credentials SET password_salt = ?, password_hash = ?, iterations = ?, updated_at = ? WHERE id = 'primary'`
    ).bind(bytesToBase64Url(salt), bytesToBase64Url(hash), ADMIN_PASSWORD_ITERATIONS, now()).run();
    await env.DB.prepare("DELETE FROM admin_sessions").run();
    await audit(env, null, "admin.password_changed", "dashboard", "primary", {});
    return jsonWithCookies({ ok: true, reauthenticate: true }, 200, sessionCookieHeaders(""));
  }

  if (url.pathname === "/api/admin/backend/status" && request.method === "GET") {
    const [credential, state, sessions, runtime] = await Promise.all([
      getAdminCredential(env),
      getAdminState(env),
      env.DB.prepare("SELECT COUNT(*) AS n FROM admin_sessions WHERE expires_at > ?").bind(now()).first(),
      env.DB.prepare("SELECT value_json, updated_at FROM runtime_state WHERE key = 'gateway' LIMIT 1").first(),
    ]);
    let gatewaySnapshot = null;
    try { gatewaySnapshot = runtime?.value_json ? JSON.parse(runtime.value_json) : null; } catch {}
    return json({
      ok: true,
      backend: {
        admin_credential_in_d1: !!credential,
        active_sessions: sessions?.n || 0,
        state,
        gateway_snapshot: gatewaySnapshot,
        gateway_snapshot_updated_at: runtime?.updated_at || null,
        secrets_location: "Cloudflare Worker Secrets",
      },
    });
  }
  if (url.pathname === "/api/admin/gateway/status" && request.method === "GET") {
    try {
      const status = await ensureGatewayPresence(env);
      return json({ ok: true, gateway: status });
    } catch (error) {
      console.error("Gateway status failed:", error);
      return json({ ok: false, error: `Gateway unavailable: ${String(error?.message || error)}` }, 503);
    }
  }

  if (url.pathname === "/api/admin/gateway/wake" && request.method === "POST") {
    try {
      const status = await ensureGatewayPresence(env);
      return json({ ok: true, gateway: status });
    } catch (error) {
      console.error("Gateway wake failed:", error);
      return json({ ok: false, error: `Could not start Gateway: ${String(error?.message || error)}` }, 503);
    }
  }

  if (url.pathname === "/api/admin/stats" && request.method === "GET") {
    const guildId = cleanText(url.searchParams.get("guild_id"), 64);
    const guildClause = guildId ? "WHERE guild_id = ?" : "";
    const bind = (stmt) => (guildId ? stmt.bind(guildId) : stmt);

    const [licenses, active, codes, executions, guilds, scripts] = await Promise.all([
      bind(env.DB.prepare(`SELECT COUNT(*) AS n FROM licenses ${guildClause}`)).first(),
      bind(env.DB.prepare(`SELECT COUNT(*) AS n FROM licenses ${guildClause ? guildClause + " AND" : "WHERE"} status = 'active'`)).first(),
      bind(env.DB.prepare(`SELECT COUNT(*) AS n FROM redeem_codes ${guildClause}`)).first(),
      guildId
        ? env.DB.prepare("SELECT COUNT(*) AS n FROM executions WHERE guild_id = ? AND occurred_at >= ?").bind(guildId, now() - 86400).first()
        : env.DB.prepare("SELECT COUNT(*) AS n FROM executions WHERE occurred_at >= ?").bind(now() - 86400).first(),
      env.DB.prepare("SELECT COUNT(*) AS n FROM guilds WHERE active = 1").first(),
      guildId
        ? env.DB.prepare("SELECT COUNT(*) AS n FROM scripts WHERE guild_id = ?").bind(guildId).first()
        : env.DB.prepare("SELECT COUNT(*) AS n FROM scripts").first(),
    ]);

    return json({
      ok: true,
      stats: {
        licenses: licenses?.n || 0,
        active_licenses: active?.n || 0,
        redeem_codes: codes?.n || 0,
        executions_24h: executions?.n || 0,
        guilds: guilds?.n || 0,
        scripts: scripts?.n || 0,
      },
    });
  }

  if (url.pathname === "/api/admin/guilds" && request.method === "GET") {
    const result = await env.DB.prepare(
      "SELECT guild_id, active, manager_role_id, buyer_role_id, base_url, created_at, updated_at FROM guilds ORDER BY created_at DESC"
    ).all();
    return json({ ok: true, guilds: result.results || [] });
  }

  if (url.pathname === "/api/admin/server-keys" && request.method === "GET") {
    const result = await env.DB.prepare(
      `SELECT id, key_hint, key_enc, intended_guild_id, note, expires_at, created_at, used_at, used_by_guild_id, used_by_discord_id
       FROM server_setup_keys
       ORDER BY created_at DESC LIMIT 250`
    ).all();
    const keys = [];
    for (const row of result.results || []) {
      let fullKey = null;
      if (row.key_enc) {
        try { fullKey = await decryptConfigSecret(env, row.key_enc); } catch {}
      }
      const { key_enc, ...safeRow } = row;
      keys.push({ ...safeRow, key: fullKey });
    }
    return json({ ok: true, keys });
  }

  if (url.pathname === "/api/admin/server-keys" && request.method === "POST") {
    const body = await readJson(request);
    const password = body?.password ?? "";
    if (!(await verifyAdminPassword(env, password))) {
      return json({ ok: false, error: "Admin password confirmation failed" }, 401);
    }

    const intendedGuildId = cleanText(body?.intended_guild_id, 64);
    if (intendedGuildId && !/^\d{15,22}$/.test(intendedGuildId)) {
      return json({ ok: false, error: "intended_guild_id must be a Discord server ID" }, 400);
    }
    const expiresInHours = Math.max(1, Math.min(720, Number(body?.expires_in_hours ?? 24)));
    const note = cleanText(body?.note, 300);
    const created = await createServerSetupKey(env, { intendedGuildId, expiresInHours, note });
    await audit(env, intendedGuildId || null, "admin.create_server_key", "dashboard", created.id, {
      intended_guild_id: intendedGuildId || null,
      expires_in_hours: expiresInHours,
      note,
    });
    return json({ ok: true, server_key: created });
  }

  const serverKeyMatch = url.pathname.match(/^\/api\/admin\/server-keys\/([^/]+)$/);
  if (serverKeyMatch && request.method === "DELETE") {
    const id = decodeURIComponent(serverKeyMatch[1]);
    const row = await env.DB.prepare(
      "SELECT id, intended_guild_id, used_at FROM server_setup_keys WHERE id = ? LIMIT 1"
    ).bind(id).first();
    if (!row) return json({ ok: false, error: "Server key not found" }, 404);
    if (row.used_at) return json({ ok: false, error: "Used server keys cannot be revoked" }, 409);
    await env.DB.prepare("DELETE FROM server_setup_keys WHERE id = ?").bind(id).run();
    await audit(env, row.intended_guild_id || null, "admin.revoke_server_key", "dashboard", id, {});
    return json({ ok: true });
  }

  if (url.pathname === "/api/admin/licenses" && request.method === "GET") {
    const guildId = cleanText(url.searchParams.get("guild_id"), 64);
    const q = cleanText(url.searchParams.get("q"), 128);
    let sql = `SELECT l.id, l.guild_id, l.discord_id, l.panel_id, p.name AS panel_name, l.status, l.auth_expire, l.note, l.hwid_hash, l.last_hwid_reset, l.created_at, l.updated_at
               FROM licenses l LEFT JOIN panels p ON p.id = l.panel_id AND p.guild_id = l.guild_id`;
    const args = [];
    const where = [];
    if (guildId) {
      where.push("l.guild_id = ?");
      args.push(guildId);
    }
    if (q) {
      where.push("(l.discord_id LIKE ? OR l.note LIKE ? OR l.id LIKE ? OR p.name LIKE ?)");
      const like = `%${q}%`;
      args.push(like, like, like, like);
    }
    if (where.length) sql += ` WHERE ${where.join(" AND ")}`;
    sql += " ORDER BY l.created_at DESC LIMIT 250";
    const result = await env.DB.prepare(sql).bind(...args).all();
    return json({ ok: true, licenses: result.results || [] });
  }

  if (url.pathname === "/api/admin/licenses" && request.method === "POST") {
    const body = await readJson(request);
    const guildId = cleanText(body?.guild_id, 64);
    if (!guildId) return json({ ok: false, error: "guild_id is required" }, 400);
    const guild = await getGuild(env, guildId);
    if (!guild) return json({ ok: false, error: "Unknown guild. Run /login in Discord first." }, 404);

    const discordId = cleanText(body?.discord_id, 64);
    const panelId = cleanText(body?.panel_id, 128);
    const days = Number(body?.days ?? -1);
    const note = cleanText(body?.note, 300);
    const panel = await getPanel(env, guildId, panelId);
    if (!panel?.script_id) return json({ ok: false, error: "Select an active panel linked to a script" }, 400);
    if (discordId && (await isBlacklisted(env, guildId, discordId))) {
      return json({ ok: false, error: "That Discord user is blacklisted" }, 409);
    }
    if (discordId) {
      const existing = await findLicenseForDiscordAndPanel(env, guildId, discordId, panel.id);
      if (existing) return json({ ok: false, error: "User already has an active license for this panel" }, 409);
    }

    const license = await createLicense(env, { guildId, discordId, panelId: panel.id, days, note });
    await audit(env, guildId, "admin.whitelist", "dashboard", discordId || license.id, { days, note, panel_id: panel.id });
    return json({ ok: true, license });
  }

  // Blacklist by raw license key.
  // Takes { guild_id, key, reason? } and in one call: hashes the key, looks up
  // the license, blacklists the Discord user, persistently blacklists the HWID
  // on hwid_blacklists, and deletes the license so the key can never be used
  // again. The right thing to call when you have an attacker's actual key.
  if (url.pathname === "/api/admin/licenses/blacklist-by-key" && request.method === "POST") {
    const body = await readJson(request);
    const guildId = cleanText(body?.guild_id, 64);
    const rawKey = cleanText(body?.key, 512);
    const reason = cleanText(body?.reason, 300) || "manual_dump";
    if (!guildId) return json({ ok: false, error: "guild_id is required" }, 400);
    if (!rawKey) return json({ ok: false, error: "key is required" }, 400);

    const keyHash = await sha256Hex(rawKey);
    const row = await env.DB.prepare(
      "SELECT id, guild_id, discord_id, hwid_hash FROM licenses WHERE guild_id = ? AND key_hash = ? LIMIT 1"
    ).bind(guildId, keyHash).first();
    if (!row) return json({ ok: false, error: "No license found for that key in this project" }, 404);

    const timestamp = now();
    const banTargets = [];

    if (row.discord_id) {
      await env.DB.prepare(
        `INSERT INTO blacklists (guild_id, discord_id, reason, expires_at, created_at)
         VALUES (?, ?, ?, -1, ?)
         ON CONFLICT(guild_id, discord_id) DO UPDATE SET reason = excluded.reason, expires_at = -1`
      ).bind(guildId, row.discord_id, reason, timestamp).run();
      banTargets.push({ kind: "discord", id: row.discord_id });
    }

    if (row.hwid_hash) {
      await env.DB.prepare(
        `INSERT INTO hwid_blacklists (guild_id, hwid_hash, reason, license_id, created_at)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(guild_id, hwid_hash) DO UPDATE SET reason = excluded.reason`
      ).bind(guildId, row.hwid_hash, reason, row.id, timestamp).run();
      banTargets.push({ kind: "hwid", id: `${String(row.hwid_hash).slice(0, 8)}...` });
    }

    await env.DB.prepare("DELETE FROM licenses WHERE id = ?").bind(row.id).run();
    await audit(env, guildId, "admin.blacklist_by_key", "dashboard", row.discord_id || row.id, { reason, discord_id: row.discord_id, had_hwid: !!row.hwid_hash });

    return json({ ok: true, license_id: row.id, banned: banTargets, had_hwid: !!row.hwid_hash });
  }

  const licenseMatch = url.pathname.match(/^\/api\/admin\/licenses\/([^/]+)(?:\/(reset-hwid))?$/);
  if (licenseMatch) {
    const id = decodeURIComponent(licenseMatch[1]);
    const action = licenseMatch[2];
    if (request.method === "DELETE" && !action) {
      const row = await env.DB.prepare("SELECT guild_id, discord_id FROM licenses WHERE id = ?").bind(id).first();
      if (!row) return json({ ok: false, error: "License not found" }, 404);
      await env.DB.prepare("DELETE FROM licenses WHERE id = ?").bind(id).run();
      await audit(env, row.guild_id, "admin.unwhitelist", "dashboard", row.discord_id || id, {});
      return json({ ok: true });
    }
    if (request.method === "POST" && action === "reset-hwid") {
      const row = await env.DB.prepare("SELECT guild_id, discord_id FROM licenses WHERE id = ?").bind(id).first();
      if (!row) return json({ ok: false, error: "License not found" }, 404);
      await env.DB.prepare("UPDATE licenses SET hwid_hash = NULL, last_hwid_reset = ?, updated_at = ? WHERE id = ?")
        .bind(now(), now(), id)
        .run();
      await audit(env, row.guild_id, "admin.reset_hwid", "dashboard", row.discord_id || id, { forced: true });
      return json({ ok: true });
    }
  }

  if (url.pathname === "/api/admin/stock-keys" && request.method === "GET") {
    const guildId = cleanText(url.searchParams.get("guild_id"), 64);
    if (!guildId) return json({ ok: false, error: "guild_id is required" }, 400);
    const result = await env.DB.prepare(
      `SELECT id, guild_id, auth_expire, note, created_at
       FROM licenses
       WHERE guild_id = ? AND discord_id IS NULL AND status = 'active'
       ORDER BY created_at DESC LIMIT 250`
    ).bind(guildId).all();
    const keys = [];
    for (const row of result.results || []) {
      keys.push({ ...row, key: await deriveLicenseKey(env, row.id) });
    }
    return json({ ok: true, keys });
  }

  if (url.pathname === "/api/admin/stock-keys" && request.method === "POST") {
    const body = await readJson(request);
    const guildId = cleanText(body?.guild_id, 64);
    if (!guildId) return json({ ok: false, error: "guild_id is required" }, 400);
    if (!(await getGuild(env, guildId))) return json({ ok: false, error: "Unknown guild" }, 404);
    const days = Number(body?.days ?? -1);
    const quantity = Math.max(1, Math.min(100, Number(body?.quantity ?? 1)));
    const note = cleanText(body?.note, 300);
    const keys = [];
    for (let i = 0; i < quantity; i++) {
      const created = await createLicense(env, { guildId, discordId: null, days, note: note || "Stock key" });
      keys.push(created.key);
    }
    await audit(env, guildId, "admin.create_stock_keys", "dashboard", guildId, { days, quantity, note });
    return json({ ok: true, keys });
  }

  if (url.pathname === "/api/admin/codes" && request.method === "GET") {
    const guildId = cleanText(url.searchParams.get("guild_id"), 64);
    const stmt = guildId
      ? env.DB.prepare("SELECT id, guild_id, days, uses_left, note, expires_at, created_at FROM redeem_codes WHERE guild_id = ? ORDER BY created_at DESC LIMIT 250").bind(guildId)
      : env.DB.prepare("SELECT id, guild_id, days, uses_left, note, expires_at, created_at FROM redeem_codes ORDER BY created_at DESC LIMIT 250");
    const result = await stmt.all();
    return json({ ok: true, codes: result.results || [] });
  }

  if (url.pathname === "/api/admin/codes" && request.method === "POST") {
    const body = await readJson(request);
    const guildId = cleanText(body?.guild_id, 64);
    if (!guildId) return json({ ok: false, error: "guild_id is required" }, 400);
    if (!(await getGuild(env, guildId))) return json({ ok: false, error: "Unknown guild" }, 404);

    const days = Number(body?.days ?? -1);
    const uses = Math.max(1, Math.min(10000, Number(body?.uses ?? 1)));
    const note = cleanText(body?.note, 300);
    const expiresInDays = Number(body?.expires_in_days ?? -1);
    const rawCode = cleanText(body?.code, 128) || `ETERNAL-${bytesToBase64Url(crypto.getRandomValues(new Uint8Array(12))).toUpperCase()}`;
    const codeHash = await sha256Hex(rawCode.toUpperCase());
    const expiresAt = expiresInDays > 0 ? now() + expiresInDays * 86400 : -1;
    const id = crypto.randomUUID();

    try {
      await env.DB.prepare(
        "INSERT INTO redeem_codes (id, guild_id, code_hash, days, uses_left, note, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
      )
        .bind(id, guildId, codeHash, days, uses, note, expiresAt, now())
        .run();
    } catch {
      return json({ ok: false, error: "Code already exists" }, 409);
    }

    await audit(env, guildId, "admin.create_code", "dashboard", id, { days, uses, note });
    return json({ ok: true, code: rawCode, id });
  }

  if (url.pathname === "/api/admin/hwid-blacklists" && request.method === "GET") {
    const guildId = cleanText(url.searchParams.get("guild_id"), 64);
    const result = guildId
      ? await env.DB.prepare("SELECT * FROM hwid_blacklists WHERE guild_id = ? ORDER BY created_at DESC LIMIT 250").bind(guildId).all()
      : await env.DB.prepare("SELECT * FROM hwid_blacklists ORDER BY created_at DESC LIMIT 250").all();
    return json({ ok: true, blacklists: result.results || [] });
  }
  if (url.pathname === "/api/admin/hwid-blacklists" && request.method === "DELETE") {
    const body = await readJson(request);
    const guildId = cleanText(body?.guild_id, 64);
    const rawDeviceId = cleanText(body?.device_id, 512);
    let hash = cleanText(body?.hwid_hash, 128)?.toLowerCase() || null;
    if (!guildId) return json({ ok: false, error: "Discord server ID is required" }, 400);
    if (rawDeviceId) hash = await hashDevice(env, rawDeviceId);
    if (!hash || !/^[a-f0-9]{64}$/.test(hash)) return json({ ok: false, error: "Enter the raw HWID or select a stored HWID ban" }, 400);
    const existing = await env.DB.prepare("SELECT reason, license_id FROM hwid_blacklists WHERE guild_id = ? AND hwid_hash = ? LIMIT 1").bind(guildId, hash).first();
    if (!existing) return json({ ok: false, error: "That HWID is not blacklisted in this project" }, 404);
    await env.DB.batch([
      env.DB.prepare("UPDATE licenses SET status = 'active', updated_at = ? WHERE guild_id = ? AND status = 'security_blacklisted' AND (hwid_hash = ? OR id IN (SELECT license_id FROM hwid_blacklists WHERE guild_id = ? AND hwid_hash = ?))").bind(now(), guildId, hash, guildId, hash),
      env.DB.prepare("DELETE FROM hwid_blacklists WHERE guild_id = ? AND hwid_hash = ?").bind(guildId, hash),
    ]);
    await audit(env, guildId, "admin.unblacklist_hwid", "dashboard", hash, { reason: existing.reason || null });
    return json({ ok: true, removed: true });
  }

  if (url.pathname === "/api/admin/blacklists" && request.method === "GET") {
    const guildId = cleanText(url.searchParams.get("guild_id"), 64);
    const stmt = guildId
      ? env.DB.prepare("SELECT guild_id, discord_id, reason, expires_at, created_at FROM blacklists WHERE guild_id = ? ORDER BY created_at DESC LIMIT 250").bind(guildId)
      : env.DB.prepare("SELECT guild_id, discord_id, reason, expires_at, created_at FROM blacklists ORDER BY created_at DESC LIMIT 250");
    const result = await stmt.all();
    return json({ ok: true, blacklists: result.results || [] });
  }

  if (url.pathname === "/api/admin/blacklists" && request.method === "POST") {
    const body = await readJson(request);
    const guildId = cleanText(body?.guild_id, 64);
    const discordId = cleanText(body?.discord_id, 64);
    const reason = cleanText(body?.reason, 300);
    const days = Number(body?.days ?? -1);
    if (!guildId || !discordId) return json({ ok: false, error: "guild_id and discord_id are required" }, 400);
    const expiresAt = days > 0 ? now() + days * 86400 : -1;
    await env.DB.prepare(
      `INSERT INTO blacklists (guild_id, discord_id, reason, expires_at, created_at)
       VALUES (?, ?, ?, ?, ?)
       ON CONFLICT(guild_id, discord_id) DO UPDATE SET reason = excluded.reason, expires_at = excluded.expires_at, created_at = excluded.created_at`
    ).bind(guildId, discordId, reason, expiresAt, now()).run();
    await env.DB.prepare("UPDATE licenses SET status = 'blacklisted', updated_at = ? WHERE guild_id = ? AND discord_id = ?")
      .bind(now(), guildId, discordId).run();
    await audit(env, guildId, "admin.blacklist", "dashboard", discordId, { days, reason });
    return json({ ok: true });
  }

  const blacklistMatch = url.pathname.match(/^\/api\/admin\/blacklists\/([^/]+)\/([^/]+)$/);
  if (blacklistMatch && request.method === "DELETE") {
    const guildId = decodeURIComponent(blacklistMatch[1]);
    const discordId = decodeURIComponent(blacklistMatch[2]);
    await env.DB.prepare("DELETE FROM blacklists WHERE guild_id = ? AND discord_id = ?").bind(guildId, discordId).run();
    await env.DB.prepare("UPDATE licenses SET status = 'active', updated_at = ? WHERE guild_id = ? AND discord_id = ? AND status = 'blacklisted'")
      .bind(now(), guildId, discordId).run();
    await audit(env, guildId, "admin.unblacklist", "dashboard", discordId, {});
    return json({ ok: true });
  }

  if (url.pathname === "/api/admin/compensate" && request.method === "POST") {
    const body = await readJson(request);
    const guildId = cleanText(body?.guild_id, 64);
    const days = Math.max(1, Math.min(3650, Number(body?.days || 1)));
    if (!guildId) return json({ ok: false, error: "guild_id is required" }, 400);
    const result = await env.DB.prepare(
      "UPDATE licenses SET auth_expire = auth_expire + ?, updated_at = ? WHERE guild_id = ? AND auth_expire > 0"
    ).bind(days * 86400, now(), guildId).run();
    await audit(env, guildId, "admin.compensate", "dashboard", guildId, { days });
    return json({ ok: true, changed: result.meta?.changes || 0 });
  }

  if (url.pathname === "/api/admin/panels" && request.method === "GET") {
    const guildId = cleanText(url.searchParams.get("guild_id"), 64);
    if (!guildId) return json({ ok: false, error: "guild_id is required" }, 400);
    const result = await env.DB.prepare(
      `SELECT id, guild_id, name, channel_id, manager_role_id, buyer_role_id, script_id, active, created_by, created_at, updated_at
       FROM panels WHERE guild_id = ? ORDER BY created_at DESC LIMIT 250`
    ).bind(guildId).all();
    return json({ ok: true, panels: result.results || [] });
  }

  const adminPanelMatch = url.pathname.match(/^\/api\/admin\/panels\/([^/]+)$/);
  if (adminPanelMatch && request.method === "DELETE") {
    const panelId = decodeURIComponent(adminPanelMatch[1]);
    const row = await env.DB.prepare("SELECT guild_id FROM panels WHERE id = ? LIMIT 1").bind(panelId).first();
    if (!row) return json({ ok: false, error: "Panel not found" }, 404);
    await env.DB.prepare("UPDATE panels SET active = 0, updated_at = ? WHERE id = ?").bind(now(), panelId).run();
    await audit(env, row.guild_id, "admin.disable_panel", "dashboard", panelId, {});
    return json({ ok: true });
  }

  if (url.pathname === "/api/admin/scripts" && request.method === "GET") {
    const guildId = cleanText(url.searchParams.get("guild_id"), 64);
    if (!guildId) return json({ ok: false, error: "guild_id is required" }, 400);
    const guild = await getGuild(env, guildId);
    if (!guild) return json({ ok: false, error: "Unknown guild" }, 404);
    await ensureGuildBaseUrl(env, guild, new URL(request.url).origin);
    const scripts = await getScriptsForGuild(env, guildId, false);
    const safeScripts = scripts.map((script) => safeScriptRecord(guild, script));
    return json({ ok: true, scripts: safeScripts });
  }

  if (url.pathname === "/api/admin/scripts" && request.method === "POST") {
    const body = await readJson(request);
    const guildId = cleanText(body?.guild_id, 64);
    if (!guildId) return json({ ok: false, error: "guild_id is required" }, 400);
    const guild = await getGuild(env, guildId);
    if (!guild) return json({ ok: false, error: "Unknown guild" }, 404);
    await ensureGuildBaseUrl(env, guild, new URL(request.url).origin);

    const id = crypto.randomUUID();
    const loaderId = await deriveScriptLoaderId(env, id);
    const sourceFileName = cleanScriptUploadFileName(body?.source_file_name);
    const rawContent = body?.content == null ? "" : String(body.content);
    if (!sourceFileName) return json({ ok: false, error: "A supported uploaded text/script file is required (.txt, .lua, .luau, etc.)." }, 400);
    if (!rawContent.trim()) return json({ ok: false, error: "Uploaded script file is empty." }, 400);
    if (rawContent.length > 2_000_000) return json({ ok: false, error: "Uploaded script file is too large." }, 413);
    const name = cleanText(body?.name, 100) || sourceFileName.replace(/\.[^.]+$/, "") || "Uploaded Script";
    const version = cleanText(body?.version, 40) || "1.0.0";
    const enabled = body?.enabled === false ? 0 : 1;
    const ffaEnabled = body?.ffa_enabled === true ? 1 : 0;
    const content = rawContent;
    const timestamp = now();

    await env.DB.prepare(
      `INSERT INTO scripts (id, guild_id, loader_id, name, version, enabled, ffa_enabled, content, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(id, guildId, loaderId, name, version, enabled, ffaEnabled, content, timestamp, timestamp).run();
    cacheDelete(scriptHotCache, `${guildId}:all`);
    cacheDelete(scriptHotCache, `${guildId}:enabled`);

    const script = await env.DB.prepare("SELECT * FROM scripts WHERE id = ?").bind(id).first();
    await audit(env, guildId, "admin.create_script", "dashboard", id, { name, version, enabled: !!enabled, source_file_name: sourceFileName });
    return json({ ok: true, script: safeScriptRecord(guild, script) }, 201);
  }

  const adminScriptMatch = url.pathname.match(/^\/api\/admin\/scripts\/([^/]+)$/);
  if (adminScriptMatch && request.method === "PUT") {
    const scriptId = decodeURIComponent(adminScriptMatch[1]);
    const existing = await env.DB.prepare("SELECT * FROM scripts WHERE id = ? LIMIT 1").bind(scriptId).first();
    if (!existing) return json({ ok: false, error: "Script not found" }, 404);
    const body = await readJson(request);
    const name = cleanText(body?.name, 100) || existing.name || "Voltra Auth Script";
    const version = cleanText(body?.version, 40) || existing.version || "1.0.0";
    const enabled = body?.enabled == null ? Number(existing.enabled) : (body.enabled === false ? 0 : 1);
    const ffaEnabled = body?.ffa_enabled == null ? Number(existing.ffa_enabled || 0) : (body.ffa_enabled === true ? 1 : 0);
    let content = existing.content;
    let sourceFileName = null;
    if (body?.content != null) {
      sourceFileName = cleanScriptUploadFileName(body?.source_file_name);
      const rawContent = String(body.content);
      if (!sourceFileName) return json({ ok: false, error: "Replacing protected source requires an uploaded text/script file." }, 400);
      if (!rawContent.trim()) return json({ ok: false, error: "Uploaded script file is empty." }, 400);
      if (rawContent.length > 2_000_000) return json({ ok: false, error: "Uploaded script file is too large." }, 413);
      content = rawContent;
    }
    await env.DB.prepare("UPDATE scripts SET name = ?, version = ?, enabled = ?, ffa_enabled = ?, content = ?, updated_at = ? WHERE id = ?")
      .bind(name, version, enabled, ffaEnabled, content, now(), scriptId)
      .run();
    cacheDelete(scriptHotCache, `${existing.guild_id}:all`);
    cacheDelete(scriptHotCache, `${existing.guild_id}:enabled`);
    const guild = await getGuild(env, existing.guild_id);
    if (guild) await ensureGuildBaseUrl(env, guild, new URL(request.url).origin);
    const script = await ensureScriptLoaderId(env, await env.DB.prepare("SELECT * FROM scripts WHERE id = ?").bind(scriptId).first());
    await audit(env, existing.guild_id, "admin.update_script", "dashboard", scriptId, { name, version, enabled: !!enabled, ffa_enabled: !!ffaEnabled, source_file_name: sourceFileName });
    return json({ ok: true, script: safeScriptRecord(guild, script) });
  }

  if (adminScriptMatch && request.method === "DELETE") {
    const scriptId = decodeURIComponent(adminScriptMatch[1]);
    const existing = await env.DB.prepare("SELECT * FROM scripts WHERE id = ? LIMIT 1").bind(scriptId).first();
    if (!existing) return json({ ok: false, error: "Script not found" }, 404);
    await env.DB.prepare("DELETE FROM scripts WHERE id = ?").bind(scriptId).run();
    cacheDelete(scriptHotCache, `${existing.guild_id}:all`);
    cacheDelete(scriptHotCache, `${existing.guild_id}:enabled`);
    await audit(env, existing.guild_id, "admin.delete_script", "dashboard", scriptId, { name: existing.name });
    return json({ ok: true });
  }

  if (url.pathname === "/api/admin/config" && request.method === "GET") {
    const guildId = cleanText(url.searchParams.get("guild_id"), 64);
    if (!guildId) return json({ ok: false, error: "guild_id is required" }, 400);
    const guild = await getGuild(env, guildId);
    if (guild) await ensureGuildBaseUrl(env, guild, new URL(request.url).origin);
    let script = guild ? await env.DB.prepare("SELECT * FROM scripts WHERE guild_id = ? ORDER BY created_at ASC LIMIT 1").bind(guildId).first() : null;
    if (script) script = await ensureScriptLoaderId(env, script);
    const safeGuild = guild ? {
      guild_id: guild.guild_id,
      active: guild.active,
      manager_role_id: guild.manager_role_id,
      buyer_role_id: guild.buyer_role_id,
      base_url: guild.base_url,
      loader_id: script?.loader_id || guild.loader_id,
      loader_url: script ? loaderUrlForScript(guild, script) : loaderUrlForGuild(guild),
      loader_template: guild.loader_template,
      logs_enabled: !!guild.log_webhook_enc,
      created_at: guild.created_at,
      updated_at: guild.updated_at,
    } : null;
    return json({ ok: true, guild: safeGuild, script: safeScriptRecord(guild, script) });
  }

  if (url.pathname === "/api/admin/config" && request.method === "PUT") {
    const body = await readJson(request);
    const guildId = cleanText(body?.guild_id, 64);
    if (!guildId) return json({ ok: false, error: "guild_id is required" }, 400);
    const guild = await getGuild(env, guildId);
    if (!guild) return json({ ok: false, error: "Unknown guild" }, 404);

    if (body.loader_template != null) {
      await env.DB.prepare("UPDATE guilds SET loader_template = ?, updated_at = ? WHERE guild_id = ?")
        .bind(String(body.loader_template).slice(0, 12000), now(), guildId)
        .run();
    }

    // Protected source is file-upload only in v1.6.1. Older clients are not
    // allowed to paste source through the legacy config endpoint.
    if (body.script_content != null) {
      return json({ ok: false, error: "Protected source must be uploaded as a text/script file." }, 400);
    }

    await audit(env, guildId, "admin.update_config", "dashboard", guildId, { loader_template: body.loader_template != null });
    return json({ ok: true });
  }

  if (url.pathname === "/api/admin/logs" && request.method === "GET") {
    const guildId = cleanText(url.searchParams.get("guild_id"), 64);
    const stmt = guildId
      ? env.DB.prepare("SELECT * FROM audit_logs WHERE guild_id = ? ORDER BY created_at DESC LIMIT 250").bind(guildId)
      : env.DB.prepare("SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 250");
    const result = await stmt.all();
    return json({ ok: true, logs: result.results || [] });
  }

  return json({ ok: false, error: "Not found" }, 404);
}

async function getGuild(env, guildId) {
  const cached = cacheGet(guildHotCache, guildId);
  if (cached) return { ...cached };
  const guild = await env.DB.prepare("SELECT * FROM guilds WHERE guild_id = ? AND active = 1 LIMIT 1").bind(guildId).first();
  const ready = await ensureGuildLoaderId(env, guild);
  if (ready) cachePut(guildHotCache, guildId, { ...ready });
  return ready;
}

async function ensureGuildBaseUrl(env, guild, origin) {
  if (!guild) return guild;
  const normalized = String(origin || "").replace(/\/$/, "");
  if (!normalized) return guild;
  if (guild.base_url !== normalized) {
    await env.DB.prepare("UPDATE guilds SET base_url = ?, updated_at = ? WHERE guild_id = ?")
      .bind(normalized, now(), guild.guild_id)
      .run();
    guild.base_url = normalized;
    cachePut(guildHotCache, guild.guild_id, { ...guild });
  }
  return guild;
}

async function audit(env, guildId, action, actorId, target, details = {}) {
  const safeDetails = JSON.stringify(details).slice(0, 4000);
  await env.DB.prepare(
    "INSERT INTO audit_logs (guild_id, action, actor_id, target, details, created_at) VALUES (?, ?, ?, ?, ?, ?)"
  )
    .bind(guildId || null, action, actorId || null, target || null, safeDetails, now())
    .run();
}

async function verifyDiscordRequest(request, env) {
  const signature = request.headers.get("x-signature-ed25519");
  const timestamp = request.headers.get("x-signature-timestamp");
  if (!signature || !timestamp || !env.DISCORD_PUBLIC_KEY) return null;

  const rawBody = await request.text();
  try {
    const publicKey = await crypto.subtle.importKey(
      "raw",
      hexToBytes(env.DISCORD_PUBLIC_KEY),
      { name: "Ed25519" },
      false,
      ["verify"]
    );
    const valid = await crypto.subtle.verify(
      { name: "Ed25519" },
      publicKey,
      hexToBytes(signature),
      enc.encode(timestamp + rawBody)
    );
    if (!valid) return null;
    return JSON.parse(rawBody);
  } catch (error) {
    console.error("Discord verify error", error);
    return null;
  }
}

// Discord interaction responses must NOT go through withSecurityHeaders.
// Discord's receiver is picky about the response envelope and the browser-level
// CSP/HSTS/COOP headers are meaningless to it. Use a plain Response.
function discordJsonResponse(payload) {
  return new Response(JSON.stringify(payload), {
    status: 200,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}

function discordMessage(content, ephemeral = true, components = undefined) {
  const data = { content, allowed_mentions: { parse: [] } };
  if (ephemeral) data.flags = EPHEMERAL;
  if (components) data.components = components;
  return discordJsonResponse({ type: 4, data });
}

function discordModal(customId, title, label, placeholder = "") {
  return discordJsonResponse({
    type: 9,
    data: {
      custom_id: customId,
      title,
      components: [
        {
          type: 1,
          components: [
            {
              type: 4,
              custom_id: "value",
              style: 1,
              label,
              placeholder,
              required: true,
              min_length: 1,
              max_length: 128,
            },
          ],
        },
      ],
    },
  });
}

async function updateDeferredDiscordResponse(interaction, response) {
  const applicationId = cleanText(interaction?.application_id, 64);
  const token = cleanText(interaction?.token, 256);
  if (!applicationId || !token) return false;

  let data = null;
  try {
    const payload = await response.clone().json();
    if (payload?.type === 4 || payload?.type === 7) data = payload.data || {};
    else if (payload?.type === 9) {
      data = {
        content: "This action needs to open a Discord modal. Please run it again.",
        allowed_mentions: { parse: [] },
      };
    }
  } catch {}

  if (!data) {
    data = {
      content: response?.ok === false
        ? "Voltra Auth could not complete that command."
        : "Voltra Auth finished the command.",
      allowed_mentions: { parse: [] },
    };
  }

  // Ephemeral state is fixed by the initial defer and cannot be changed here.
  if (data && typeof data === "object") {
    delete data.flags;
    if (!data.allowed_mentions) data.allowed_mentions = { parse: [] };
  }

  const result = await fetch(
    `https://discord.com/api/v10/webhooks/${encodeURIComponent(applicationId)}/${encodeURIComponent(token)}/messages/@original`,
    {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(data),
    },
  );
  if (!result.ok) {
    console.error("Discord deferred response update failed", result.status, await result.text().catch(() => ""));
  }
  return result.ok;
}

function deferredDiscordMessage() {
  return discordJsonResponse({
    type: 5,
    data: { flags: EPHEMERAL },
  });
}

function interactionUserId(interaction) {
  return interaction.member?.user?.id || interaction.user?.id || null;
}

function optionMap(interaction) {
  return Object.fromEntries((interaction.data?.options || []).map((o) => [o.name, o.value]));
}

function memberIsAdmin(interaction) {
  try {
    return (BigInt(interaction.member?.permissions || "0") & ADMINISTRATOR) === ADMINISTRATOR;
  } catch {
    return false;
  }
}

function memberIsManager(interaction, guild) {
  if (memberIsAdmin(interaction)) return true;
  const roles = interaction.member?.roles || [];
  return !!guild?.manager_role_id && roles.includes(guild.manager_role_id);
}

async function getPanel(env, guildId, panelId) {
  if (!panelId) return null;
  const cacheKey = `${guildId}:${panelId}`;
  const cached = cacheGet(panelHotCache, cacheKey);
  if (cached) return { ...cached };
  const panel = await env.DB.prepare(
    "SELECT * FROM panels WHERE id = ? AND guild_id = ? AND active = 1 LIMIT 1"
  ).bind(panelId, guildId).first();
  if (panel) cachePut(panelHotCache, cacheKey, { ...panel });
  return panel;
}

function guildForPanel(guild, panel) {
  if (!panel) return guild;
  return {
    ...guild,
    manager_role_id: panel.manager_role_id || guild.manager_role_id || null,
    buyer_role_id: panel.buyer_role_id || guild.buyer_role_id || null,
    loader_template: panel.loader_template || guild.loader_template || defaultLoaderTemplate(),
  };
}

async function handleDiscordInteraction(request, env, ctx, verifiedInteraction = null, background = false) {
  const interaction = verifiedInteraction || await verifyDiscordRequest(request, env);
  if (!interaction) return new Response("Invalid request signature", { status: 401 });

  // Discord only allows a few seconds for the initial interaction response.
  // Ping and autocomplete stay synchronous; normal commands are acknowledged
  // immediately and completed through the interaction webhook in waitUntil().
  if (!background) {
    if (interaction.type === 1) return discordJsonResponse({ type: 1 });

    if (interaction.type === 3) {
      const customId = String(interaction.data?.custom_id || "");
      const parts = customId.split(":");
      const action = parts[1] || "";
      const panelId = parts[2] || null;

      // A modal must be the initial interaction response; it cannot be opened
      // after a defer. Redeem does not need a database lookup.
      if (action === "redeem") {
        return discordModal(
          `eternal:redeem_modal${panelId ? `:${panelId}` : ""}`,
          "Redeem Voltra Auth Key",
          "Redeem code",
          "ETERNAL-...",
        );
      }

      // setpanel_project also opens a modal. Keep that path synchronous, but
      // skip the expensive schema bootstrap below.
      if (action !== "setpanel_project") {
        ctx.waitUntil((async () => {
          try {
            try {
              await ensureBackendPersistenceSchema(env);
            } catch (schemaError) {
              // Existing panel actions should still work if a background
              // self-migration check has a transient/race failure.
              console.error("Discord component schema ensure failed", schemaError);
            }
            const response = await handleDiscordComponent(interaction, env, ctx);
            await updateDeferredDiscordResponse(interaction, response);
          } catch (error) {
            console.error("Deferred Discord component failed", error);
            const message = String(error?.message || error || "unknown error").slice(0, 180);
            await updateDeferredDiscordResponse(
              interaction,
              discordMessage(`Voltra Auth action failed: ${message}`),
            );
          }
        })());
        return deferredDiscordMessage();
      }
    }

    if (interaction.type === 5) {
      ctx.waitUntil((async () => {
        try {
          try {
            await ensureBackendPersistenceSchema(env);
          } catch (schemaError) {
            console.error("Discord modal schema ensure failed", schemaError);
          }
          const response = await handleDiscordModalSubmit(interaction, env, ctx);
          await updateDeferredDiscordResponse(interaction, response);
        } catch (error) {
          console.error("Deferred Discord modal failed", error);
          const message = String(error?.message || error || "unknown error").slice(0, 180);
          await updateDeferredDiscordResponse(
            interaction,
            discordMessage(`Voltra Auth action failed: ${message}`),
          );
        }
      })());
      return deferredDiscordMessage();
    }

    if (interaction.type === 2) {
      ctx.waitUntil((async () => {
        try {
          const response = await handleDiscordInteraction(request, env, ctx, interaction, true);
          await updateDeferredDiscordResponse(interaction, response);
        } catch (error) {
          console.error("Deferred Discord command failed", error);
          const message = String(error?.message || error || "unknown error").slice(0, 180);
          await updateDeferredDiscordResponse(
            interaction,
            discordMessage(`Voltra Auth command failed: ${message}`),
          );
        }
      })());
      return deferredDiscordMessage();
    }
  }

  if (interaction.type === 1) return discordJsonResponse({ type: 1 });

  if (interaction.type === 4) {
    const guildId = interaction.guild_id;
    const command = interaction.data?.name;
    const focused = (interaction.data?.options || []).find((option) => option.focused);
    if ((command !== "whitelist" && command !== "unwhitelist") || focused?.name !== "panel" || !guildId) return discordJsonResponse({ type: 8, data: { choices: [] } });
    const query = String(focused.value || "").toLowerCase();
    const panels = await env.DB.prepare("SELECT id, name FROM panels WHERE guild_id = ? AND active = 1 AND script_id IS NOT NULL ORDER BY created_at DESC LIMIT 25").bind(guildId).all();
    const panelChoices = (panels.results || [])
      .filter((panel) => !query || String(panel.name || "").toLowerCase().includes(query) || String(panel.id).toLowerCase().includes(query))
      .slice(0, command === "unwhitelist" ? 24 : 25)
      .map((panel) => ({ name: String(panel.name || "Voltra Auth Panel").slice(0, 100), value: String(panel.id) }));
    // /unwhitelist gets an extra "All panels" choice that nukes every license
    // the user holds in this project in one call.
    const choices = command === "unwhitelist" && (!query || "all panels".includes(query) || "all".includes(query))
      ? [{ name: "All panels", value: "*" }, ...panelChoices]
      : panelChoices;
    return discordJsonResponse({ type: 8, data: { choices } });
  }

  const fastModalAction = interaction.type === 3
    ? String(interaction.data?.custom_id || "").split(":")[1] || ""
    : "";
  if (fastModalAction !== "setpanel_project") {
    await ensureBackendPersistenceSchema(env);
  } else {
    // Schema is already provisioned in deployed environments; don't put DDL
    // on the critical path for a modal that must be returned immediately.
    ctx.waitUntil(ensureBackendPersistenceSchema(env).catch((error) => {
      console.error("Background schema ensure failed", error);
    }));
  }

  if (interaction.type === 3) {
    return handleDiscordComponent(interaction, env, ctx);
  }

  if (interaction.type === 5) {
    return handleDiscordModalSubmit(interaction, env, ctx);
  }

  if (interaction.type !== 2) return discordMessage("Unsupported interaction.");

  const name = interaction.data?.name;
  const guildId = interaction.guild_id;
  const userId = interactionUserId(interaction);
  if (!guildId || !userId) return discordMessage("Voltra Auth commands must be used in a server.");

  const opts = optionMap(interaction);

  if (name === "login") {
    if (!memberIsAdmin(interaction)) return discordMessage("Only a Discord server administrator can run `/login`.");

    const existingGuild = await getGuild(env, guildId);
    if (existingGuild) {
      await ensureGuildBaseUrl(env, existingGuild, new URL(request.url).origin);
      const existingLoaderUrl = loaderUrlForGuild(existingGuild);
      return discordMessage(existingLoaderUrl
        ? `Voltra Auth is already linked to this server.\n\n**Loader URL:**\n${existingLoaderUrl}`
        : "Voltra Auth is already linked to this server.");
    }

    const serverKey = cleanText(opts.key, 512) || "";
    const consumed = await consumeServerSetupKey(env, serverKey, guildId, userId);
    if (!consumed.ok) return discordMessage(consumed.error);

    const timestamp = now();
    const baseUrl = new URL(request.url).origin;
    await env.DB.prepare(
      `INSERT INTO guilds
        (guild_id, active, base_url, loader_template, created_at, updated_at)
       VALUES (?, 1, ?, ?, ?, ?)
       ON CONFLICT(guild_id) DO UPDATE SET
         active = 1,
         base_url = excluded.base_url,
         updated_at = excluded.updated_at`
    )
      .bind(guildId, baseUrl, defaultLoaderTemplate(), timestamp, timestamp)
      .run();

    await audit(env, guildId, "discord.login", userId, guildId, { server_key_id: consumed.row.id });
    return discordMessage("✅ Voltra Auth is linked. That server key has been consumed and cannot be reused. Now run `/setpanel` with your loader template, manager role, and optional buyer role.");
  }

  const guild = await getGuild(env, guildId);
  if (!guild) return discordMessage("Voltra Auth is not configured here yet. A server administrator must run `/login`.");
  await ensureGuildBaseUrl(env, guild, new URL(request.url).origin);

  if (name === "logout") {
    if (!memberIsManager(interaction, guild)) return discordMessage("Manager permission required.");
    await env.DB.prepare("UPDATE guilds SET active = 0, updated_at = ? WHERE guild_id = ?")
      .bind(now(), guildId)
      .run();
    await audit(env, guildId, "discord.logout", userId, guildId, {});
    return discordMessage("✅ Voltra Auth has been logged out from this server.");
  }

  if (name === "setlogs") {
    if (!memberIsManager(interaction, guild) && !memberIsAdmin(interaction)) return discordMessage("Manager permission required.");
    const webhook = cleanText(opts.webhook, 1000);
    if (!webhook) return discordMessage("Provide a Discord webhook URL, or `off` to disable logs.");
    if (webhook.toLowerCase() === "off") {
      await env.DB.prepare("UPDATE guilds SET log_webhook_enc = NULL, updated_at = ? WHERE guild_id = ?")
        .bind(now(), guildId)
        .run();
      await audit(env, guildId, "discord.setlogs", userId, "disabled", {});
      return discordMessage("✅ Voltra Auth command logs are disabled.");
    }
    if (!/^https:\/\/(?:canary\.|ptb\.)?discord(?:app)?\.com\/api\/webhooks\//i.test(webhook)) {
      return discordMessage("That does not look like a Discord webhook URL.");
    }
    const encrypted = await encryptConfigSecret(env, webhook);
    await env.DB.prepare("UPDATE guilds SET log_webhook_enc = ?, updated_at = ? WHERE guild_id = ?")
      .bind(encrypted, now(), guildId)
      .run();
    await audit(env, guildId, "discord.setlogs", userId, "webhook", {});
    return discordMessage("✅ Voltra Auth logs will be sent through that webhook.");
  }

  if (name === "setpanel") {
    if (!memberIsManager(interaction, guild) && !memberIsAdmin(interaction)) return discordMessage("Manager permission required.");

    const attachmentId = cleanText(opts.loader_script, 64);
    const managerRole = cleanText(opts.manager_role, 64);
    const buyerRole = cleanText(opts.buyer_role, 64);
    if (!attachmentId || !managerRole || !buyerRole) {
      return discordMessage("`loader_script`, `manager_role`, and `buyer_role` are required.");
    }

    const attachment = interaction.data?.resolved?.attachments?.[attachmentId];
    if (!attachment?.url) return discordMessage("I could not read the uploaded loader script attachment.");

    const fileName = String(attachment.filename || "loader.lua");
    const extension = fileName.includes(".") ? fileName.slice(fileName.lastIndexOf(".")).toLowerCase() : "";
    const allowedExtensions = new Set([".lua", ".luau", ".txt", ".md", ".cfg", ".ini", ".json", ".js", ".ts", ".xml", ".yaml", ".yml", ".py", ".rb", ".sh", ".ps1", ".bat", ".cmd", ".toml", ".conf", ".log"]);
    if (!allowedExtensions.has(extension)) {
      return discordMessage("Upload a text/script file such as `.lua`, `.luau`, or `.txt` for `loader_script`.");
    }
    if (Number(attachment.size || 0) > 1024 * 1024) {
      return discordMessage("The loader script file is too large. Keep it under 1 MB.");
    }

    // The attachment download and project lookup are independent. Start both
    // immediately so Discord waits for one network round trip instead of two.
    const attachmentPromise = (async () => {
      const attachmentUrl = new URL(attachment.url);
      if (attachmentUrl.protocol !== "https:") throw new Error("Attachment URL must use HTTPS");
      const response = await fetch(attachmentUrl.toString(), {
        headers: { "user-agent": "VoltraAuth/1.9.0" },
        cf: { cacheTtl: 30, cacheEverything: true },
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return (await response.text()).replace(/^\uFEFF/, "").trim();
    })();
    const scriptsPromise = getScriptsForGuild(env, guildId, true);

    let uploadedText, enabledScripts;
    try {
      [uploadedText, enabledScripts] = await Promise.all([attachmentPromise, scriptsPromise]);
    } catch (error) {
      console.error("Voltra Auth setpanel preload failed", error);
      return discordMessage("I could not prepare the uploaded loader script. Please try again.");
    }

    if (!uploadedText) return discordMessage("The uploaded loader script file is empty.");
    const uploadedLoaderUrl = extractLoaderUrl(uploadedText);
    if (!uploadedLoaderUrl) {
      return discordMessage('The loader file only needs a normal Voltra Auth loadstring, for example `loadstring(game:HttpGet("https://.../files/v4/loaders/LOADER_ID.lua"))()` (a bare loader URL also works).');
    }

    let parsedLoaderUrl;
    try { parsedLoaderUrl = new URL(uploadedLoaderUrl); }
    catch { return discordMessage("The uploaded loader URL is invalid."); }
    if (parsedLoaderUrl.protocol !== "https:") return discordMessage("The loader URL must use HTTPS.");

    const loaderMatch = parsedLoaderUrl.pathname.match(/^\/files\/v4\/loaders\/([a-f0-9]{32})\.lua$/i);
    if (!loaderMatch) return discordMessage("The uploaded loadstring must point to an Voltra Auth `/files/v4/loaders/<loader-id>.lua` URL.");

    enabledScripts = (enabledScripts || []).slice(0, 25);
    if (!enabledScripts.length) return discordMessage("This Voltra Auth project has no enabled scripts to link a panel to.");

    const draftId = crypto.randomUUID();
    const ts = now();
    const loaderTemplate = `script_key="{{KEY}}";\nloadstring(game:HttpGet(${JSON.stringify(uploadedLoaderUrl)}))()`;
    const draftRecord = {
      id: draftId, guild_id: guildId, channel_id: interaction.channel_id || null,
      manager_role_id: managerRole, buyer_role_id: buyerRole, loader_template: loaderTemplate,
      uploaded_loader_url: uploadedLoaderUrl, selected_script_id: null, created_by: userId,
      created_at: ts, expires_at: ts + 900,
    };
    await env.DB.prepare(
      `INSERT INTO panel_drafts
        (id, guild_id, channel_id, manager_role_id, buyer_role_id, loader_template, uploaded_loader_url, created_by, created_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(draftId, guildId, interaction.channel_id || null, managerRole, buyerRole, loaderTemplate, uploadedLoaderUrl, userId, ts, ts + 900).run();
    cachePut(draftHotCache, draftId, draftRecord, 15 * 60_000);

    const projectOptions = enabledScripts.map((script) => ({
      label: String(script.name || "Unnamed Script").slice(0, 100),
      description: `Version ${String(script.version || "1.0.0")}`.slice(0, 100),
      value: script.id,
    }));

    return json({
      type: 4,
      data: {
        flags: EPHEMERAL,
        embeds: [{
          title: "[2/3] Select a project",
          description: `Selected manager role: <@&${managerRole}>\nSelected buyer role: <@&${buyerRole}>\n\nPlease select a project to link this panel to`,
          color: 0x2563eb,
          timestamp: new Date().toISOString(),
        }],
        components: [{
          type: 1,
          components: [{
            type: 3,
            custom_id: `eternal:setpanel_project:${draftId}`,
            placeholder: "Select a project",
            min_values: 1,
            max_values: 1,
            options: projectOptions,
          }],
        }],
      },
    });
  }

  if (name === "whitelist") {
    if (!memberIsManager(interaction, guild)) return discordMessage("Manager permission required.");
    const target = cleanText(opts.user, 64);
    const days = Number(opts.days ?? -1);
    const note = cleanText(opts.note, 300);
    const panel = await getPanel(env, guildId, cleanText(opts.panel, 128));
    if (!panel?.script_id) return discordMessage("Select an active panel linked to a script.");
    if (await isBlacklisted(env, guildId, target)) return discordMessage("That user is blacklisted.");
    if (await findLicenseForDiscordAndPanel(env, guildId, target, panel.id)) return discordMessage(`That user already has an active license for **${panel.name}**.`);

    const license = await createLicense(env, { guildId, discordId: target, panelId: panel.id, days, note });
    const panelGuild = guildForPanel(guild, panel);
    ctx.waitUntil(addBuyerRole(env, panelGuild, target));
    ctx.waitUntil(dmLoader(env, panelGuild, target, license.key, guild.base_url, panel));
    await audit(env, guildId, "discord.whitelist", userId, target, { days, note, panel_id: panel.id });
    ctx.waitUntil(sendLog(env, guild, `✅ Whitelisted <@${target}> to panel **${panel.name}**${days > 0 ? ` for ${days} day(s)` : " (lifetime)"}.`));
    return discordMessage(`✅ Whitelisted <@${target}> to **${panel.name}**. Key: \`${license.key}\``);
  }

  if (name === "unwhitelist") {
    if (!memberIsManager(interaction, guild)) return discordMessage("Manager permission required.");
    const target = cleanText(opts.user, 64);
    const panelRaw = cleanText(opts.panel, 128);
    if (!panelRaw) return discordMessage("Select a panel to remove the user from.");

    // "*" means wipe every panel for this user in this project.
    if (panelRaw === "*") {
      const result = await env.DB.prepare("DELETE FROM licenses WHERE guild_id = ? AND discord_id = ?")
        .bind(guildId, target)
        .run();
      const deleted = result.meta?.changes || 0;
      if (!deleted) return discordMessage(`<@${target}> had no active licenses in this project.`);
      ctx.waitUntil(removeBuyerRole(env, guild, target));
      await audit(env, guildId, "discord.unwhitelist", userId, target, { deleted, panel_id: "all" });
      ctx.waitUntil(sendLog(env, guild, `🗑️ Unwhitelisted <@${target}> from **all panels** (${deleted} license(s)).`));
      return discordMessage(`✅ Unwhitelisted <@${target}> from **all panels** (${deleted} license(s)).`);
    }

    const panel = await getPanel(env, guildId, panelRaw);
    if (!panel) return discordMessage("Select a panel to remove the user from.");
    const result = await env.DB.prepare("DELETE FROM licenses WHERE guild_id = ? AND discord_id = ? AND panel_id = ?")
      .bind(guildId, target, panel.id)
      .run();
    const deleted = result.meta?.changes || 0;
    if (!deleted) return discordMessage(`<@${target}> had no active license on **${panel.name}**.`);
    // Only strip the buyer role if the user has no remaining licenses in this project.
    const remaining = await findLicenseForDiscord(env, guildId, target);
    if (!remaining) ctx.waitUntil(removeBuyerRole(env, guildForPanel(guild, panel), target));
    await audit(env, guildId, "discord.unwhitelist", userId, target, { deleted, panel_id: panel.id });
    ctx.waitUntil(sendLog(env, guild, `🗑️ Unwhitelisted <@${target}> from panel **${panel.name}**.`));
    return discordMessage(`✅ Unwhitelisted <@${target}> from **${panel.name}**.`);
  }

  if (name === "blacklist") {
    if (!memberIsManager(interaction, guild)) return discordMessage("Manager permission required.");
    const target = cleanText(opts.user, 64);
    const days = Number(opts.days ?? -1);
    const reason = cleanText(opts.reason, 300);
    const expiresAt = days > 0 ? now() + days * 86400 : -1;
    await env.DB.prepare(
      `INSERT INTO blacklists (guild_id, discord_id, reason, expires_at, created_at)
       VALUES (?, ?, ?, ?, ?)
       ON CONFLICT(guild_id, discord_id) DO UPDATE SET
         reason = excluded.reason, expires_at = excluded.expires_at, created_at = excluded.created_at`
    )
      .bind(guildId, target, reason, expiresAt, now())
      .run();
    await env.DB.prepare("UPDATE licenses SET status = 'blacklisted', updated_at = ? WHERE guild_id = ? AND discord_id = ?")
      .bind(now(), guildId, target)
      .run();
    ctx.waitUntil(removeBuyerRole(env, guild, target));
    await audit(env, guildId, "discord.blacklist", userId, target, { days, reason });
    ctx.waitUntil(sendLog(env, guild, `⛔ Blacklisted <@${target}>${reason ? ` — ${reason}` : ""}`));
    return discordMessage(`✅ Blacklisted <@${target}>.`);
  }

  if (name === "unblacklist") {
    if (!memberIsManager(interaction, guild)) return discordMessage("Manager permission required.");
    const target = cleanText(opts.user, 64);
    const targetLicenses = await env.DB.prepare("SELECT id, hwid_hash FROM licenses WHERE guild_id = ? AND discord_id = ?").bind(guildId, target).all();
    const statements = [
      env.DB.prepare("DELETE FROM blacklists WHERE guild_id = ? AND discord_id = ?").bind(guildId, target),
      env.DB.prepare("UPDATE licenses SET status = 'active', updated_at = ? WHERE guild_id = ? AND discord_id = ? AND status IN ('blacklisted','security_blacklisted')").bind(now(), guildId, target),
    ];
    for (const license of targetLicenses.results || []) {
      statements.push(env.DB.prepare("DELETE FROM hwid_blacklists WHERE guild_id = ? AND (license_id = ? OR hwid_hash = ?)").bind(guildId, license.id, license.hwid_hash || ""));
    }
    await env.DB.batch(statements);
    await audit(env, guildId, "discord.unblacklist", userId, target, { hwid_cleared: true });
    return discordMessage(`✅ Removed Discord and HWID blacklists for <@${target}>.`);
  }

  if (name === "compensate") {
    if (!memberIsManager(interaction, guild)) return discordMessage("Manager permission required.");
    const days = Math.max(1, Number(opts.days || 1));
    await env.DB.prepare(
      "UPDATE licenses SET auth_expire = auth_expire + ?, updated_at = ? WHERE guild_id = ? AND auth_expire > 0"
    )
      .bind(days * 86400, now(), guildId)
      .run();
    await audit(env, guildId, "discord.compensate", userId, guildId, { days });
    ctx.waitUntil(sendLog(env, guild, `🎁 Added ${days} day(s) to all expiring Voltra Auth licenses.`));
    return discordMessage(`✅ Added ${days} day(s) to all non-lifetime licenses.`);
  }

  if (name === "force-resethwid") {
    if (!memberIsManager(interaction, guild)) return discordMessage("Manager permission required.");
    const target = cleanText(opts.user, 64);
    const license = await findAnyLicenseForDiscord(env, guildId, target);
    if (!license) return discordMessage("That user has no Voltra Auth license.");
    await env.DB.prepare("UPDATE licenses SET hwid_hash = NULL, last_hwid_reset = ?, updated_at = ? WHERE id = ?")
      .bind(now(), now(), license.id)
      .run();
    await audit(env, guildId, "discord.force_resethwid", userId, target, {});
    return discordMessage(`✅ Forced an HWID reset for <@${target}>.`);
  }

  if (name === "mass-whitelist") {
    if (!memberIsManager(interaction, guild)) return discordMessage("Manager permission required.");
    const roleId = cleanText(opts.role, 64);
    const days = Number(opts.days ?? -1);
    const members = await fetchGuildMembersWithRole(env, guildId, roleId);
    let added = 0;
    let skipped = 0;
    for (const member of members) {
      if (member.user?.bot) continue;
      const target = member.user?.id;
      if (!target || (await isBlacklisted(env, guildId, target)) || (await findLicenseForDiscord(env, guildId, target))) {
        skipped++;
        continue;
      }
      await createLicense(env, { guildId, discordId: target, days, note: `Mass whitelist from role ${roleId}` });
      added++;
    }
    await audit(env, guildId, "discord.mass_whitelist", userId, roleId, { days, added, skipped });
    return discordMessage(`✅ Mass whitelist complete. Added: **${added}** • Skipped: **${skipped}**.`);
  }

  if (name === "redeem") {
    const code = cleanText(opts.code, 128);
    return redeemForDiscord(env, guild, userId, code, ctx);
  }

  if (name === "resethwid") {
    return resetOwnHwid(env, guild, userId, ctx);
  }

  if (name === "script") {
    return sendOwnScript(env, guild, userId, interaction);
  }

  if (name === "ffa") {
    return sendFfaScript(env, guild, opts.script);
  }

  if (name === "getrole") {
    const license = await findLicenseForDiscord(env, guildId, userId);
    const valid = await validateLicense(env, license, null, false);
    if (!valid.ok) return discordMessage(valid.error);
    const ok = await addBuyerRole(env, guild, userId);
    return discordMessage(ok ? "✅ Your buyer role has been restored." : "Your access is valid, but no buyer role is configured or I could not assign it.");
  }

  if (name === "stats") {
    if (!memberIsManager(interaction, guild)) return discordMessage("Manager permission required.");
    const [licenses, blacklisted, execs] = await Promise.all([
      env.DB.prepare("SELECT COUNT(*) AS n FROM licenses WHERE guild_id = ? AND status = 'active'").bind(guildId).first(),
      env.DB.prepare("SELECT COUNT(*) AS n FROM blacklists WHERE guild_id = ?").bind(guildId).first(),
      env.DB.prepare("SELECT COUNT(*) AS n FROM executions WHERE guild_id = ? AND occurred_at >= ?").bind(guildId, now() - 86400).first(),
    ]);
    return discordMessage(`📊 **Voltra Auth Stats**\nActive licenses: **${licenses?.n || 0}**\nBlacklisted: **${blacklisted?.n || 0}**\nExecutions (24h): **${execs?.n || 0}**`);
  }

  return discordMessage("Unknown Voltra Auth command.");
}

function panelComponents(panelId = null) {
  const suffix = panelId ? `:${panelId}` : "";
  return [
    {
      type: 1,
      components: [
        { type: 2, style: 3, label: "Redeem Key", custom_id: `eternal:redeem${suffix}`, emoji: { name: "🔑" } },
        { type: 2, style: 1, label: "Get Script", custom_id: `eternal:get_script${suffix}`, emoji: { name: "📜" } },
        { type: 2, style: 1, label: "Get Role", custom_id: `eternal:get_role${suffix}`, emoji: { name: "👤" } },
        { type: 2, style: 2, label: "Reset HWID", custom_id: `eternal:reset_hwid${suffix}`, emoji: { name: "⚙️" } },
        { type: 2, style: 2, label: "Get Stats", custom_id: `eternal:get_stats${suffix}`, emoji: { name: "📊" } },
      ],
    },
  ];
}

async function handleDiscordComponent(interaction, env, ctx) {
  const customId = interaction.data?.custom_id || "";
  const parts = customId.split(":");
  const action = parts[1] || "";
  const panelId = parts[2] || null;
  const guildId = interaction.guild_id;
  const userId = interactionUserId(interaction);
  if (!guildId || !userId) return discordMessage("This panel only works in a server.");
  const guild = await getGuild(env, guildId);
  if (!guild) return discordMessage("Voltra Auth is not configured in this server.");

  if (action === "setpanel_project") {
    const draftId = panelId;
    const selectedScriptId = cleanText(interaction.data?.values?.[0], 128);
    let draft = cacheGet(draftHotCache, draftId);
    if (!draft || draft.guild_id !== guildId || draft.created_by !== userId || Number(draft.expires_at) <= now()) {
      draft = await env.DB.prepare(
        "SELECT * FROM panel_drafts WHERE id = ? AND guild_id = ? AND created_by = ? AND expires_at > ? LIMIT 1"
      ).bind(draftId, guildId, userId, now()).first();
      if (draft) cachePut(draftHotCache, draftId, draft, 15 * 60_000);
    }
    if (!draft) return discordMessage("That /setpanel setup expired. Run `/setpanel` again.");

    let script = null;
    const cachedScripts = cacheGet(scriptHotCache, `${guildId}:enabled`);
    if (cachedScripts) script = cachedScripts.find((item) => item.id === selectedScriptId) || null;
    if (!script) {
      script = await env.DB.prepare(
        "SELECT * FROM scripts WHERE id = ? AND guild_id = ? AND enabled = 1 LIMIT 1"
      ).bind(selectedScriptId, guildId).first();
    }
    script = await ensureScriptLoaderId(env, script);
    if (!script) return discordMessage("That project is no longer available.");

    const loaderUrl = loaderUrlForScript(guild, script);
    if (!loaderUrl) return discordMessage("Voltra Auth could not build this project's loader URL.");
    const loaderTemplate = `script_key="{{KEY}}";\nloadstring(game:HttpGet(${JSON.stringify(loaderUrl)}))()`;
    draft.selected_script_id = script.id;
    draft.loader_template = loaderTemplate;
    cachePut(draftHotCache, draftId, draft, 15 * 60_000);
    // Persist for cross-isolate reliability, but cache makes the common next
    // modal submit avoid another D1 read.
    await env.DB.prepare(
      "UPDATE panel_drafts SET selected_script_id = ?, loader_template = ? WHERE id = ?"
    ).bind(script.id, loaderTemplate, draftId).run();

    const defaultTitle = `${script.name || "Voltra Auth"} Control Panel`.slice(0, 256);
    const defaultDescription = `This control panel is for the project: **${script.name || "Voltra Auth"}**\nIf you're a buyer, click on the buttons below to redeem your key, get the script or get your role`.slice(0, 4000);

    return json({
      type: 9,
      data: {
        custom_id: `eternal:setpanel_modal:${draftId}`,
        title: "[3/3] Specify the panel message",
        components: [
          { type: 1, components: [{ type: 4, custom_id: "embed_title", style: 1, label: "Title of the embed", value: defaultTitle, required: true, min_length: 1, max_length: 256 }] },
          { type: 1, components: [{ type: 4, custom_id: "embed_description", style: 2, label: "Description of the embed", value: defaultDescription, required: true, min_length: 1, max_length: 4000 }] },
          { type: 1, components: [{ type: 4, custom_id: "embed_color", style: 1, label: "Color of the embed (hex)", value: "#db9509", required: true, min_length: 4, max_length: 7 }] },
        ],
      },
    });
  }

  const panel = panelId ? await getPanel(env, guildId, panelId) : null;
  if (panelId && !panel) return discordMessage("This Voltra Auth panel has been disabled or removed.");
  const panelGuild = guildForPanel(guild, panel);

  if (action === "redeem") {
    return discordModal(`eternal:redeem_modal${panelId ? `:${panelId}` : ""}`, "Redeem Voltra Auth Key", "Redeem code", "ETERNAL-...");
  }
  if (action === "copy_script" || action === "mobile_copy_script") {
    const selectedScriptId = cleanText(parts[3], 128);
    const copyPanel = panelId && panelId !== "guild" ? await getPanel(env, guildId, panelId) : null;
    if (panelId && panelId !== "guild" && !copyPanel) {
      return discordMessage("This Voltra Auth panel has been disabled or removed.");
    }
    const copyGuild = guildForPanel(guild, copyPanel);
    return sendOwnScript(
      env,
      copyGuild,
      userId,
      interaction,
      selectedScriptId,
      copyPanel,
      false,
      action === "mobile_copy_script",
    );
  }
  if (action === "get_script") return sendOwnScript(env, panelGuild, userId, interaction, null, panel);
  if (action === "script_select") {
    const selectedScriptId = cleanText(interaction.data?.values?.[0], 128);
    return sendOwnScript(env, panelGuild, userId, interaction, selectedScriptId, panel);
  }
  if (action === "reset_hwid") return resetOwnHwid(env, panelGuild, userId, ctx);
  if (action === "get_role") {
    const license = await findLicenseForDiscord(env, guildId, userId);
    const valid = await validateLicense(env, license, null, false);
    if (!valid.ok) return discordMessage(valid.error);
    const ok = await addBuyerRole(env, panelGuild, userId);
    return discordMessage(ok ? "✅ Your buyer role has been restored." : "Your access is valid, but I could not assign this panel's buyer role.");
  }
  if (action === "get_stats") {
    const license = await findAnyLicenseForDiscord(env, guildId, userId);
    const valid = await validateLicense(env, license, null, false);
    if (!valid.ok) return discordMessage(valid.error);
    const execs = await env.DB.prepare(
      "SELECT COUNT(*) AS n FROM executions WHERE guild_id = ? AND license_id = ?"
    ).bind(guildId, license.id).first();
    return discordMessage(`📊 **Your Voltra Auth Stats**\nStatus: **${license.status || "active"}**\nExpires: **${license.auth_expire === -1 ? "Lifetime" : new Date(Number(license.auth_expire) * 1000).toLocaleString()}**\nHWID: **${license.hwid_hash ? "Linked" : "Not linked"}**\nExecutions: **${execs?.n || 0}**`);
  }
  return discordMessage("Unknown panel action.");
}

async function handleDiscordModalSubmit(interaction, env, ctx) {
  const guildId = interaction.guild_id;
  const userId = interactionUserId(interaction);
  if (!guildId || !userId) return discordMessage("This action only works in a server.");
  const guild = await getGuild(env, guildId);
  if (!guild) return discordMessage("Voltra Auth is not configured here.");

  const customId = interaction.data?.custom_id || "";
  const parts = customId.split(":");
  const action = parts[1] || "";
  const panelId = parts[2] || null;

  if (action === "setpanel_modal") {
    const draftId = panelId;
    let draft = cacheGet(draftHotCache, draftId);
    if (!draft || draft.guild_id !== guildId || draft.created_by !== userId || Number(draft.expires_at) <= now()) {
      draft = await env.DB.prepare(
        "SELECT * FROM panel_drafts WHERE id = ? AND guild_id = ? AND created_by = ? AND expires_at > ? LIMIT 1"
      ).bind(draftId, guildId, userId, now()).first();
      if (draft) cachePut(draftHotCache, draftId, draft, 15 * 60_000);
    }
    if (!draft) return discordMessage("That /setpanel setup expired. Run `/setpanel` again.");

    const fields = {};
    for (const row of interaction.data?.components || []) {
      for (const component of row.components || []) {
        if (component.custom_id) fields[component.custom_id] = component.value;
      }
    }

    const embedTitle = cleanText(fields.embed_title, 256);
    const embedDescription = cleanText(fields.embed_description, 4000);
    const rawColor = String(fields.embed_color || "").trim();
    if (!embedTitle || !embedDescription) return discordMessage("The panel title and description are required.");

    let hex = rawColor.replace(/^#/, "");
    if (/^[0-9a-f]{3}$/i.test(hex)) hex = hex.split("").map((c) => c + c).join("");
    if (!/^[0-9a-f]{6}$/i.test(hex)) return discordMessage("Use a valid hex color such as `#db9509`.");
    const embedColor = parseInt(hex, 16);

    let script = null;
    if (draft.selected_script_id) {
      const cachedScripts = cacheGet(scriptHotCache, `${guildId}:enabled`);
      if (cachedScripts) script = cachedScripts.find((item) => item.id === draft.selected_script_id) || null;
      if (!script) {
        script = await env.DB.prepare(
          "SELECT * FROM scripts WHERE id = ? AND guild_id = ? LIMIT 1"
        ).bind(draft.selected_script_id, guildId).first();
      }
    }
    if (!script) return discordMessage("The selected project is no longer available. Run `/setpanel` again.");

    const panelIdFinal = crypto.randomUUID();
    const timestamp = now();
    const auditDetails = JSON.stringify({
      channel_id: draft.channel_id || interaction.channel_id,
      project: script.name,
      script_id: script.id,
      manager_role_id: draft.manager_role_id,
      buyer_role_id: draft.buyer_role_id,
      embed_title: embedTitle,
      embed_color: `#${hex.toLowerCase()}`,
    }).slice(0, 4000);

    // One D1 round trip replaces four sequential ones. The panel record is
    // committed before the Discord message is posted so button clicks are safe
    // immediately after the message appears.
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO panels
          (id, guild_id, name, channel_id, manager_role_id, buyer_role_id, loader_template, active, created_by, created_at, updated_at, embed_title, embed_description, embed_color, script_id)
         VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?)`
      ).bind(
        panelIdFinal, guildId, script.name || "Voltra Auth",
        draft.channel_id || interaction.channel_id || null, draft.manager_role_id,
        draft.buyer_role_id, draft.loader_template, userId, timestamp, timestamp,
        embedTitle, embedDescription, embedColor, script.id,
      ),
      env.DB.prepare(
        "UPDATE guilds SET loader_template = ?, manager_role_id = ?, buyer_role_id = ?, updated_at = ? WHERE guild_id = ?"
      ).bind(draft.loader_template, draft.manager_role_id, draft.buyer_role_id, timestamp, guildId),
      env.DB.prepare("DELETE FROM panel_drafts WHERE id = ?").bind(draftId),
      env.DB.prepare(
        "INSERT INTO audit_logs (guild_id, action, actor_id, target, details, created_at) VALUES (?, ?, ?, ?, ?, ?)"
      ).bind(guildId, "discord.setpanel", userId, panelIdFinal, auditDetails, timestamp),
    ]);
    cachePut(panelHotCache, `${guildId}:${panelIdFinal}`, {
      id: panelIdFinal, guild_id: guildId, name: script.name || "Voltra Auth",
      channel_id: draft.channel_id || interaction.channel_id || null,
      manager_role_id: draft.manager_role_id, buyer_role_id: draft.buyer_role_id,
      loader_template: draft.loader_template, active: 1, created_by: userId,
      created_at: timestamp, updated_at: timestamp, embed_title: embedTitle,
      embed_description: embedDescription, embed_color: embedColor, script_id: script.id,
    });
    cacheDelete(draftHotCache, draftId);
    cacheDelete(guildHotCache, guildId);

    const user = interaction.member?.user || interaction.user || {};
    const sentBy = user.global_name || user.username || userId;
    let footerIcon;
    if (user.avatar) footerIcon = `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png?size=64`;

    const targetChannelId = draft.channel_id || interaction.channel_id || null;
    if (!targetChannelId) {
      return discordMessage("I could not determine which channel to send the panel to.");
    }

    const sentPanel = await discordApi(env, `/channels/${targetChannelId}/messages`, {
      method: "POST",
      body: JSON.stringify({
        embeds: [{
          title: embedTitle,
          description: embedDescription,
          color: embedColor,
          footer: { text: `Sent by ${sentBy}`, ...(footerIcon ? { icon_url: footerIcon } : {}) },
          timestamp: new Date(timestamp * 1000).toISOString(),
        }],
        components: panelComponents(panelIdFinal),
        allowed_mentions: { parse: [] },
      }),
    });

    if (!sentPanel?.id) {
      return discordMessage("The panel was saved, but I could not send the panel message in this channel.");
    }

    ctx.waitUntil(
      env.DB.prepare(
        "UPDATE panels SET message_id = ?, channel_id = ?, updated_at = ? WHERE id = ?"
      ).bind(sentPanel.id, targetChannelId, now(), panelIdFinal).run().catch(() => {})
    );

    return discordMessage(`✅ Panel created successfully.`, true);
  }

  const panel = panelId ? await getPanel(env, guildId, panelId) : null;
  if (panelId && !panel) return discordMessage("This Voltra Auth panel has been disabled or removed.");
  const panelGuild = guildForPanel(guild, panel);

  if (action === "redeem_modal") {
    const code = interaction.data.components?.[0]?.components?.[0]?.value;
    return redeemForDiscord(env, panelGuild, userId, cleanText(code, 128), ctx);
  }
  return discordMessage("Unknown modal action.");
}

async function redeemForDiscord(env, guild, userId, rawCode, ctx) {
  if (!rawCode) return discordMessage("Enter an Voltra Auth key.");
  if (await isBlacklisted(env, guild.guild_id, userId)) return discordMessage("You are blacklisted from this Voltra Auth project.");
  if (await findLicenseForDiscord(env, guild.guild_id, userId)) return discordMessage("You already have an active license.");

  // Luarmor-style redeem: an unclaimed stock key becomes linked to the Discord user.
  const stockLicense = await findLicenseByKey(env, rawCode);
  if (stockLicense && stockLicense.guild_id === guild.guild_id) {
    if (stockLicense.discord_id && stockLicense.discord_id !== userId) {
      return discordMessage("That key is already linked to another Discord user.");
    }
    const valid = await validateLicense(env, stockLicense, null, false);
    if (!valid.ok) return discordMessage(valid.error);
    await env.DB.prepare("UPDATE licenses SET discord_id = ?, updated_at = ? WHERE id = ?")
      .bind(userId, now(), stockLicense.id)
      .run();
    ctx.waitUntil(addBuyerRole(env, guild, userId));
    await audit(env, guild.guild_id, "discord.redeem_stock_key", userId, stockLicense.id, {});
    ctx.waitUntil(sendLog(env, guild, `🔑 <@${userId}> redeemed an Voltra Auth stock key.`));
    return discordMessage(`✅ Key linked successfully. Use **Get Script** or \`/script\` to receive your loader.`);
  }

  // Optional coupon-style codes are supported too.
  const codeHash = await sha256Hex(rawCode.toUpperCase());
  const code = await env.DB.prepare("SELECT * FROM redeem_codes WHERE guild_id = ? AND code_hash = ? LIMIT 1")
    .bind(guild.guild_id, codeHash)
    .first();
  if (!code || code.uses_left <= 0 || (code.expires_at !== -1 && code.expires_at <= now())) {
    return discordMessage("That Voltra Auth key is invalid or expired.");
  }

  const license = await createLicense(env, {
    guildId: guild.guild_id,
    discordId: userId,
    days: code.days,
    note: code.note || "Redeemed code",
  });

  if (code.uses_left <= 1) {
    await env.DB.prepare("DELETE FROM redeem_codes WHERE id = ?").bind(code.id).run();
  } else {
    await env.DB.prepare("UPDATE redeem_codes SET uses_left = uses_left - 1 WHERE id = ?").bind(code.id).run();
  }

  ctx.waitUntil(addBuyerRole(env, guild, userId));
  await audit(env, guild.guild_id, "discord.redeem_code", userId, code.id, { days: code.days });
  ctx.waitUntil(sendLog(env, guild, `🔑 <@${userId}> redeemed an Voltra Auth code.`));
  return discordMessage(`✅ Redeemed successfully. Your key is \`${license.key}\`. Use **Get Script** or \`/script\` for your loader.`);
}

async function resetOwnHwid(env, guild, userId, ctx) {
  const license = await findAnyLicenseForDiscord(env, guild.guild_id, userId);
  const valid = await validateLicense(env, license, null, false);
  if (!valid.ok) return discordMessage(valid.error);

  const cooldown = hwidCooldownSeconds(env);
  const last = Number(license.last_hwid_reset || 0);
  if (last && now() - last < cooldown) {
    const remaining = cooldown - (now() - last);
    return discordMessage(`HWID reset is on cooldown. Try again in ${Math.ceil(remaining)} second(s).`);
  }

  const resetAt = now();
  const reset = await env.DB.prepare("UPDATE licenses SET hwid_hash = NULL, last_hwid_reset = ?, updated_at = ? WHERE id = ? AND status = 'active' AND (last_hwid_reset IS NULL OR last_hwid_reset <= ?) AND NOT EXISTS (SELECT 1 FROM hwid_blacklists b WHERE b.guild_id = licenses.guild_id AND b.hwid_hash = licenses.hwid_hash)")
    .bind(resetAt, resetAt, license.id, resetAt - cooldown).run();
  if (!reset.meta?.changes) return discordMessage("HWID reset unavailable. Check your license or wait for the five-minute cooldown.");
  await audit(env, guild.guild_id, "discord.resethwid", userId, userId, {});
  ctx.waitUntil(sendLog(env, guild, `🔄 <@${userId}> reset their Voltra Auth HWID.`));
  return discordMessage("✅ HWID reset. Your next successful authentication will link the new device.");
}

function extractLoaderUrl(value) {
  const text = String(value || "").trim();
  // Prefer the URL inside HttpGet(...), but accept a bare Voltra Auth loader URL too.
  const httpGet = text.match(/HttpGet\s*\(\s*["'](https:\/\/[^"']+)["']\s*\)/i);
  if (httpGet?.[1]) return httpGet[1];
  const direct = text.match(/https:\/\/[^"')\s]+\/files\/v4\/loaders\/[a-f0-9]{32}\.lua(?:[?#][^"')\s]*)?/i);
  return direct?.[0] || null;
}

function pinnedLoaderIdFromTemplate(template) {
  const url = extractLoaderUrl(template);
  if (!url) return null;
  try {
    const match = new URL(url).pathname.match(/^\/files\/v4\/loaders\/([a-f0-9]{32})\.lua$/i);
    return match?.[1]?.toLowerCase() || null;
  } catch {
    return null;
  }
}

async function sendOwnScript(env, guild, userId, interaction, selectedScriptId = null, panel = null, includeCopyButton = true, mobileFormat = false) {
  const license = await findAnyLicenseForDiscord(env, guild.guild_id, userId);
  const valid = await validateLicense(env, license, null, false);
  if (!valid.ok) return discordMessage(valid.error);

  if (license.panel_id) {
    const assignedPanel = await getPanel(env, guild.guild_id, license.panel_id);
    if (!assignedPanel?.script_id) return discordMessage("Your assigned panel is disabled or no longer linked to a script.");
    if (panel && panel.id !== assignedPanel.id) return discordMessage("Your license is assigned to a different panel.");
    panel = assignedPanel;
    selectedScriptId = assignedPanel.script_id;
  }

  let scripts = await getScriptsForGuild(env, guild.guild_id, true);
  if (license.panel_id) scripts = scripts.filter((script) => script.id === selectedScriptId);
  if (!scripts.length) return discordMessage("There are no enabled Voltra Auth scripts in this project.");

  // A /setpanel loader pins that panel to one specific Voltra Auth script.
  // The guild-level template is the latest panel default, so /script also uses
  // that pinned loader instead of opening a selector when one is available.
  if (!selectedScriptId) {
    const pinnedLoaderId = pinnedLoaderIdFromTemplate(panel?.loader_template || guild.loader_template);
    if (pinnedLoaderId) {
      const pinnedScript = scripts.find((row) => String(row.loader_id || "").toLowerCase() === pinnedLoaderId);
      if (pinnedScript) selectedScriptId = pinnedScript.id;
    }
  }

  if (!selectedScriptId && scripts.length > 1) {
    const options = scripts.slice(0, 25).map((script) => ({
      label: String(script.name || "Voltra Auth Script").slice(0, 100),
      value: script.id,
      description: `Version ${String(script.version || "1.0.0").slice(0, 80)}`,
    }));
    return discordMessage("Select which script you want:", true, [{
      type: 1,
      components: [{
        type: 3,
        custom_id: `eternal:script_select${panel?.id ? `:${panel.id}` : ""}`,
        placeholder: "Select a script",
        min_values: 1,
        max_values: 1,
        options,
      }],
    }]);
  }

  const script = selectedScriptId
    ? scripts.find((row) => row.id === selectedScriptId)
    : scripts[0];
  if (!script) return discordMessage("That Voltra Auth script is unavailable or disabled.");

  const key = await deriveLicenseKey(env, license.id);
  const loaderUrl = loaderUrlForScript(guild, script);
  if (!loaderUrl) return discordMessage("Voltra Auth could not build this script's loader URL yet.");

  const cleanLoader = `script_key=${JSON.stringify(key)}\nloadstring(game:HttpGet(${JSON.stringify(loaderUrl)}))()`;
  const components = includeCopyButton ? [{
    type: 1,
    components: [
      {
        type: 2,
        style: 2,
        label: "Copy Script",
        custom_id: `eternal:copy_script:${panel?.id || "guild"}:${script.id}`,
        emoji: { name: "📋" },
      },
      {
        type: 2,
        style: 2,
        label: "Mobile Copy",
        custom_id: `eternal:mobile_copy_script:${panel?.id || "guild"}:${script.id}`,
        emoji: { name: "📱" },
      },
    ],
  }] : undefined;

  const content = mobileFormat
    ? `\`${cleanLoader.replace("\n", "; ")}\``
    : `\`\`\`lua
${cleanLoader}
\`\`\``;

  return discordMessage(content, true, components);
}

async function sendFfaScript(env, guild, requestedName = null) {
  const scripts = (await getScriptsForGuild(env, guild.guild_id, true)).filter((row) => !!row.ffa_enabled);
  if (!scripts.length) return discordMessage("There are no FFA scripts enabled in this project.");

  let script = null;
  if (requestedName) {
    const target = String(requestedName).trim().toLowerCase();
    script = scripts.find((row) => String(row.name || "").toLowerCase() === target) || null;
    if (!script) return discordMessage(`FFA script not found. Available: ${scripts.map((row) => `\`${row.name}\``).join(", ")}`);
  } else if (scripts.length === 1) {
    script = scripts[0];
  } else {
    return discordMessage(`Choose one with \`/ffa script:<name>\`. Available: ${scripts.map((row) => `\`${row.name}\``).join(", ")}`);
  }

  const loaderUrl = ffaLoaderUrlForScript(guild, script);
  if (!loaderUrl) return discordMessage("Voltra Auth could not build this FFA loader URL yet.");
  return discordMessage(`**${script.name}** • v${script.version} • FFA

No key is required:
\`\`\`lua
${ffaLauncher(loaderUrl)}
\`\`\``);
}


function defaultLoaderTemplate() {
  return `script_key = "{{KEY}}"\nloadstring(game:HttpGet("{{LOADER_URL}}"))()`;
}

// Authoritative Discord slash-command definitions used by the dashboard's
// "Sync commands" button. Keep in sync with scripts/register-commands.mjs.
function voltraAuthDiscordCommands() {
  const USER = 6, ROLE = 8, STRING = 3, INTEGER = 4, ATTACHMENT = 11;
  return [
    { name: "login", description: "Link Voltra Auth to this Discord server", options: [
      { name: "key", description: "One-time Voltra Auth server key created by the owner", type: STRING, required: true },
    ]},
    { name: "logout", description: "Log Voltra Auth out of this server" },
    { name: "setpanel", description: "Sends the control panel message in this channel", options: [
      { name: "loader_script", description: "Upload the loader script file used by this panel", type: ATTACHMENT, required: true },
      { name: "manager_role", description: "Role allowed to use manager commands", type: ROLE, required: true },
      { name: "buyer_role", description: "Role to give users after redeeming or being whitelisted", type: ROLE, required: true },
    ]},
    { name: "setlogs", description: "Set the Discord webhook used for Voltra Auth logs", options: [
      { name: "webhook", description: "Discord webhook URL, or 'off' to disable logs", type: STRING, required: true },
    ]},
    { name: "whitelist", description: "Whitelist a Discord user", options: [
      { name: "user", description: "User to whitelist", type: USER, required: true },
      { name: "panel", description: "Panel this license can access", type: STRING, required: true, autocomplete: true },
      { name: "days", description: "Days of access; omit for lifetime", type: INTEGER, required: false, min_value: 1 },
    ]},
    { name: "unwhitelist", description: "Remove a Discord user's Voltra Auth access", options: [
      { name: "user", description: "User to unwhitelist", type: USER, required: true },
      { name: "panel", description: "Panel to remove them from (choose All to wipe every panel)", type: STRING, required: true, autocomplete: true },
    ]},
    { name: "blacklist", description: "Blacklist a Discord user from the project", options: [
      { name: "user", description: "User to blacklist", type: USER, required: true },
      { name: "reason", description: "Reason shown to the user", type: STRING, required: false },
      { name: "days", description: "Blacklist duration; omit for indefinite", type: INTEGER, required: false, min_value: 1 },
    ]},
    { name: "compensate", description: "Add days to every non-lifetime key", options: [
      { name: "days", description: "Number of days to add", type: INTEGER, required: true, min_value: 1, max_value: 3650 },
    ]},
    { name: "force-resethwid", description: "Reset a user's HWID while ignoring the cooldown", options: [
      { name: "user", description: "User whose HWID should be reset", type: USER, required: true },
    ]},
    { name: "mass-whitelist", description: "Whitelist members who have a specific Discord role", options: [
      { name: "role", description: "Role whose members should be whitelisted", type: ROLE, required: true },
      { name: "days", description: "Days of access; omit for lifetime", type: INTEGER, required: false, min_value: 1 },
    ]},
    { name: "clean", description: "Clean the server of bannable members in batches of 50", default_member_permissions: null, contexts: [0], integration_types: [0] },
    { name: "redeem", description: "Redeem an unclaimed Voltra Auth key", options: [
      { name: "key", description: "Voltra Auth key", type: STRING, required: true },
    ]},
    { name: "resethwid", description: "Reset the HWID linked to your Voltra Auth key" },
    { name: "script", description: "Get your personal Voltra Auth loader" },
    { name: "ffa", description: "Get a keyless FFA loader when enabled", options: [
      { name: "script", description: "Script name; omit when only one FFA script is enabled", type: STRING, required: false },
    ]},
    { name: "getrole", description: "Restore your configured buyer role" },
    { name: "stats", description: "Show Voltra Auth project statistics" },
  ];
}

function buildLoader(template, key, guild, script = null) {
  const loaderUrl = script
    ? (loaderUrlForScript(guild, script) || `${String(guild?.base_url || "https://YOUR-WORKER.workers.dev").replace(/\/$/, "")}/files/v4/loaders/LOADER_ID.lua`)
    : (loaderUrlForGuild(guild) || `${String(guild?.base_url || "https://YOUR-WORKER.workers.dev").replace(/\/$/, "")}/files/v4/loaders/LOADER_ID.lua`);
  // Short, panel-style two-liner. HWID + credential handshake still happens
  // server-side inside the Lua returned by the loader URL.
  return `script_key=${JSON.stringify(key)}\nloadstring(game:HttpGet(${JSON.stringify(loaderUrl)}))()`;
}

async function discordApi(env, path, options = {}) {
  if (!env.DISCORD_BOT_TOKEN) return null;
  const headers = new Headers(options.headers || {});
  headers.set("authorization", `Bot ${env.DISCORD_BOT_TOKEN}`);
  if (options.body && !headers.has("content-type")) headers.set("content-type", "application/json");
  const response = await fetch(`https://discord.com/api/v10${path}`, { ...options, headers });
  if (!response.ok) {
    console.error("Discord API error", response.status, await response.text());
    return null;
  }
  if (response.status === 204) return true;
  return response.json();
}

async function addBuyerRole(env, guild, userId) {
  if (!guild?.buyer_role_id) return false;
  return !!(await discordApi(env, `/guilds/${guild.guild_id}/members/${userId}/roles/${guild.buyer_role_id}`, { method: "PUT" }));
}

async function removeBuyerRole(env, guild, userId) {
  if (!guild?.buyer_role_id) return false;
  return !!(await discordApi(env, `/guilds/${guild.guild_id}/members/${userId}/roles/${guild.buyer_role_id}`, { method: "DELETE" }));
}

async function dmLoader(env, guild, userId, key, origin, panel = null) {
  const dm = await discordApi(env, "/users/@me/channels", {
    method: "POST",
    body: JSON.stringify({ recipient_id: userId }),
  });
  if (!dm?.id) return false;

  let scripts = await getScriptsForGuild(env, guild.guild_id, true);
  if (panel?.script_id) scripts = scripts.filter((script) => script.id === panel.script_id);
  let content;
  if (scripts.length === 1) {
    const loader = buildLoader(guild.loader_template || defaultLoaderTemplate(), key, guild, scripts[0]);
    content = loader.length <= 1900
      ? `\`\`\`lua\n${loader}\n\`\`\``
      : `\`${key}\``;
  } else {
    content = `\`${key}\``;
  }

  return !!(await discordApi(env, `/channels/${dm.id}/messages`, {
    method: "POST",
    body: JSON.stringify({ content, allowed_mentions: { parse: [] } }),
  }));
}

async function sendLog(env, guild, message) {
  if (!guild?.log_webhook_enc) return false;
  try {
    const webhook = await decryptConfigSecret(env, guild.log_webhook_enc);
    const response = await fetch(webhook, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        username: "Voltra Auth",
        content: message,
        allowed_mentions: { parse: [] },
      }),
    });
    return response.ok;
  } catch (error) {
    console.error("Voltra Auth log webhook error", error);
    return false;
  }
}

async function fetchGuildMembersWithRole(env, guildId, roleId) {
  const out = [];
  let after = "0";
  for (let page = 0; page < 5; page++) {
    const query = new URLSearchParams({ limit: "1000", after });
    const members = await discordApi(env, `/guilds/${guildId}/members?${query.toString()}`, { method: "GET" });
    if (!Array.isArray(members)) break;
    for (const member of members) {
      if ((member.roles || []).includes(roleId)) out.push(member);
    }
    if (members.length < 1000) break;
    after = members[members.length - 1]?.user?.id || after;
  }
  return out;
}
