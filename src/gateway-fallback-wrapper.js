import prefixWorker, { EternalGateway as PrefixEternalGateway } from "./prefix-clean-wrapper.js";

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export class EternalGateway extends PrefixEternalGateway {
  constructor(ctx, env) {
    super(ctx, env);
    this.messageContentIntentEnabled = true;
    this.messageContentFallback = false;
    this.messageContentWarning = null;
  }

  async fetch(request) {
    const url = new URL(request.url);

    // A manual reconnect always retries the full privileged-intent set.
    if (url.pathname === "/reconnect" && request.method === "POST") {
      this.messageContentIntentEnabled = true;
      this.messageContentFallback = false;
      this.messageContentWarning = null;
      this.fatal = false;
    }

    // Internal RPC: fixed-window rate limiter shared across the Worker.
    // All requests to the Worker come through one Durable Object instance
    // (idFromName("eternal-auth-primary-gateway")), so this is a single
    // counter per key, no cross-instance drift.
    if (url.pathname === "/rate-check" && request.method === "POST") {
      try {
        const body = await request.json();
        const kind = String(body?.kind || "");
        const identifier = String(body?.id || "");
        const limit = Math.max(1, Number(body?.limit || 5));
        const windowSeconds = Math.max(1, Number(body?.window || 60));
        if (!kind || !identifier) {
          return new Response(JSON.stringify({ ok: false, error: "kind and id required" }), {
            status: 400, headers: { "content-type": "application/json" },
          });
        }
        const storageKey = `rl:${kind}:${identifier}`;
        const nowSec = Math.floor(Date.now() / 1000);
        const windowStart = nowSec - (nowSec % windowSeconds);
        const current = await this.ctx.storage.get(storageKey);
        let count = 0;
        if (current && Number(current.window_start) === windowStart) {
          count = Number(current.count || 0);
        }
        count += 1;
        await this.ctx.storage.put(storageKey, { window_start: windowStart, count });
        const allowed = count <= limit;
        const retryAfter = allowed ? 0 : (windowStart + windowSeconds) - nowSec;
        return new Response(JSON.stringify({
          ok: true, allowed, remaining: Math.max(0, limit - count), retry_after: retryAfter,
        }), { headers: { "content-type": "application/json" } });
      } catch (error) {
        return new Response(JSON.stringify({ ok: false, error: String(error?.message || error) }), {
          status: 500, headers: { "content-type": "application/json" },
        });
      }
    }

    return super.fetch(request);
  }

  sendIdentify() {
    if (this.messageContentIntentEnabled) {
      return super.sendIdentify();
    }

    // Safe fallback: GUILDS + GUILD_MESSAGES + DIRECT_MESSAGES.
    this.sendGateway({
      op: 2,
      d: {
        token: this.env.DISCORD_BOT_TOKEN,
        intents: 1 | (1 << 9) | (1 << 12),
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

  handleGatewayClose(code, reason) {
    if (code === 4014 && this.messageContentIntentEnabled) {
      this.messageContentIntentEnabled = false;
      this.messageContentFallback = true;
      this.messageContentWarning =
        "Discord rejected Message Content Intent (Gateway 4014). Voltra Auth reconnected without it; `.b` is disabled until Message Content Intent is enabled and the Gateway is reconnected.";

      this.clearHeartbeat();
      this.clearReconnectTimer();
      this.clearSession();
      this.ready = false;
      this.awaitingHeartbeatAck = false;
      this.fatal = false;
      this.lastError = this.messageContentWarning;

      const old = this.ws;
      this.ws = null;
      try {
        if (old && (old.readyState === 0 || old.readyState === 1)) {
          old.close(4000, "Retry without Message Content Intent");
        }
      } catch {}

      this.scheduleReconnect(1000);
      return;
    }

    return super.handleGatewayClose(code, reason);
  }

  status() {
    const data = super.status();
    return {
      ...data,
      prefix_b_enabled: !!data.gateway_ready && !this.messageContentFallback,
      prefix_b_fallback: this.messageContentFallback,
      prefix_b_warning: this.messageContentWarning,
      last_error: this.messageContentWarning || data.last_error,
    };
  }
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // The Overview button calls /api/admin/gateway/wake. Let the normal
    // authenticated handler run first, then force the Durable Object to drop
    // any old fallback session and reconnect with the full privileged intents.
    if (url.pathname === "/api/admin/gateway/wake" && request.method === "POST") {
      const wakeResponse = await prefixWorker.fetch(request, env, ctx);
      if (!wakeResponse.ok) return wakeResponse;

      try {
        const id = env.GATEWAY.idFromName("eternal-auth-primary-gateway");
        const gateway = env.GATEWAY.get(id);
        await gateway.fetch("https://gateway.internal/reconnect", { method: "POST" });

        await sleep(1200);
        const statusRequest = new Request(new URL("/api/admin/gateway/status", request.url).toString(), {
          method: "GET",
          headers: request.headers,
        });
        return prefixWorker.fetch(statusRequest, env, ctx);
      } catch (error) {
        console.error("Could not force full-intent Gateway reconnect", error);
        return wakeResponse;
      }
    }

    return prefixWorker.fetch(request, env, ctx);
  },

  async scheduled(controller, env, ctx) {
    if (typeof prefixWorker.scheduled === "function") {
      return prefixWorker.scheduled(controller, env, ctx);
    }
  },
};
