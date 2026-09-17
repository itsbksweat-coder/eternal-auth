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
          browser: "Eternal Auth",
          device: "Eternal Auth",
        },
        presence: {
          since: null,
          activities: [{ name: "Eternal Auth", type: 3 }],
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
        "Discord rejected Message Content Intent (Gateway 4014). Eternal Auth reconnected without it; `.b` is disabled until Message Content Intent is enabled and the Gateway is reconnected.";

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
