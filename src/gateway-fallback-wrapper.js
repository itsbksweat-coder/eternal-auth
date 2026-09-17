import prefixWorker, { EternalGateway as PrefixEternalGateway } from "./prefix-massban-wrapper.js";

export class EternalGateway extends PrefixEternalGateway {
  constructor(ctx, env) {
    super(ctx, env);
    this.messageContentIntentEnabled = true;
    this.messageContentFallback = false;
    this.messageContentWarning = null;
  }

  async fetch(request) {
    const url = new URL(request.url);

    // When the dashboard manually reconnects the bot, try Message Content again.
    // This lets `.b` start working immediately after the intent is enabled in
    // Discord's Developer Portal without requiring another code deployment.
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
    // The bot stays online and slash/dashboard commands keep working, but
    // Discord will not expose ordinary guild message text, so `.b` is disabled.
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
    // 4014 means Discord rejected one or more privileged intents. The only
    // privileged Gateway intent added for `.b` is MESSAGE_CONTENT, so fall back
    // once instead of letting the base Gateway mark itself permanently fatal.
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
      // Keep the reason visible on the dashboard even after the fallback
      // connection reaches READY and the base class clears lastError.
      last_error: this.messageContentWarning || data.last_error,
    };
  }
}

export default {
  async fetch(request, env, ctx) {
    return prefixWorker.fetch(request, env, ctx);
  },

  async scheduled(controller, env, ctx) {
    if (typeof prefixWorker.scheduled === "function") {
      return prefixWorker.scheduled(controller, env, ctx);
    }
  },
};
