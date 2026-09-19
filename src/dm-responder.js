const OWNER_ID = "1167590082878902435";
// Direct-message command responder for Eternal Auth.
export class DmResponder {
  constructor(env, request = fetch, clock = Date.now) {
    this.env = env;
    this.request = request;
    this.clock = clock;
    this.recent = new Map();
    this.sent = 0;
    this.lastError = null;
    this.blockedUntil = 0;
    this.pending = 0;
    this.windowStart = 0;
    this.windowCount = 0;
  }

  async handle(message) {
    if (message.guild_id || message.author?.bot || message.webhook_id ||
        !/^\d+$/.test(message.author?.id || '') || !/^\d+$/.test(message.channel_id || '') ||
        ![0, 19].includes(message.type ?? 0)) return false;

    const now = this.clock();
    if (now < this.blockedUntil || this.pending >= 3) return false;

    const rawText = String(message.content || '').trim();
    const text = rawText.toLowerCase();
    for (const [id, expiry] of this.recent) if (expiry <= now) this.recent.delete(id);
    if (this.recent.has(message.author.id)) return false;
    if (now - this.windowStart >= 60_000) { this.windowStart = now; this.windowCount = 0; }
    if (this.windowCount >= 20) return false;
    this.windowCount++;
    this.recent.set(message.author.id, now + 10_000);

    this.pending++;
    try {
      let content = 'Eternal Auth is online. Use your server’s Eternal Auth panel for Get Script, Redeem Key, Reset HWID, or Get Role. Send help, script, redeem, hwid, or status here for guidance.';
      if (/^(?:help|\/help)$/.test(text)) {
        content = 'Eternal Auth help:\n• Get Script: use /script in your linked server.\n• Redeem: use /redeem or Redeem Key on the panel.\n• Reset HWID: use /resethwid or Reset HWID.\n• Restore role: use /getrole or Get Role.\nLicense actions run in your linked server so the correct project is selected.';
      }
      else if (/^(?:script|key|loader|\/script)$/.test(text)) content = 'Use /script or Get Script in your linked server. Eternal Auth will check your license and send your personal loader privately.';
      else if (/^(?:redeem|\/redeem)$/.test(text)) content = 'Use Redeem Key on your server’s Eternal Auth panel, or /redeem in that server. Enter your key in the modal or command field.';
      else if (/^(?:hwid|reset|resethwid|\/resethwid)$/.test(text)) content = 'Use Reset HWID on your server’s panel or /resethwid. Your project’s reset cooldown applies.';
      else if (/^(?:status|ping)$/.test(text)) content = 'Eternal Auth’s Discord connection is online and receiving DMs. This checks the bot connection only; license and database status are checked when you use your server’s panel.';

      return await this.sendMessage(message.channel_id, content);
    } catch {
      this.lastError = 'Discord DM request failed';
      return false;
    } finally {
      this.pending--;
    }
  }

  async discordApi(path, options = {}) {
    const headers = new Headers(options.headers || {});
    headers.set('authorization', `Bot ${this.env.DISCORD_BOT_TOKEN}`);
    if (options.body && !headers.has('content-type')) headers.set('content-type', 'application/json');

    return this.request(`https://discord.com/api/v10${path}`, {
      ...options,
      headers,
      signal: options.signal || AbortSignal.timeout(15_000),
    });
  }

  async sendMessage(channelId, content) {
    const response = await this.request(`https://discord.com/api/v10/channels/${channelId}/messages`, {
      method: 'POST',
      headers: { authorization: `Bot ${this.env.DISCORD_BOT_TOKEN}`, 'content-type': 'application/json' },
      body: JSON.stringify({ content, allowed_mentions: { parse: [] } }),
      signal: AbortSignal.timeout(10_000),
    });

    if (response.status === 429) {
      const data = await response.json().catch(() => ({}));
      const seconds = Number(data.retry_after);
      this.blockedUntil = this.clock() + (Number.isFinite(seconds) && seconds > 0 ? seconds * 1000 : 60_000);
    }

    if (!response.ok) {
      this.lastError = `Discord DM HTTP ${response.status}`;
      return false;
    }

    this.sent++;
    this.lastError = null;
    return true;
  }
}
