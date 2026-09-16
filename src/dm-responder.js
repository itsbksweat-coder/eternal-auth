const OWNER_ID = "1167590082878902435";
const BAN_CONFIRM_WINDOW_MS = 60_000;
const BULK_BAN_LIMIT = 200;

// No privileged MESSAGE_CONTENT intent is needed for direct messages to the bot.
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
    this.pendingBanAll = new Map();
  }

  async handle(message) {
    if (message.guild_id || message.author?.bot || message.webhook_id ||
        !/^\d+$/.test(message.author?.id || '') || !/^\d+$/.test(message.channel_id || '') ||
        ![0, 19].includes(message.type ?? 0)) return false;

    const now = this.clock();
    if (now < this.blockedUntil || this.pending >= 3) return false;

    const rawText = String(message.content || '').trim();
    const text = rawText.toLowerCase();
    const isOwner = message.author.id === OWNER_ID;
    const isBanAll = isOwner && /^\/?ban-?all(?:\s|$)/i.test(rawText);

    // Owner cleanup commands have their own confirmation guard, so don't make
    // the normal per-user 10-second DM cooldown get in the way of confirming.
    if (!isBanAll) {
      for (const [id, expiry] of this.recent) if (expiry <= now) this.recent.delete(id);
      if (this.recent.has(message.author.id)) return false;
      if (now - this.windowStart >= 60_000) { this.windowStart = now; this.windowCount = 0; }
      if (this.windowCount >= 20) return false;
      this.windowCount++;
      this.recent.set(message.author.id, now + 10_000);
    }

    this.pending++;
    try {
      if (isBanAll) {
        return await this.handleBanAll(message, rawText);
      }

      let content = 'Eternal Auth is online. Use your server’s Eternal Auth panel for Get Script, Redeem Key, Reset HWID, or Get Role. Send help, script, redeem, hwid, or status here for guidance.';
      if (/^(?:help|\/help)$/.test(text)) {
        content = 'Eternal Auth help:\n• Get Script: use /script in your linked server.\n• Redeem: use /redeem or Redeem Key on the panel.\n• Reset HWID: use /resethwid or Reset HWID.\n• Restore role: use /getrole or Get Role.\nLicense actions run in your linked server so the correct project is selected.';
        if (isOwner) {
          content += '\n\nOwner cleanup:\n• /banall <guild_id> — preview members\n• /banall <guild_id> confirm — confirm the preview and bulk-ban everyone the bot can, excluding you, the server owner, and the bot.';
        }
      }
      else if (/^(?:script|key|loader|\/script)$/.test(text)) content = 'Use /script or Get Script in your linked server. Eternal Auth will check your license and send your personal loader privately.';
      else if (/^(?:redeem|\/redeem)$/.test(text)) content = 'Use Redeem Key on your server’s Eternal Auth panel, or /redeem in that server. Enter your key in the modal or command field.';
      else if (/^(?:hwid|reset|resethwid|\/resethwid)$/.test(text)) content = 'Use Reset HWID on your server’s panel or /resethwid. Your project’s reset cooldown applies.';
      else if (/^(?:status|ping)$/.test(text)) content = 'Eternal Auth’s Discord connection is online and receiving DMs. This checks the bot connection only; license and database status are checked when you use your server’s panel.';

      return await this.sendMessage(message.channel_id, content);
    } catch (error) {
      this.lastError = String(error?.message || error || 'Discord DM request failed');
      return false;
    } finally {
      this.pending--;
    }
  }

  async handleBanAll(message, rawText) {
    if (message.author.id !== OWNER_ID) return false;

    const match = rawText.match(/^\/?ban-?all\s+(\d{5,25})(?:\s+(confirm))?\s*$/i);
    if (!match) {
      return this.sendMessage(message.channel_id, 'Usage: /banall <guild_id>\nThen: /banall <guild_id> confirm');
    }

    const guildId = match[1];
    const confirming = !!match[2];
    const now = this.clock();

    if (!confirming) {
      const preview = await this.getBanAllTargets(guildId, message.author.id);
      if (!preview.ok) return this.sendMessage(message.channel_id, preview.error);

      this.pendingBanAll.set(guildId, {
        expiresAt: now + BAN_CONFIRM_WINDOW_MS,
        userIds: preview.userIds,
        guildName: preview.guildName,
      });

      return this.sendMessage(
        message.channel_id,
        `⚠️ Server cleanup preview for **${preview.guildName}**: ${preview.userIds.length} member(s) will be submitted for banning.\n` +
        `Your account, the server owner, and Eternal Auth are excluded. Discord will refuse anyone above the bot in the role hierarchy.\n\n` +
        `To continue within 60 seconds, send:\n/banall ${guildId} confirm`
      );
    }

    const pending = this.pendingBanAll.get(guildId);
    this.pendingBanAll.delete(guildId);
    if (!pending || pending.expiresAt <= now) {
      return this.sendMessage(message.channel_id, `That cleanup preview expired. Send /banall ${guildId} again first.`);
    }

    if (!pending.userIds.length) {
      return this.sendMessage(message.channel_id, `No eligible members were found in **${pending.guildName}**.`);
    }

    let banned = 0;
    let failed = 0;

    for (let i = 0; i < pending.userIds.length; i += BULK_BAN_LIMIT) {
      const batch = pending.userIds.slice(i, i + BULK_BAN_LIMIT);
      const response = await this.discordApi(`/guilds/${guildId}/bulk-ban`, {
        method: 'POST',
        headers: { 'x-audit-log-reason': 'Eternal Auth owner server cleanup' },
        body: JSON.stringify({
          user_ids: batch,
          delete_message_seconds: 0,
        }),
      });

      const data = await response.json().catch(() => ({}));
      if (!response.ok) {
        const detail = data?.message ? `: ${data.message}` : '';
        return this.sendMessage(
          message.channel_id,
          `Cleanup stopped after ${banned} successful ban(s). Discord returned HTTP ${response.status}${detail}. ` +
          `Make sure Eternal Auth has Ban Members + Manage Server and that Server Members Intent is enabled.`
        );
      }

      banned += Array.isArray(data.banned_users) ? data.banned_users.length : 0;
      failed += Array.isArray(data.failed_users) ? data.failed_users.length : 0;
    }

    return this.sendMessage(
      message.channel_id,
      `✅ Cleanup finished for **${pending.guildName}**. Banned: ${banned}. Could not ban/already banned: ${failed}.`
    );
  }

  async getBanAllTargets(guildId, callerId) {
    const [guildResponse, meResponse] = await Promise.all([
      this.discordApi(`/guilds/${guildId}`),
      this.discordApi('/users/@me'),
    ]);

    if (!guildResponse.ok) {
      return { ok: false, error: `I couldn't access that server (Discord HTTP ${guildResponse.status}).` };
    }
    if (!meResponse.ok) {
      return { ok: false, error: `I couldn't read Eternal Auth's bot account (Discord HTTP ${meResponse.status}).` };
    }

    const guild = await guildResponse.json();
    const botUser = await meResponse.json();
    const excluded = new Set([callerId, guild.owner_id, botUser.id].filter(Boolean));
    const userIds = [];

    let after = '0';
    while (true) {
      const response = await this.discordApi(`/guilds/${guildId}/members?limit=1000&after=${encodeURIComponent(after)}`);
      if (!response.ok) {
        const data = await response.json().catch(() => ({}));
        const detail = data?.message ? `: ${data.message}` : '';
        return {
          ok: false,
          error: `I couldn't list server members (Discord HTTP ${response.status}${detail}). Enable Server Members Intent for Eternal Auth and try again.`,
        };
      }

      const members = await response.json();
      if (!Array.isArray(members) || members.length === 0) break;

      for (const member of members) {
        const id = member?.user?.id;
        if (id && !excluded.has(id)) userIds.push(id);
      }

      if (members.length < 1000) break;
      const lastId = members[members.length - 1]?.user?.id;
      if (!lastId || lastId === after) break;
      after = lastId;
    }

    return {
      ok: true,
      guildName: String(guild.name || guildId),
      userIds: [...new Set(userIds)],
    };
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
