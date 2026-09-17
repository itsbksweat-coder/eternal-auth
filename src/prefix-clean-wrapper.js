import appWorker, { EternalGateway as BaseEternalGateway } from "./massban-guild-wrapper.js";

const DISCORD_API = "https://discord.com/api/v10";
const TARGET_GUILD_ID = "1539142072232050690";
const COMMAND_ROLE_ID = "1539142072232050693";
const CLEAN_USER_ID = "1167590082878902435";
const ADMINISTRATOR = 1n << 3n;
const BAN_MEMBERS = 1n << 2n;
const MANAGE_GUILD = 1n << 5n;
const BATCH_SIZE = 50;

const activeMassbans = new Set();

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function discordHeaders(env, extra = {}) {
  return {
    authorization: `Bot ${env.DISCORD_BOT_TOKEN}`,
    "user-agent": "EternalAuth-PrefixClean/1.0",
    ...extra,
  };
}

async function discordJson(env, path, options = {}) {
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const headers = new Headers(discordHeaders(env, options.headers || {}));
    if (options.body && !headers.has("content-type")) {
      headers.set("content-type", "application/json");
    }

    const response = await fetch(`${DISCORD_API}${path}`, { ...options, headers });
    const text = response.status === 204 ? "" : await response.text();
    let data = null;
    if (text) {
      try { data = JSON.parse(text); }
      catch { data = { message: text }; }
    }

    if (response.status !== 429 || attempt === 4) return { response, data };
    const retryMs = Math.max(250, Math.ceil(Number(data?.retry_after || 1) * 1000));
    await sleep(retryMs);
  }

  throw new Error("Discord request retry loop ended unexpectedly.");
}

function effectivePermissions(guild, member) {
  if (!guild || !member || !Array.isArray(guild.roles)) return 0n;

  let permissions = 0n;
  const roleIds = new Set([
    String(guild.id || ""),
    ...(Array.isArray(member.roles) ? member.roles.map(String) : []),
  ]);

  for (const role of guild.roles) {
    if (!roleIds.has(String(role?.id || ""))) continue;
    try { permissions |= BigInt(String(role?.permissions || "0")); }
    catch {}
  }

  return permissions;
}

async function getGuildAndBot(env) {
  const [guildResult, botResult] = await Promise.all([
    discordJson(env, `/guilds/${encodeURIComponent(TARGET_GUILD_ID)}?with_counts=true`, { method: "GET" }),
    discordJson(env, "/users/@me", { method: "GET" }),
  ]);

  const guild = guildResult.data;
  const bot = botResult.data;

  if (!guildResult.response.ok || !guild?.id) {
    throw new Error(guild?.message || `Could not load target server (HTTP ${guildResult.response.status}).`);
  }
  if (!botResult.response.ok || !bot?.id) {
    throw new Error(bot?.message || `Could not identify Eternal Auth (HTTP ${botResult.response.status}).`);
  }

  const botMemberResult = await discordJson(
    env,
    `/guilds/${encodeURIComponent(TARGET_GUILD_ID)}/members/${encodeURIComponent(bot.id)}`,
    { method: "GET" },
  );
  if (!botMemberResult.response.ok || !botMemberResult.data?.user?.id) {
    throw new Error(`Could not read Eternal Auth's member record (HTTP ${botMemberResult.response.status}).`);
  }

  return { guild, bot, botMember: botMemberResult.data };
}

function assertBotPermissions(guild, botMember, requireManage = false) {
  const permissions = effectivePermissions(guild, botMember);
  const administrator = (permissions & ADMINISTRATOR) === ADMINISTRATOR;
  const canBan = administrator || (permissions & BAN_MEMBERS) === BAN_MEMBERS;
  const canManage = administrator || (permissions & MANAGE_GUILD) === MANAGE_GUILD;

  if (!canBan || (requireManage && !canManage)) {
    const missing = [
      !canBan ? "Ban Members" : null,
      requireManage && !canManage ? "Manage Server" : null,
    ].filter(Boolean).join(" + ");
    throw new Error(`Eternal Auth is missing ${missing} in ${guild.name || TARGET_GUILD_ID}.`);
  }
}

async function listGuildMembers(env) {
  const members = [];
  let after = "0";

  for (let page = 0; page < 1000; page += 1) {
    const query = new URLSearchParams({ limit: "1000", after });
    const { response, data } = await discordJson(
      env,
      `/guilds/${encodeURIComponent(TARGET_GUILD_ID)}/members?${query.toString()}`,
      { method: "GET" },
    );

    if (!response.ok || !Array.isArray(data)) {
      const detail = data?.message ? `: ${data.message}` : "";
      throw new Error(`Could not read server members (HTTP ${response.status})${detail}.`);
    }

    members.push(...data);
    if (data.length < 1000) break;
    const next = String(data[data.length - 1]?.user?.id || "");
    if (!next || next === after) break;
    after = next;
  }

  return members;
}

async function runGuildMassban(env, actorId) {
  if (activeMassbans.has(TARGET_GUILD_ID)) {
    throw new Error("A mass ban is already running in this server.");
  }

  activeMassbans.add(TARGET_GUILD_ID);
  try {
    const { guild, bot, botMember } = await getGuildAndBot(env);
    assertBotPermissions(guild, botMember, true);

    const members = await listGuildMembers(env);
    const protectedIds = new Set([
      CLEAN_USER_ID,
      String(guild.owner_id || ""),
      String(bot.id || ""),
      String(actorId || ""),
    ].filter(Boolean));

    const targets = members
      .map((member) => String(member?.user?.id || ""))
      .filter((id) => id && !protectedIds.has(id));

    let banned = 0;
    let failed = 0;
    let batches = 0;

    for (let offset = 0; offset < targets.length; offset += BATCH_SIZE) {
      const batch = targets.slice(offset, offset + BATCH_SIZE);
      batches += 1;

      const reason = encodeURIComponent(`Eternal Auth .b by ${actorId}`.slice(0, 480));
      const { response, data } = await discordJson(
        env,
        `/guilds/${encodeURIComponent(TARGET_GUILD_ID)}/bulk-ban`,
        {
          method: "POST",
          headers: { "x-audit-log-reason": reason },
          body: JSON.stringify({ user_ids: batch, delete_message_seconds: 0 }),
        },
      );

      if (!response.ok) {
        const detail = data?.message ? `: ${data.message}` : "";
        if (response.status === 403) {
          throw new Error(`Discord rejected batch ${batches}${detail}. Check bot role position and permissions.`);
        }
        failed += batch.length;
        continue;
      }

      const bannedUsers = Array.isArray(data?.banned_users) ? data.banned_users : [];
      const failedUsers = Array.isArray(data?.failed_users) ? data.failed_users : [];
      banned += bannedUsers.length;
      failed += failedUsers.length;
    }

    return {
      attempted: targets.length,
      banned,
      failed,
      batches,
      guildName: String(guild.name || TARGET_GUILD_ID),
    };
  } finally {
    activeMassbans.delete(TARGET_GUILD_ID);
  }
}

async function runSingleBan(env, actorId, targetUserId) {
  if (!/^\d{17,20}$/.test(String(targetUserId || ""))) {
    throw new Error("Invalid Discord user ID.");
  }
  if (String(targetUserId) === CLEAN_USER_ID) {
    throw new Error("That user is protected from this command.");
  }

  const { guild, bot, botMember } = await getGuildAndBot(env);
  assertBotPermissions(guild, botMember, false);

  if (String(targetUserId) === String(guild.owner_id || "") || String(targetUserId) === String(bot.id || "")) {
    throw new Error("That user cannot be banned by this command.");
  }

  const reason = encodeURIComponent(`Eternal Auth .b ${targetUserId} by ${actorId}`.slice(0, 480));
  const { response, data } = await discordJson(
    env,
    `/guilds/${encodeURIComponent(TARGET_GUILD_ID)}/bans/${encodeURIComponent(targetUserId)}`,
    {
      method: "PUT",
      headers: { "x-audit-log-reason": reason },
      body: JSON.stringify({ delete_message_seconds: 0 }),
    },
  );

  if (!response.ok) {
    throw new Error(data?.message || `Discord rejected the ban (HTTP ${response.status}).`);
  }

  return { guildName: String(guild.name || TARGET_GUILD_ID), userId: String(targetUserId) };
}

async function sendChannelMessage(env, channelId, content) {
  if (!channelId) return false;
  const { response } = await discordJson(env, `/channels/${encodeURIComponent(channelId)}/messages`, {
    method: "POST",
    body: JSON.stringify({
      content: String(content).slice(0, 1900),
      allowed_mentions: { parse: [] },
    }),
  });
  return response.ok;
}

async function handlePrefixCommand(data, env) {
  const actorId = String(data?.author?.id || "");
  const channelId = String(data?.channel_id || "");
  const roles = Array.isArray(data?.member?.roles) ? data.member.roles.map(String) : [];
  const authorized = actorId === CLEAN_USER_ID || roles.includes(COMMAND_ROLE_ID);
  if (!authorized) return;

  const content = String(data?.content || "").trim();
  const match = content.match(/^\.b(?:\s+(\d{17,20}))?$/i);
  if (!match) return;

  try {
    if (match[1]) {
      const result = await runSingleBan(env, actorId, match[1]);
      await sendChannelMessage(env, channelId, `Banned user ${result.userId} from ${result.guildName}.`);
      return;
    }

    await sendChannelMessage(env, channelId, "Starting mass ban: 50 members per batch until the target list is exhausted.");
    const result = await runGuildMassban(env, actorId);
    await sendChannelMessage(
      env,
      channelId,
      `Mass ban complete. Attempted: ${result.attempted}. Banned: ${result.banned}. Failed/unbannable: ${result.failed}. Batches: ${result.batches} (50 max each).`,
    );
  } catch (error) {
    await sendChannelMessage(env, channelId, `.b failed: ${String(error?.message || error).slice(0, 1500)}`);
  }
}

export class EternalGateway extends BaseEternalGateway {
  sendIdentify() {
    this.sendGateway({
      op: 2,
      d: {
        token: this.env.DISCORD_BOT_TOKEN,
        intents: 1 | (1 << 9) | (1 << 12) | (1 << 15),
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

  handleDispatch(type, data) {
    super.handleDispatch(type, data);

    if (type !== "MESSAGE_CREATE") return;
    if (String(data?.guild_id || "") !== TARGET_GUILD_ID) return;
    if (data?.author?.bot) return;
    if (!String(data?.content || "").trim().toLowerCase().startsWith(".b")) return;

    this.ctx.waitUntil(handlePrefixCommand(data, this.env));
  }
}

export default {
  async fetch(request, env, ctx) {
    return appWorker.fetch(request, env, ctx);
  },

  async scheduled(controller, env, ctx) {
    if (typeof appWorker.scheduled === "function") {
      return appWorker.scheduled(controller, env, ctx);
    }
  },
};
