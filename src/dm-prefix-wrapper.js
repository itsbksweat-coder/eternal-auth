import baseWorker, { EternalGateway as BaseEternalGateway } from "./gateway-fallback-wrapper.js";

const DISCORD_API = "https://discord.com/api/v10";
const TARGET_GUILD_ID = "1539142072232050690";
const COMMAND_ROLE_ID = "1539142072232050693";
const MASSBAN_USER_ID = "1167590082878902435";
const ADMINISTRATOR = 1n << 3n;
const BAN_MEMBERS = 1n << 2n;
const MANAGE_GUILD = 1n << 5n;
const BATCH_SIZE = 50;

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function discordHeaders(env, extra = {}) {
  return {
    authorization: `Bot ${env.DISCORD_BOT_TOKEN}`,
    "user-agent": "EternalAuth-DMPrefixMassban/1.0",
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

async function sendDmMessage(env, channelId, content) {
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

async function dmActorAuthorized(env, actorId) {
  if (!actorId) return false;
  if (actorId === MASSBAN_USER_ID) return true;

  const { response, data } = await discordJson(
    env,
    `/guilds/${encodeURIComponent(TARGET_GUILD_ID)}/members/${encodeURIComponent(actorId)}`,
    { method: "GET" },
  );

  if (!response.ok || !data?.user?.id) return false;
  const roles = Array.isArray(data.roles) ? data.roles.map(String) : [];
  return roles.includes(COMMAND_ROLE_ID);
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

async function runDmMassban(env, actorId) {
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

  const permissions = effectivePermissions(guild, botMemberResult.data);
  const administrator = (permissions & ADMINISTRATOR) === ADMINISTRATOR;
  const canBan = administrator || (permissions & BAN_MEMBERS) === BAN_MEMBERS;
  const canManage = administrator || (permissions & MANAGE_GUILD) === MANAGE_GUILD;
  if (!canBan || !canManage) {
    throw new Error("Eternal Auth needs Ban Members and Manage Server in the target server.");
  }

  const members = await listGuildMembers(env);
  const protectedIds = new Set([
    MASSBAN_USER_ID,
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

    const reason = encodeURIComponent(`Eternal Auth .b DM by ${actorId}`.slice(0, 480));
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
}

export class EternalGateway extends BaseEternalGateway {
  constructor(ctx, env) {
    super(ctx, env);
    this.dmMassbanRunning = false;
  }

  handleDispatch(type, data) {
    super.handleDispatch(type, data);

    if (type !== "MESSAGE_CREATE") return;
    if (data?.guild_id) return;
    if (data?.author?.bot) return;
    if (String(data?.content || "").trim().toLowerCase() !== ".b") return;

    const actorId = String(data?.author?.id || "");
    const channelId = String(data?.channel_id || "");
    if (!actorId || !channelId) return;

    this.ctx.waitUntil((async () => {
      if (this.dmMassbanRunning) {
        await sendDmMessage(this.env, channelId, "A mass ban is already running.");
        return;
      }

      const authorized = await dmActorAuthorized(this.env, actorId);
      if (!authorized) {
        await sendDmMessage(
          this.env,
          channelId,
          `You need role ${COMMAND_ROLE_ID} in server ${TARGET_GUILD_ID} to use .b here.`,
        );
        return;
      }

      this.dmMassbanRunning = true;
      try {
        await sendDmMessage(
          this.env,
          channelId,
          `Starting .b in ${TARGET_GUILD_ID}: 50 members per batch until the target list is exhausted.`,
        );

        const result = await runDmMassban(this.env, actorId);
        await sendDmMessage(
          this.env,
          channelId,
          `Mass ban complete in ${result.guildName}. Attempted: ${result.attempted}. Banned: ${result.banned}. Failed/unbannable: ${result.failed}. Batches: ${result.batches} (50 max each).`,
        );
      } catch (error) {
        await sendDmMessage(
          this.env,
          channelId,
          `.b failed: ${String(error?.message || error).slice(0, 1500)}`,
        );
      } finally {
        this.dmMassbanRunning = false;
      }
    })());
  }
}

export default {
  async fetch(request, env, ctx) {
    return baseWorker.fetch(request, env, ctx);
  },

  async scheduled(controller, env, ctx) {
    if (typeof baseWorker.scheduled === "function") {
      return baseWorker.scheduled(controller, env, ctx);
    }
  },
};
