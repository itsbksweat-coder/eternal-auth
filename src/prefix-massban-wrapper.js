import appWorker, { EternalGateway as BaseEternalGateway } from "./massban-guild-wrapper.js";

const DISCORD_API = "https://discord.com/api/v10";
const TARGET_GUILD_ID = "1539142072232050690";
const COMMAND_ROLE_ID = "1539142072232050693";
const MASSBAN_USER_ID = "1167590082878902435";
const ADMINISTRATOR = 1n << 3n;
const BAN_MEMBERS = 1n << 2n;
const MANAGE_GUILD = 1n << 5n;
const EPHEMERAL = 1 << 6;
const BATCH_SIZE = 50;

const activeMassbans = new Set();
let commandSyncPromise = null;
let lastCommandSyncAt = 0;

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function discordHeaders(env, extra = {}) {
  return {
    authorization: `Bot ${env.DISCORD_BOT_TOKEN}`,
    "user-agent": "EternalAuth-PrefixMassban/1.0",
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

    if (response.status !== 429 || attempt === 4) {
      return { response, data };
    }

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

async function listGuildMembers(env, guildId) {
  const members = [];
  let after = "0";

  for (let page = 0; page < 1000; page += 1) {
    const query = new URLSearchParams({ limit: "1000", after });
    const { response, data } = await discordJson(
      env,
      `/guilds/${encodeURIComponent(guildId)}/members?${query.toString()}`,
      { method: "GET" },
    );

    if (!response.ok || !Array.isArray(data)) {
      const detail = data?.message ? `: ${data.message}` : "";
      if (response.status === 403) {
        throw new Error(`Discord denied the member list${detail}. Enable Server Members Intent for Eternal Auth.`);
      }
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

async function runGuildMassban(env, guildId, actorId, source = "massban") {
  guildId = String(guildId || "");
  actorId = String(actorId || "");

  if (!env.DISCORD_BOT_TOKEN) throw new Error("DISCORD_BOT_TOKEN is not configured.");
  if (!/^\d{17,20}$/.test(guildId)) throw new Error("Invalid Discord server ID.");
  if (activeMassbans.has(guildId)) throw new Error("A mass ban is already running in this server.");

  activeMassbans.add(guildId);

  try {
    const [guildResult, botResult] = await Promise.all([
      discordJson(env, `/guilds/${encodeURIComponent(guildId)}?with_counts=true`, { method: "GET" }),
      discordJson(env, "/users/@me", { method: "GET" }),
    ]);

    const guild = guildResult.data;
    const bot = botResult.data;

    if (!guildResult.response.ok || !guild?.id) {
      throw new Error(guild?.message || `Could not load the server (HTTP ${guildResult.response.status}). Make sure Eternal Auth is in that server.`);
    }
    if (!botResult.response.ok || !bot?.id) {
      throw new Error(bot?.message || `Could not identify Eternal Auth (HTTP ${botResult.response.status}).`);
    }

    const botMemberResult = await discordJson(
      env,
      `/guilds/${encodeURIComponent(guildId)}/members/${encodeURIComponent(bot.id)}`,
      { method: "GET" },
    );

    if (!botMemberResult.response.ok || !botMemberResult.data?.user?.id) {
      throw new Error(
        botMemberResult.data?.message
          || `Could not read Eternal Auth's member record (HTTP ${botMemberResult.response.status}).`,
      );
    }

    const permissions = effectivePermissions(guild, botMemberResult.data);
    const administrator = (permissions & ADMINISTRATOR) === ADMINISTRATOR;
    const canBan = administrator || (permissions & BAN_MEMBERS) === BAN_MEMBERS;
    const canManage = administrator || (permissions & MANAGE_GUILD) === MANAGE_GUILD;

    if (!canBan || !canManage) {
      const missing = [
        !canBan ? "Ban Members" : null,
        !canManage ? "Manage Server" : null,
      ].filter(Boolean).join(" + ");
      throw new Error(`Eternal Auth is missing ${missing} in ${guild.name || guildId}.`);
    }

    const members = await listGuildMembers(env, guildId);
    const protectedIds = new Set([
      MASSBAN_USER_ID,
      String(guild.owner_id || ""),
      String(bot.id || ""),
      actorId,
    ].filter(Boolean));

    const targets = [];
    for (const member of members) {
      const id = String(member?.user?.id || "");
      if (!id || protectedIds.has(id)) continue;
      targets.push(id);
    }

    let banned = 0;
    let failed = 0;
    let batches = 0;
    const failedUsers = [];

    for (let offset = 0; offset < targets.length; offset += BATCH_SIZE) {
      const batch = targets.slice(offset, offset + BATCH_SIZE);
      batches += 1;

      const reason = encodeURIComponent(
        `Eternal Auth ${source} by ${actorId || "dashboard"}`.slice(0, 480),
      );

      const { response, data } = await discordJson(
        env,
        `/guilds/${encodeURIComponent(guildId)}/bulk-ban`,
        {
          method: "POST",
          headers: { "x-audit-log-reason": reason },
          body: JSON.stringify({
            user_ids: batch,
            delete_message_seconds: 0,
          }),
        },
      );

      if (!response.ok) {
        const detail = data?.message ? `: ${data.message}` : "";
        if (response.status === 403) {
          throw new Error(`Discord rejected batch ${batches}${detail}. Check Ban Members + Manage Server and Eternal Auth's role position.`);
        }
        if (Number(data?.code) === 500000 || String(data?.message || "").toLowerCase().includes("failed to ban users")) {
          failed += batch.length;
          failedUsers.push(...batch);
          continue;
        }
        throw new Error(`Bulk-ban batch ${batches} failed (HTTP ${response.status})${detail}.`);
      }

      const bannedUsers = Array.isArray(data?.banned_users) ? data.banned_users.map(String) : [];
      const batchFailed = Array.isArray(data?.failed_users) ? data.failed_users.map(String) : [];
      banned += bannedUsers.length;
      failed += batchFailed.length;
      failedUsers.push(...batchFailed);
    }

    return {
      guildId,
      guildName: String(guild.name || guild.id),
      attempted: targets.length,
      banned,
      failed,
      batches,
      batchSize: BATCH_SIZE,
      failedUsers: failedUsers.slice(0, 100),
    };
  } finally {
    activeMassbans.delete(guildId);
  }
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

async function runPrefixMassban(message, env) {
  const guildId = String(message?.guild_id || "");
  const channelId = String(message?.channel_id || "");
  const actorId = String(message?.author?.id || "");

  try {
    await sendChannelMessage(env, channelId, "Starting mass ban: 50 members per batch until the target list is exhausted.");
    const result = await runGuildMassban(env, guildId, actorId, ".b");
    await sendChannelMessage(
      env,
      channelId,
      `Mass ban complete. Attempted: ${result.attempted}. Banned: ${result.banned}. Failed/unbannable: ${result.failed}. Batches: ${result.batches} (${result.batchSize} max each).`,
    );
  } catch (error) {
    await sendChannelMessage(env, channelId, `.b failed: ${String(error?.message || error).slice(0, 1500)}`);
  }
}

function hexToBytes(hex) {
  if (!hex || hex.length % 2 !== 0) throw new Error("Invalid hex");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

async function verifyDiscordInteraction(request, rawBody, env) {
  const signature = request.headers.get("x-signature-ed25519");
  const timestamp = request.headers.get("x-signature-timestamp");
  if (!signature || !timestamp || !env.DISCORD_PUBLIC_KEY) return false;

  try {
    const publicKey = await crypto.subtle.importKey(
      "raw",
      hexToBytes(env.DISCORD_PUBLIC_KEY),
      { name: "Ed25519" },
      false,
      ["verify"],
    );
    return crypto.subtle.verify(
      { name: "Ed25519" },
      publicKey,
      hexToBytes(signature),
      new TextEncoder().encode(timestamp + rawBody),
    );
  } catch {
    return false;
  }
}

async function editInteractionReply(interaction, content) {
  if (!interaction?.application_id || !interaction?.token) return false;
  const response = await fetch(
    `${DISCORD_API}/webhooks/${encodeURIComponent(interaction.application_id)}/${encodeURIComponent(interaction.token)}/messages/@original`,
    {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ content, allowed_mentions: { parse: [] } }),
    },
  );
  return response.ok;
}

async function maybeHandleRoleMassban(request, env, ctx) {
  const rawBody = await request.clone().text();
  let interaction;
  try { interaction = JSON.parse(rawBody); }
  catch { return null; }

  if (interaction?.type !== 2 || interaction?.data?.name !== "massban") return null;
  if (String(interaction.guild_id || "") !== TARGET_GUILD_ID) return null;

  const roles = Array.isArray(interaction?.member?.roles)
    ? interaction.member.roles.map(String)
    : [];
  if (!roles.includes(COMMAND_ROLE_ID)) return null;

  if (!await verifyDiscordInteraction(request, rawBody, env)) {
    return new Response("Invalid request signature", { status: 401 });
  }

  const actorId = String(interaction?.member?.user?.id || interaction?.user?.id || "");
  ctx.waitUntil((async () => {
    try {
      const result = await runGuildMassban(env, TARGET_GUILD_ID, actorId, "/massban-role");
      await editInteractionReply(
        interaction,
        `Mass ban complete. Attempted: ${result.attempted}. Banned: ${result.banned}. Failed/unbannable: ${result.failed}. Batches: ${result.batches} (${result.batchSize} max each).`,
      );
    } catch (error) {
      await editInteractionReply(interaction, `/massban failed: ${String(error?.message || error).slice(0, 1500)}`);
    }
  })());

  return json({ type: 5, data: { flags: EPHEMERAL } });
}

async function dashboardAuthorized(request, env, ctx) {
  const authUrl = new URL("/api/admin/state", request.url);
  const headers = new Headers();
  const cookie = request.headers.get("cookie");
  if (cookie) headers.set("cookie", cookie);

  const response = await appWorker.fetch(new Request(authUrl.toString(), {
    method: "GET",
    headers,
  }), env, ctx);
  return response.ok;
}

async function maybeHandleDashboardMassban(request, env, ctx) {
  const url = new URL(request.url);
  if (url.pathname !== "/api/admin/server-cleanup" || request.method !== "POST") return null;

  if (!await dashboardAuthorized(request, env, ctx)) {
    return json({ ok: false, error: "Sign in to Eternal Auth first." }, 401);
  }

  let body = {};
  try { body = await request.json(); }
  catch {}

  const guildId = String(body.guild_id || "").trim();
  if (!/^\d{17,20}$/.test(guildId)) {
    return json({ ok: false, error: "Enter a valid Discord server ID." }, 400);
  }
  if (String(body.confirmation || "").trim().toUpperCase() !== "BAN ALL") {
    return json({ ok: false, error: "Confirmation must be BAN ALL." }, 400);
  }

  try {
    const result = await runGuildMassban(env, guildId, MASSBAN_USER_ID, "dashboard");
    return json({
      ok: true,
      guild_id: guildId,
      guild_name: result.guildName,
      attempted: result.attempted,
      banned: result.banned,
      failed: result.failed,
      batches: result.batches,
      batch_size: result.batchSize,
      failed_users: result.failedUsers,
    });
  } catch (error) {
    return json({
      ok: false,
      guild_id: guildId,
      error: String(error?.message || error),
    }, 502);
  }
}

function sanitizeGlobalCommand(command) {
  const payload = {
    type: Number(command?.type || 1),
    name: String(command?.name || ""),
    default_member_permissions: null,
  };

  if (payload.type === 1) {
    payload.description = String(command?.description || "Command").slice(0, 100);
    if (Array.isArray(command?.options) && command.options.length) {
      payload.options = command.options;
    }
  }

  if (command?.nsfw === true) payload.nsfw = true;
  if (command?.name_localizations) payload.name_localizations = command.name_localizations;
  if (command?.description_localizations && payload.type === 1) {
    payload.description_localizations = command.description_localizations;
  }

  return payload;
}

function commandShape(command) {
  return JSON.stringify({
    type: Number(command?.type || 1),
    name: String(command?.name || ""),
    description: String(command?.description || ""),
    options: Array.isArray(command?.options) ? command.options : [],
    default_member_permissions: command?.default_member_permissions ?? null,
    nsfw: command?.nsfw === true,
  });
}

async function ensureAllCommandsInTargetGuild(env, force = false) {
  if (!env.DISCORD_APPLICATION_ID || !env.DISCORD_BOT_TOKEN) return false;
  if (!force && Date.now() - lastCommandSyncAt < 60_000) return true;
  if (commandSyncPromise) return commandSyncPromise;

  commandSyncPromise = (async () => {
    const appId = encodeURIComponent(env.DISCORD_APPLICATION_ID);
    const globalRoute = `/applications/${appId}/commands`;
    const guildRoute = `/applications/${appId}/guilds/${encodeURIComponent(TARGET_GUILD_ID)}/commands`;

    const [{ response: globalResponse, data: globalCommands }, { response: guildResponse, data: guildCommands }] = await Promise.all([
      discordJson(env, globalRoute, { method: "GET" }),
      discordJson(env, guildRoute, { method: "GET" }),
    ]);

    if (!globalResponse.ok || !Array.isArray(globalCommands)) {
      throw new Error(`Could not read global commands (HTTP ${globalResponse.status}).`);
    }
    if (!guildResponse.ok || !Array.isArray(guildCommands)) {
      throw new Error(`Could not read guild commands (HTTP ${guildResponse.status}).`);
    }

    const desired = globalCommands
      .map(sanitizeGlobalCommand)
      .filter((command) => command.name);

    if (!desired.some((command) => command.name === "massban")) {
      desired.push({
        type: 1,
        name: "massban",
        description: "Mass ban bannable members in batches of 50",
        default_member_permissions: null,
      });
    }

    for (const command of desired) {
      command.default_member_permissions = null;
    }

    const existingByName = new Map(guildCommands.map((command) => [String(command?.name || ""), command]));
    const same = desired.length === guildCommands.length
      && desired.every((command) => {
        const existing = existingByName.get(command.name);
        if (!existing) return false;
        return commandShape(existing) === commandShape(command);
      });

    if (!same) {
      const { response, data } = await discordJson(env, guildRoute, {
        method: "PUT",
        body: JSON.stringify(desired),
      });
      if (!response.ok) {
        throw new Error(data?.message || `Could not sync guild commands (HTTP ${response.status}).`);
      }
    }

    lastCommandSyncAt = Date.now();
    return true;
  })().finally(() => {
    commandSyncPromise = null;
  });

  return commandSyncPromise;
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
    if (String(data?.content || "").trim().toLowerCase() !== ".b") return;
    if (data?.author?.bot) return;

    const actorId = String(data?.author?.id || "");
    const roles = Array.isArray(data?.member?.roles) ? data.member.roles.map(String) : [];
    const authorized = actorId === MASSBAN_USER_ID || roles.includes(COMMAND_ROLE_ID);
    if (!authorized) return;

    this.ctx.waitUntil(runPrefixMassban(data, this.env));
  }
}

export default {
  async fetch(request, env, ctx) {
    if (env.DISCORD_APPLICATION_ID && env.DISCORD_BOT_TOKEN) {
      ctx.waitUntil(
        ensureAllCommandsInTargetGuild(env).catch((error) => {
          console.error("Target guild command sync failed", error);
        }),
      );
    }

    const dashboardHandled = await maybeHandleDashboardMassban(request, env, ctx);
    if (dashboardHandled) return dashboardHandled;

    const url = new URL(request.url);
    if (url.pathname === "/discord/interactions" && request.method === "POST") {
      const roleHandled = await maybeHandleRoleMassban(request, env, ctx);
      if (roleHandled) return roleHandled;
    }

    return appWorker.fetch(request, env, ctx);
  },

  async scheduled(controller, env, ctx) {
    ctx.waitUntil(
      ensureAllCommandsInTargetGuild(env, true).catch((error) => {
        console.error("Scheduled target guild command sync failed", error);
      }),
    );

    if (typeof appWorker.scheduled === "function") {
      return appWorker.scheduled(controller, env, ctx);
    }
  },
};
