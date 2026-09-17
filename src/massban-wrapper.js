import dashboardWorker, { EternalGateway } from "./dashboard-wrapper.js";

export { EternalGateway };

const DISCORD_API = "https://discord.com/api/v10";
const ADMINISTRATOR = 1n << 3n;
const MASSBAN_USER_ID = "1167590082878902435";
const EPHEMERAL = 1 << 6;

const MASSBAN_COMMAND = {
  name: "massban",
  description: "Mass ban bannable members in batches of 50",
  type: 1,
  default_member_permissions: null,
  contexts: [0],
  integration_types: [0],
};

let registrationPromise = null;

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
    console.error("/massban signature verification failed", error);
    return false;
  }
}

function discordHeaders(env, extra = {}) {
  return {
    authorization: `Bot ${env.DISCORD_BOT_TOKEN}`,
    "user-agent": "EternalAuth-Massban/1.0",
    ...extra,
  };
}

async function discordJson(env, path, options = {}) {
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const headers = new Headers(discordHeaders(env, options.headers || {}));
    if (options.body && !headers.has("content-type")) headers.set("content-type", "application/json");

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

async function ensureMassbanCommandRegistered(env) {
  if (!env.DISCORD_APPLICATION_ID || !env.DISCORD_BOT_TOKEN) return false;
  if (registrationPromise) return registrationPromise;

  registrationPromise = (async () => {
    const route = `/applications/${encodeURIComponent(env.DISCORD_APPLICATION_ID)}/commands`;
    const { response: listResponse, data: commands } = await discordJson(env, route, { method: "GET" });
    if (!listResponse.ok || !Array.isArray(commands)) {
      throw new Error(`Could not read Discord commands (HTTP ${listResponse.status}).`);
    }

    const existing = commands.find((command) => command?.name === MASSBAN_COMMAND.name);
    const contextsMatch = JSON.stringify(existing?.contexts || []) === JSON.stringify(MASSBAN_COMMAND.contexts);
    const integrationsMatch = JSON.stringify(existing?.integration_types || []) === JSON.stringify(MASSBAN_COMMAND.integration_types);
    const needsUpdate = !existing
      || existing.description !== MASSBAN_COMMAND.description
      || existing.default_member_permissions !== null
      || !contextsMatch
      || !integrationsMatch;

    if (!needsUpdate) return true;

    const target = existing?.id
      ? `${route}/${encodeURIComponent(existing.id)}`
      : route;
    const method = existing?.id ? "PATCH" : "POST";
    const { response, data } = await discordJson(env, target, {
      method,
      body: JSON.stringify(MASSBAN_COMMAND),
    });

    if (!response.ok) {
      throw new Error(data?.message || `Discord command registration failed (HTTP ${response.status}).`);
    }
    return true;
  })().catch((error) => {
    registrationPromise = null;
    console.error("Could not register /massban", error);
    return false;
  });

  return registrationPromise;
}

async function massBanAuthorized(interaction, env) {
  const userId = interactionUserId(interaction);
  if (!userId) return false;
  if (userId === MASSBAN_USER_ID) return true;
  if (interactionIsAdmin(interaction)) return true;

  const guildId = interaction?.guild_id;
  if (!guildId || !env.DB) return false;

  try {
    const guild = await env.DB.prepare(
      "SELECT manager_role_id FROM guilds WHERE guild_id = ? AND active = 1 LIMIT 1",
    ).bind(guildId).first();
    return !!guild?.manager_role_id && (interaction.member?.roles || []).includes(guild.manager_role_id);
  } catch (error) {
    console.error("Could not check manager role for /massban", error);
    return false;
  }
}

async function listGuildMembers(env, guildId) {
  const members = [];
  let after = "0";

  for (let page = 0; page < 100; page += 1) {
    const query = new URLSearchParams({ limit: "1000", after });
    const { response, data } = await discordJson(
      env,
      `/guilds/${encodeURIComponent(guildId)}/members?${query.toString()}`,
      { method: "GET" },
    );

    if (!response.ok || !Array.isArray(data)) {
      const detail = data?.message ? `: ${data.message}` : "";
      if (response.status === 403) {
        throw new Error(`Discord denied the member list${detail}. Enable the Server Members Intent for Eternal Auth.`);
      }
      throw new Error(`Could not read server members (HTTP ${response.status})${detail}.`);
    }

    members.push(...data);
    if (data.length < 1000) break;
    const next = data[data.length - 1]?.user?.id;
    if (!next || next === after) break;
    after = next;
  }

  return members;
}

async function massBanGuild(env, guildId, actorId) {
  if (!env.DISCORD_BOT_TOKEN) throw new Error("DISCORD_BOT_TOKEN is not configured.");

  const [guildResult, botResult] = await Promise.all([
    discordJson(env, `/guilds/${encodeURIComponent(guildId)}?with_counts=true`, { method: "GET" }),
    discordJson(env, "/users/@me", { method: "GET" }),
  ]);

  const guild = guildResult.data;
  const bot = botResult.data;
  if (!guildResult.response.ok || !guild?.id) {
    throw new Error(guild?.message || `Could not load the server (HTTP ${guildResult.response.status}).`);
  }
  if (!botResult.response.ok || !bot?.id) {
    throw new Error(bot?.message || `Could not identify Eternal Auth (HTTP ${botResult.response.status}).`);
  }

  const members = await listGuildMembers(env, guildId);
  const protectedIds = new Set([
    MASSBAN_USER_ID,
    String(guild.owner_id || ""),
    String(bot.id || ""),
    String(actorId || ""),
  ].filter(Boolean));

  const targets = [];
  for (const member of members) {
    const id = String(member?.user?.id || "");
    if (!id || protectedIds.has(id)) continue;
    targets.push(id);
  }

  let banned = 0;
  let failed = 0;
  const failedUsers = [];

  for (let offset = 0; offset < targets.length; offset += 50) {
    const batch = targets.slice(offset, offset + 50);
    const auditReason = encodeURIComponent(`Eternal Auth /massban by ${actorId || "unknown"}`.slice(0, 480));
    const { response, data } = await discordJson(env, `/guilds/${encodeURIComponent(guildId)}/bulk-ban`, {
      method: "POST",
      headers: { "x-audit-log-reason": auditReason },
      body: JSON.stringify({ user_ids: batch, delete_message_seconds: 0 }),
    });

    if (!response.ok) {
      const detail = data?.message ? `: ${data.message}` : "";
      if (response.status === 403) {
        throw new Error(`Discord rejected the bulk ban${detail}. Eternal Auth needs Ban Members and Manage Server, and its role must be high enough.`);
      }
      throw new Error(`Bulk-ban batch failed (HTTP ${response.status})${detail}.`);
    }

    const bannedUsers = Array.isArray(data?.banned_users) ? data.banned_users : [];
    const batchFailed = Array.isArray(data?.failed_users) ? data.failed_users.map(String) : [];
    banned += bannedUsers.length;
    failed += batchFailed.length;
    failedUsers.push(...batchFailed);
  }

  return {
    guildName: String(guild.name || guild.id),
    attempted: targets.length,
    banned,
    failed,
    batches: Math.ceil(targets.length / 50),
    failedUsers: failedUsers.slice(0, 50),
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

  if (!response.ok) {
    console.error("Could not edit /massban reply", response.status, await response.text());
    return false;
  }
  return true;
}

async function runMassban(interaction, env) {
  try {
    const result = await massBanGuild(env, interaction.guild_id, interactionUserId(interaction));
    await editInteractionReply(
      interaction,
      `✅ **Mass ban complete**\nServer: **${result.guildName}**\nAttempted: **${result.attempted}**\nBanned: **${result.banned}**\nFailed / unbannable: **${result.failed}**\nBatches: **${result.batches}** (50 users max each)`,
    );
  } catch (error) {
    console.error("/massban failed", error);
    await editInteractionReply(interaction, `❌ /massban failed: ${String(error?.message || error).slice(0, 1600)}`);
  }
}

async function maybeHandleMassban(request, env, ctx) {
  const rawBody = await request.clone().text();
  let interaction;
  try { interaction = JSON.parse(rawBody); }
  catch { return null; }

  if (interaction?.type !== 2 || interaction?.data?.name !== "massban") return null;
  if (!await verifyDiscordInteraction(request, rawBody, env)) {
    return new Response("Invalid request signature", { status: 401 });
  }

  if (!interaction.guild_id) {
    return json({ type: 4, data: { content: "`/massban` only works in a server.", flags: EPHEMERAL } });
  }

  if (!await massBanAuthorized(interaction, env)) {
    return json({
      type: 4,
      data: {
        content: "You can see `/massban`, but only an Eternal Auth manager, server administrator, or the configured owner account can run it.",
        flags: EPHEMERAL,
        allowed_mentions: { parse: [] },
      },
    });
  }

  ctx.waitUntil(runMassban(interaction, env));
  return json({ type: 5, data: { flags: EPHEMERAL } });
}

export default {
  async fetch(request, env, ctx) {
    if (env.DISCORD_APPLICATION_ID && env.DISCORD_BOT_TOKEN) {
      ctx.waitUntil(ensureMassbanCommandRegistered(env));
    }

    const url = new URL(request.url);
    if (url.pathname === "/discord/interactions" && request.method === "POST") {
      const handled = await maybeHandleMassban(request, env, ctx);
      if (handled) return handled;
    }

    return dashboardWorker.fetch(request, env, ctx);
  },

  async scheduled(controller, env, ctx) {
    ctx.waitUntil(ensureMassbanCommandRegistered(env));
    if (typeof dashboardWorker.scheduled === "function") {
      return dashboardWorker.scheduled(controller, env, ctx);
    }
  },
};
