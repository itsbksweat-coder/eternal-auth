import baseWorker, { EternalGateway as BaseEternalGateway } from "./oauth-wrapper.js";

const DISCORD_API = "https://discord.com/api/v10";
const ADMINISTRATOR = 1n << 3n;
const BAN_MEMBERS = 1n << 2n;
const MANAGE_GUILD = 1n << 5n;

const PINNED_GUILDS = {
  "1249019782632570971": "WakeHub",
  "1539142072232050690": "CleanHub",
};

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

// Keep the existing EternalGateway connection, but expose the guild IDs it
// receives from Discord's READY/GUILD_CREATE/GUILD_DELETE gateway events.
export class EternalGateway extends BaseEternalGateway {
  async fetch(request) {
    const url = new URL(request.url);

    if (url.pathname === "/guilds" && request.method === "GET") {
      await super.fetch(new Request("https://gateway.internal/status", { method: "GET" }));

      for (let i = 0; i < 50 && !this.ready; i += 1) {
        await sleep(100);
      }

      return json({
        ok: true,
        gateway_ready: !!this.ready,
        guild_ids: [...this.guildIds].map(String),
        gateway: this.status(),
      });
    }

    return super.fetch(request);
  }
}

async function dashboardAdminAuthorized(request, env, ctx) {
  const url = new URL(request.url);
  const headers = new Headers();
  const cookie = request.headers.get("cookie");
  if (cookie) headers.set("cookie", cookie);

  const response = await baseWorker.fetch(new Request(`${url.origin}/api/admin/state`, {
    method: "GET",
    headers,
  }), env, ctx);

  return response.ok;
}

function discordHeaders(env) {
  return {
    authorization: `Bot ${env.DISCORD_BOT_TOKEN}`,
    "user-agent": "EternalAuth-Dashboard/2.1",
  };
}

async function gatewayGuildIds(env) {
  const id = env.GATEWAY.idFromName("eternal-auth-primary-gateway");
  const gateway = env.GATEWAY.get(id);
  const response = await gateway.fetch("https://gateway.internal/guilds", { method: "GET" });
  const data = await response.json().catch(() => ({}));

  if (!response.ok || data.ok === false) {
    throw new Error(data.error || `Gateway guild lookup failed (HTTP ${response.status}).`);
  }

  const ids = Array.isArray(data.guild_ids)
    ? [...new Set(data.guild_ids.map(String).filter(Boolean))]
    : [];

  return { ids, gateway: data.gateway || {}, gatewayReady: !!data.gateway_ready };
}

function effectivePermissions(guild, member) {
  if (!guild || !member || !Array.isArray(guild.roles)) return null;

  let permissions = 0n;
  const roleIds = new Set([String(guild.id), ...(member.roles || []).map(String)]);

  for (const role of guild.roles) {
    if (!roleIds.has(String(role.id))) continue;
    try { permissions |= BigInt(String(role.permissions || "0")); } catch {}
  }

  return permissions;
}

async function loadGuild(env, guildId, botUserId, fallbackName = null) {
  const guildResponse = await fetch(`${DISCORD_API}/guilds/${encodeURIComponent(guildId)}?with_counts=true`, {
    headers: discordHeaders(env),
  });

  if (!guildResponse.ok) {
    return {
      id: String(guildId),
      name: String(fallbackName || guildId),
      approximate_member_count: 0,
      administrator: null,
      ban_members: null,
      manage_server: null,
      can_bulk_ban: null,
      permission_check: "unknown",
      accessible: false,
      discord_status: guildResponse.status,
    };
  }

  const guild = await guildResponse.json();
  let member = null;

  if (botUserId) {
    const memberResponse = await fetch(
      `${DISCORD_API}/guilds/${encodeURIComponent(guildId)}/members/${encodeURIComponent(botUserId)}`,
      { headers: discordHeaders(env) },
    );
    if (memberResponse.ok) member = await memberResponse.json().catch(() => null);
  }

  const permissions = effectivePermissions(guild, member);
  let administrator = null;
  let banMembers = null;
  let manageGuild = null;

  if (permissions !== null) {
    administrator = (permissions & ADMINISTRATOR) !== 0n;
    banMembers = administrator || (permissions & BAN_MEMBERS) !== 0n;
    manageGuild = administrator || (permissions & MANAGE_GUILD) !== 0n;
  }

  return {
    id: String(guild.id || guildId),
    name: String(guild.name || fallbackName || guildId),
    approximate_member_count: Number(guild.approximate_member_count || guild.approximate_presence_count || 0),
    administrator,
    ban_members: banMembers,
    manage_server: manageGuild,
    can_bulk_ban: permissions === null ? null : (banMembers && manageGuild),
    permission_check: permissions === null ? "unknown" : "known",
    accessible: true,
  };
}

async function listBotGuilds(env) {
  if (!env.DISCORD_BOT_TOKEN) {
    return json({ ok: false, error: "DISCORD_BOT_TOKEN is not configured." }, 500);
  }

  let discovered = { ids: [], gateway: {}, gatewayReady: false };
  try {
    discovered = await gatewayGuildIds(env);
  } catch (error) {
    discovered = {
      ids: [],
      gateway: { error: String(error?.message || error) },
      gatewayReady: false,
    };
  }

  // Always include the two known Eternal Auth servers as a fallback. Discord
  // REST is still queried for each ID so names, counts and permissions stay live.
  const allIds = [...new Set([
    ...discovered.ids.map(String),
    ...Object.keys(PINNED_GUILDS),
  ])];

  const meResponse = await fetch(`${DISCORD_API}/users/@me`, { headers: discordHeaders(env) });
  const me = meResponse.ok ? await meResponse.json().catch(() => ({})) : {};
  const botUserId = String(me?.id || "");

  const guilds = [];
  for (let i = 0; i < allIds.length; i += 10) {
    const batch = allIds.slice(i, i + 10);
    const rows = await Promise.all(batch.map((guildId) =>
      loadGuild(env, guildId, botUserId, PINNED_GUILDS[guildId] || null)
    ));
    guilds.push(...rows);
  }

  guilds.sort((a, b) => a.name.localeCompare(b.name));

  return json({
    ok: true,
    guilds,
    source: discovered.ids.length ? "discord_gateway+pinned" : "pinned_fallback",
    gateway_ready: discovered.gatewayReady,
    gateway_count: discovered.ids.length,
    pinned_count: Object.keys(PINNED_GUILDS).length,
    gateway: discovered.gateway,
  });
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === "/api/admin/server-cleanup/guilds" && request.method === "GET") {
      if (!await dashboardAdminAuthorized(request, env, ctx)) {
        return json({ ok: false, error: "Unauthorized" }, 401);
      }

      try {
        return await listBotGuilds(env);
      } catch (error) {
        return json({
          ok: false,
          error: `Could not read Eternal Auth's Discord servers: ${String(error?.message || error)}`,
        }, 502);
      }
    }

    return baseWorker.fetch(request, env, ctx);
  },

  async scheduled(controller, env, ctx) {
    if (typeof baseWorker.scheduled === "function") {
      return baseWorker.scheduled(controller, env, ctx);
    }
  },
};
