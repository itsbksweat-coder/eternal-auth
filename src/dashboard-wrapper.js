import baseWorker, { EternalGateway } from "./oauth-wrapper.js";

export { EternalGateway };

const DISCORD_API = "https://discord.com/api/v10";
const ADMINISTRATOR = 1n << 3n;
const BAN_MEMBERS = 1n << 2n;
const MANAGE_GUILD = 1n << 5n;

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
    },
  });
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

async function listBotGuilds(env) {
  if (!env.DISCORD_BOT_TOKEN) {
    return json({ ok: false, error: "DISCORD_BOT_TOKEN is not configured." }, 500);
  }

  const response = await fetch(`${DISCORD_API}/users/@me/guilds?limit=200&with_counts=true`, {
    headers: {
      authorization: `Bot ${env.DISCORD_BOT_TOKEN}`,
      "user-agent": "EternalAuth-Dashboard/1.0",
    },
  });

  const data = await response.json().catch(() => null);
  if (!response.ok || !Array.isArray(data)) {
    return json({
      ok: false,
      error: data?.message || `Discord could not list Eternal Auth servers (HTTP ${response.status}).`,
    }, response.ok ? 502 : response.status);
  }

  const guilds = data.map((guild) => {
    let permissions = 0n;
    try { permissions = BigInt(String(guild.permissions || "0")); } catch {}

    const administrator = (permissions & ADMINISTRATOR) !== 0n;
    const banMembers = administrator || (permissions & BAN_MEMBERS) !== 0n;
    const manageGuild = administrator || (permissions & MANAGE_GUILD) !== 0n;

    return {
      id: String(guild.id || ""),
      name: String(guild.name || guild.id || "Unknown Server"),
      approximate_member_count: Number(guild.approximate_member_count || 0),
      permissions: permissions.toString(),
      administrator,
      ban_members: banMembers,
      manage_server: manageGuild,
      can_bulk_ban: banMembers && manageGuild,
    };
  }).filter((guild) => guild.id)
    .sort((a, b) => a.name.localeCompare(b.name));

  return json({ ok: true, guilds });
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === "/api/admin/server-cleanup/guilds" && request.method === "GET") {
      if (!await dashboardAdminAuthorized(request, env, ctx)) {
        return json({ ok: false, error: "Unauthorized" }, 401);
      }
      return listBotGuilds(env);
    }

    return baseWorker.fetch(request, env, ctx);
  },

  async scheduled(controller, env, ctx) {
    if (typeof baseWorker.scheduled === "function") {
      return baseWorker.scheduled(controller, env, ctx);
    }
  },
};
