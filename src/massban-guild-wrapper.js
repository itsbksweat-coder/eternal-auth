import massbanWorker, { EternalGateway } from "./massban-wrapper.js";

export { EternalGateway };

const DISCORD_API = "https://discord.com/api/v10";
const PINNED_GUILD_IDS = [
  "1249019782632570971",
  "1539142072232050690",
];

// Guild-scoped commands must not send global-only fields such as
// contexts or integration_types.
const GUILD_MASSBAN_COMMAND = {
  name: "massban",
  description: "Mass ban bannable members in batches of 50",
  type: 1,
  default_member_permissions: null,
};

let registrationPromise = null;
let lastRegistrationAt = 0;

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function discordJson(env, path, options = {}) {
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const headers = new Headers(options.headers || {});
    headers.set("authorization", `Bot ${env.DISCORD_BOT_TOKEN}`);
    headers.set("user-agent", "EternalAuth-MassbanGuild/1.1");
    if (options.body && !headers.has("content-type")) {
      headers.set("content-type", "application/json");
    }

    const response = await fetch(`${DISCORD_API}${path}`, { ...options, headers });
    const text = response.status === 204 ? "" : await response.text();
    let data = null;

    if (text) {
      try {
        data = JSON.parse(text);
      } catch {
        data = { message: text };
      }
    }

    if (response.status !== 429 || attempt === 4) {
      return { response, data };
    }

    const retryMs = Math.max(250, Math.ceil(Number(data?.retry_after || 1) * 1000));
    await sleep(retryMs);
  }

  throw new Error("Discord request retry loop ended unexpectedly.");
}

async function botGuildIds(env) {
  const guildIds = [];
  let after = null;

  // Bot users are not limited to 200 guilds, so keep paginating until
  // Discord returns fewer than 200 entries.
  for (let page = 0; page < 1000; page += 1) {
    const query = new URLSearchParams({
      limit: "200",
      with_counts: "false",
    });
    if (after) query.set("after", after);

    const { response, data } = await discordJson(
      env,
      `/users/@me/guilds?${query.toString()}`,
      { method: "GET" },
    );

    if (!response.ok || !Array.isArray(data)) {
      throw new Error(
        data?.message || `Could not enumerate Eternal Auth guilds (HTTP ${response.status}).`,
      );
    }

    for (const guild of data) {
      const id = String(guild?.id || "");
      if (id) guildIds.push(id);
    }

    if (data.length < 200) break;

    const next = String(data[data.length - 1]?.id || "");
    if (!next || next === after) break;
    after = next;
  }

  return guildIds;
}

async function gatewayGuildIds(env) {
  if (!env.GATEWAY) return [];

  try {
    const id = env.GATEWAY.idFromName("eternal-auth-primary-gateway");
    const gateway = env.GATEWAY.get(id);
    const response = await gateway.fetch("https://gateway.internal/guilds", { method: "GET" });
    const data = await response.json().catch(() => ({}));

    if (!response.ok || !Array.isArray(data.guild_ids)) return [];
    return data.guild_ids.map(String).filter(Boolean);
  } catch (error) {
    console.error("Could not read Gateway guild IDs for /massban", error);
    return [];
  }
}

function commandMatches(existing) {
  if (!existing) return false;
  return existing.description === GUILD_MASSBAN_COMMAND.description
    && existing.default_member_permissions === null;
}

async function registerInGuild(env, guildId) {
  const base = `/applications/${encodeURIComponent(env.DISCORD_APPLICATION_ID)}/guilds/${encodeURIComponent(guildId)}/commands`;
  const { response: listResponse, data: commands } = await discordJson(env, base, {
    method: "GET",
  });

  if (!listResponse.ok || !Array.isArray(commands)) {
    throw new Error(
      data?.message || `Could not read commands for guild ${guildId} (HTTP ${listResponse.status}).`,
    );
  }

  const existing = commands.find((command) => command?.name === "massban");
  if (commandMatches(existing)) return true;

  // POST is an upsert by command name for application commands.
  const { response, data } = await discordJson(env, base, {
    method: "POST",
    body: JSON.stringify(GUILD_MASSBAN_COMMAND),
  });

  if (!response.ok) {
    throw new Error(
      data?.message || `Could not register /massban in guild ${guildId} (HTTP ${response.status}).`,
    );
  }

  return true;
}

async function ensureGuildMassbanRegistered(env, force = false) {
  if (!env.DISCORD_APPLICATION_ID || !env.DISCORD_BOT_TOKEN) return false;
  if (!force && Date.now() - lastRegistrationAt < 60_000) return true;
  if (registrationPromise) return registrationPromise;

  registrationPromise = (async () => {
    let restGuilds = [];
    try {
      restGuilds = await botGuildIds(env);
    } catch (error) {
      console.error("Could not enumerate all bot guilds for /massban", error);
    }

    const cachedGuilds = await gatewayGuildIds(env);
    const guildIds = [...new Set([
      ...PINNED_GUILD_IDS,
      ...restGuilds,
      ...cachedGuilds,
    ])];

    let ok = 0;
    let failed = 0;

    // Keep a little concurrency so large guild lists finish quickly without
    // blasting Discord with every request simultaneously.
    for (let offset = 0; offset < guildIds.length; offset += 10) {
      const group = guildIds.slice(offset, offset + 10);
      const results = await Promise.allSettled(
        group.map((guildId) => registerInGuild(env, guildId)),
      );

      for (let i = 0; i < results.length; i += 1) {
        const result = results[i];
        if (result.status === "fulfilled") {
          ok += 1;
        } else {
          failed += 1;
          console.error(
            `Could not register /massban in guild ${group[i]}`,
            result.reason,
          );
        }
      }
    }

    lastRegistrationAt = Date.now();
    console.log(`/massban guild sync complete: ${ok} ok, ${failed} failed, ${guildIds.length} discovered.`);
    return ok > 0;
  })().finally(() => {
    registrationPromise = null;
  });

  return registrationPromise;
}

export default {
  async fetch(request, env, ctx) {
    if (env.DISCORD_APPLICATION_ID && env.DISCORD_BOT_TOKEN) {
      ctx.waitUntil(ensureGuildMassbanRegistered(env));
    }

    return massbanWorker.fetch(request, env, ctx);
  },

  async scheduled(controller, env, ctx) {
    ctx.waitUntil(ensureGuildMassbanRegistered(env, true));

    if (typeof massbanWorker.scheduled === "function") {
      return massbanWorker.scheduled(controller, env, ctx);
    }
  },
};
