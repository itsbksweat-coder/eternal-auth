import massbanWorker, { EternalGateway } from "./massban-wrapper.js";

export { EternalGateway };

const DISCORD_API = "https://discord.com/api/v10";
const PINNED_GUILD_IDS = [
  "1249019782632570971",
  "1539142072232050690",
];

const MASSBAN_COMMAND = {
  name: "massban",
  description: "Mass ban bannable members in batches of 50",
  type: 1,
  default_member_permissions: null,
  contexts: [0],
  integration_types: [0],
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
    headers.set("user-agent", "EternalAuth-MassbanGuild/1.0");
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
  const contexts = Array.isArray(existing.contexts) ? existing.contexts : [];
  const integrations = Array.isArray(existing.integration_types) ? existing.integration_types : [];
  return existing.description === MASSBAN_COMMAND.description
    && existing.default_member_permissions === null
    && JSON.stringify(contexts) === JSON.stringify(MASSBAN_COMMAND.contexts)
    && JSON.stringify(integrations) === JSON.stringify(MASSBAN_COMMAND.integration_types);
}

async function registerInGuild(env, guildId) {
  const base = `/applications/${encodeURIComponent(env.DISCORD_APPLICATION_ID)}/guilds/${encodeURIComponent(guildId)}/commands`;
  const { response: listResponse, data: commands } = await discordJson(env, base, { method: "GET" });
  if (!listResponse.ok || !Array.isArray(commands)) {
    throw new Error(`Could not read commands for guild ${guildId} (HTTP ${listResponse.status}).`);
  }

  const existing = commands.find((command) => command?.name === "massban");
  if (commandMatches(existing)) return true;

  const target = existing?.id ? `${base}/${encodeURIComponent(existing.id)}` : base;
  const method = existing?.id ? "PATCH" : "POST";
  const { response, data } = await discordJson(env, target, {
    method,
    body: JSON.stringify(MASSBAN_COMMAND),
  });

  if (!response.ok) {
    throw new Error(data?.message || `Could not register /massban in guild ${guildId} (HTTP ${response.status}).`);
  }
  return true;
}

async function ensureGuildMassbanRegistered(env, force = false) {
  if (!env.DISCORD_APPLICATION_ID || !env.DISCORD_BOT_TOKEN) return false;
  if (!force && Date.now() - lastRegistrationAt < 60_000) return true;
  if (registrationPromise) return registrationPromise;

  registrationPromise = (async () => {
    const discovered = await gatewayGuildIds(env);
    const guildIds = [...new Set([...PINNED_GUILD_IDS, ...discovered])];
    let ok = 0;

    for (const guildId of guildIds) {
      try {
        await registerInGuild(env, guildId);
        ok += 1;
      } catch (error) {
        console.error(`Could not register /massban in guild ${guildId}`, error);
      }
    }

    lastRegistrationAt = Date.now();
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
