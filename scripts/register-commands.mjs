const APP_ID = process.env.DISCORD_APPLICATION_ID;
const BOT_TOKEN = process.env.DISCORD_BOT_TOKEN;
const GUILD_ID = process.env.DISCORD_GUILD_ID || "";

if (!APP_ID || !BOT_TOKEN) {
  console.error("Missing DISCORD_APPLICATION_ID or DISCORD_BOT_TOKEN.");
  console.error("Tip: node --env-file=.commands.env ./scripts/register-commands.mjs");
  process.exit(1);
}

const USER = 6;
const ROLE = 8;
const STRING = 3;
const INTEGER = 4;
const ATTACHMENT = 11;

const commands = [
  {
    name: "login",
    description: "Link Eternal Auth to this Discord server",
    options: [
      { name: "key", description: "One-time Eternal Auth server key created by the owner", type: STRING, required: true },
    ],
  },
  { name: "logout", description: "Log Eternal Auth out of this server" },
  {
    name: "setpanel",
    description: "Sends the control panel message in this channel",
    options: [
      { name: "loader_script", description: "Upload the loader script file used by this panel", type: ATTACHMENT, required: true },
      { name: "manager_role", description: "Role allowed to use manager commands", type: ROLE, required: true },
      { name: "buyer_role", description: "Role to give users after redeeming or being whitelisted", type: ROLE, required: true },
    ],
  },
  {
    name: "setlogs",
    description: "Set the Discord webhook used for Eternal Auth logs",
    options: [
      { name: "webhook", description: "Discord webhook URL, or 'off' to disable logs", type: STRING, required: true },
    ],
  },
  {
    name: "whitelist",
    description: "Whitelist a Discord user",
    options: [
      { name: "user", description: "User to whitelist", type: USER, required: true },
      { name: "panel", description: "Panel this license can access", type: STRING, required: true, autocomplete: true },
      { name: "days", description: "Days of access; omit for lifetime", type: INTEGER, required: false, min_value: 1 },
    ],
  },
  {
    name: "unwhitelist",
    description: "Remove a Discord user's Eternal Auth access",
    options: [
      { name: "user", description: "User to unwhitelist", type: USER, required: true },
    ],
  },
  {
    name: "blacklist",
    description: "Blacklist a Discord user from the project",
    options: [
      { name: "user", description: "User to blacklist", type: USER, required: true },
      { name: "reason", description: "Reason shown to the user", type: STRING, required: false },
      { name: "days", description: "Blacklist duration; omit for indefinite", type: INTEGER, required: false, min_value: 1 },
    ],
  },
  {
    name: "compensate",
    description: "Add days to every non-lifetime key",
    options: [
      { name: "days", description: "Number of days to add", type: INTEGER, required: true, min_value: 1, max_value: 3650 },
    ],
  },
  {
    name: "force-resethwid",
    description: "Reset a user's HWID while ignoring the cooldown",
    options: [
      { name: "user", description: "User whose HWID should be reset", type: USER, required: true },
    ],
  },
  {
    name: "mass-whitelist",
    description: "Whitelist members who have a specific Discord role",
    options: [
      { name: "role", description: "Role whose members should be whitelisted", type: ROLE, required: true },
      { name: "days", description: "Days of access; omit for lifetime", type: INTEGER, required: false, min_value: 1 },
    ],
  },
  {
    name: "redeem",
    description: "Redeem an unclaimed Eternal Auth key",
    options: [
      { name: "key", description: "Eternal Auth key", type: STRING, required: true },
    ],
  },
  { name: "resethwid", description: "Reset the HWID linked to your Eternal Auth key" },
  { name: "script", description: "Get your personal Eternal Auth loader" },
  {
    name: "ffa",
    description: "Get a keyless FFA loader when enabled",
    options: [{ name: "script", description: "Script name; omit when only one FFA script is enabled", type: STRING, required: false }],
  },
  { name: "getrole", description: "Restore your configured buyer role" },
  { name: "stats", description: "Show Eternal Auth project statistics" },
  {
    name: "unblacklist",
    description: "Remove a user's Eternal Auth blacklist",
    options: [
      { name: "user", description: "User to unblacklist", type: USER, required: true },
    ],
  },
];

const route = GUILD_ID
  ? `https://discord.com/api/v10/applications/${APP_ID}/guilds/${GUILD_ID}/commands`
  : `https://discord.com/api/v10/applications/${APP_ID}/commands`;

const response = await fetch(route, {
  method: "PUT",
  headers: {
    Authorization: `Bot ${BOT_TOKEN}`,
    "Content-Type": "application/json",
  },
  body: JSON.stringify(commands),
});

const text = await response.text();
if (!response.ok) {
  console.error(`Discord returned ${response.status}: ${text}`);
  process.exit(1);
}

console.log(`Registered ${commands.length} Eternal Auth commands ${GUILD_ID ? `in guild ${GUILD_ID}` : "globally"}.`);
