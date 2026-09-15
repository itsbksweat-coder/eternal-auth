PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS guilds (
  guild_id TEXT PRIMARY KEY,
  active INTEGER NOT NULL DEFAULT 1,
  manager_role_id TEXT,
  buyer_role_id TEXT,
  log_webhook_enc TEXT,
  base_url TEXT,
  loader_template TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);


CREATE TABLE IF NOT EXISTS panels (
  id TEXT PRIMARY KEY,
  guild_id TEXT NOT NULL,
  name TEXT NOT NULL DEFAULT 'Eternal Auth Panel',
  channel_id TEXT,
  manager_role_id TEXT,
  buyer_role_id TEXT,
  loader_template TEXT,
  active INTEGER NOT NULL DEFAULT 1,
  created_by TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  embed_title TEXT,
  embed_description TEXT,
  embed_color INTEGER,
  script_id TEXT,
  FOREIGN KEY (guild_id) REFERENCES guilds(guild_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_panels_guild_active
ON panels(guild_id, active, created_at DESC);

CREATE TABLE IF NOT EXISTS panel_drafts (
  id TEXT PRIMARY KEY,
  guild_id TEXT NOT NULL,
  channel_id TEXT,
  manager_role_id TEXT,
  buyer_role_id TEXT,
  loader_template TEXT NOT NULL,
  uploaded_loader_url TEXT,
  selected_script_id TEXT,
  created_by TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_panel_drafts_expires
ON panel_drafts(expires_at);

CREATE TABLE IF NOT EXISTS server_setup_keys (
  id TEXT PRIMARY KEY,
  key_hash TEXT NOT NULL UNIQUE,
  key_hint TEXT NOT NULL,
  key_enc TEXT,
  intended_guild_id TEXT,
  note TEXT,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  used_at INTEGER,
  used_by_guild_id TEXT,
  used_by_discord_id TEXT
);

CREATE INDEX IF NOT EXISTS idx_server_setup_keys_created
ON server_setup_keys(created_at DESC);

CREATE TABLE IF NOT EXISTS licenses (
  id TEXT PRIMARY KEY,
  guild_id TEXT NOT NULL,
  key_hash TEXT NOT NULL UNIQUE,
  discord_id TEXT,
  status TEXT NOT NULL DEFAULT 'active',
  auth_expire INTEGER NOT NULL DEFAULT -1,
  note TEXT,
  hwid_hash TEXT,
  last_hwid_reset INTEGER,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  FOREIGN KEY (guild_id) REFERENCES guilds(guild_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_licenses_guild_discord
ON licenses(guild_id, discord_id);

CREATE INDEX IF NOT EXISTS idx_licenses_guild_status
ON licenses(guild_id, status);

CREATE TABLE IF NOT EXISTS blacklists (
  guild_id TEXT NOT NULL,
  discord_id TEXT NOT NULL,
  reason TEXT,
  expires_at INTEGER NOT NULL DEFAULT -1,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (guild_id, discord_id),
  FOREIGN KEY (guild_id) REFERENCES guilds(guild_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS redeem_codes (
  id TEXT PRIMARY KEY,
  guild_id TEXT NOT NULL,
  code_hash TEXT NOT NULL UNIQUE,
  days INTEGER NOT NULL DEFAULT -1,
  uses_left INTEGER NOT NULL DEFAULT 1,
  note TEXT,
  expires_at INTEGER NOT NULL DEFAULT -1,
  created_at INTEGER NOT NULL,
  FOREIGN KEY (guild_id) REFERENCES guilds(guild_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_redeem_codes_guild
ON redeem_codes(guild_id);

CREATE TABLE IF NOT EXISTS scripts (
  id TEXT PRIMARY KEY,
  guild_id TEXT NOT NULL,
  loader_id TEXT UNIQUE,
  name TEXT NOT NULL DEFAULT 'Eternal Auth Script',
  version TEXT NOT NULL DEFAULT '1.0.0',
  enabled INTEGER NOT NULL DEFAULT 1,
  ffa_enabled INTEGER NOT NULL DEFAULT 0,
  content TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  FOREIGN KEY (guild_id) REFERENCES guilds(guild_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_scripts_guild
ON scripts(guild_id, created_at);

CREATE UNIQUE INDEX IF NOT EXISTS idx_scripts_loader_id
ON scripts(loader_id);

CREATE TABLE IF NOT EXISTS executions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  guild_id TEXT NOT NULL,
  license_id TEXT NOT NULL,
  occurred_at INTEGER NOT NULL,
  FOREIGN KEY (guild_id) REFERENCES guilds(guild_id) ON DELETE CASCADE,
  FOREIGN KEY (license_id) REFERENCES licenses(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_executions_license_time
ON executions(license_id, occurred_at DESC);

CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  guild_id TEXT,
  action TEXT NOT NULL,
  actor_id TEXT,
  target TEXT,
  details TEXT,
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_time
ON audit_logs(created_at DESC);


CREATE TABLE IF NOT EXISTS admin_credentials (
  id TEXT PRIMARY KEY,
  password_salt TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  iterations INTEGER NOT NULL DEFAULT 100000,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS admin_sessions (
  id TEXT PRIMARY KEY,
  token_hash TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_admin_sessions_expires
ON admin_sessions(expires_at);

CREATE TABLE IF NOT EXISTS admin_state (
  id TEXT PRIMARY KEY,
  last_guild_id TEXT,
  active_tab TEXT NOT NULL DEFAULT 'gateway',
  preferences_json TEXT NOT NULL DEFAULT '{}',
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS runtime_state (
  key TEXT PRIMARY KEY,
  value_json TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS hwid_blacklists (
  guild_id TEXT NOT NULL,
  hwid_hash TEXT NOT NULL,
  reason TEXT NOT NULL,
  license_id TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (guild_id, hwid_hash)
);
