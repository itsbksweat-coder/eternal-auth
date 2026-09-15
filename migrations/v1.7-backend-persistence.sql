PRAGMA foreign_keys = ON;

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

INSERT OR IGNORE INTO admin_state (id, active_tab, preferences_json, updated_at)
VALUES ('primary', 'gateway', '{}', unixepoch());

CREATE TABLE IF NOT EXISTS runtime_state (
  key TEXT PRIMARY KEY,
  value_json TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);

-- key_enc is added safely by the Worker after inspecting PRAGMA table_info.
-- Keeping the SQL migration idempotent prevents duplicate-column failures.
