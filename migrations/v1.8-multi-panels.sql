PRAGMA foreign_keys = ON;

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
  FOREIGN KEY (guild_id) REFERENCES guilds(guild_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_panels_guild_active
ON panels(guild_id, active, created_at DESC);
