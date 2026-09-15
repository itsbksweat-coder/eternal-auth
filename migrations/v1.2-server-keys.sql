CREATE TABLE IF NOT EXISTS server_setup_keys (
  id TEXT PRIMARY KEY,
  key_hash TEXT NOT NULL UNIQUE,
  key_hint TEXT NOT NULL,
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
