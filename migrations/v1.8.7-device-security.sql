CREATE TABLE IF NOT EXISTS hwid_blacklists (
  guild_id TEXT NOT NULL,
  hwid_hash TEXT NOT NULL,
  reason TEXT NOT NULL,
  license_id TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (guild_id, hwid_hash)
);
