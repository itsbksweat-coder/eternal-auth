PRAGMA foreign_keys=OFF;

ALTER TABLE scripts RENAME TO scripts_single_legacy;

CREATE TABLE scripts (
  id TEXT PRIMARY KEY,
  guild_id TEXT NOT NULL,
  loader_id TEXT UNIQUE,
  name TEXT NOT NULL DEFAULT 'Eternal Auth Script',
  version TEXT NOT NULL DEFAULT '1.0.0',
  enabled INTEGER NOT NULL DEFAULT 1,
  content TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  FOREIGN KEY (guild_id) REFERENCES guilds(guild_id) ON DELETE CASCADE
);

INSERT INTO scripts (id, guild_id, loader_id, name, version, enabled, content, created_at, updated_at)
SELECT 'legacy-' || guild_id, guild_id, NULL, name, version, enabled, content, updated_at, updated_at
FROM scripts_single_legacy;

DROP TABLE scripts_single_legacy;

CREATE INDEX IF NOT EXISTS idx_scripts_guild
ON scripts(guild_id, created_at);

CREATE UNIQUE INDEX IF NOT EXISTS idx_scripts_loader_id
ON scripts(loader_id);

PRAGMA foreign_keys=ON;
