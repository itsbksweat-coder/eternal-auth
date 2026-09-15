ALTER TABLE licenses ADD COLUMN panel_id TEXT;

CREATE INDEX IF NOT EXISTS idx_licenses_guild_panel
ON licenses(guild_id, panel_id, status);
