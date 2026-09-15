-- Eternal Auth v1.8.4 panel customization
-- The Worker also self-initializes these additions, so this migration is optional.

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

CREATE INDEX IF NOT EXISTS idx_panel_drafts_expires ON panel_drafts(expires_at);
