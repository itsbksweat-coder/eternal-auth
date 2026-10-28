-- Voltra Auth v1.9.0 migration
--
-- 1. Adds a `csrf_token` column to admin_sessions so state-changing admin
--    endpoints can require an in-memory CSRF token in addition to the
--    session cookie. Existing active sessions get NULL csrf_token; those
--    sessions will fail CSRF and the admin re-logs in, which generates a
--    fresh token. See src/index.js createAdminSession / requireCsrf.
--
-- 2. Updates the default `name` for new scripts and panels from
--    'Eternal Auth Script' / 'Eternal Auth Panel' to
--    'Voltra Auth Script' / 'Voltra Auth Panel'. SQLite cannot alter a
--    column default in place; the schema's inline CREATE TABLE IF NOT EXISTS
--    already carries the new default for fresh databases, and existing rows
--    keep whatever name the user set.
--
-- This migration is safe to run multiple times.

ALTER TABLE admin_sessions ADD COLUMN csrf_token TEXT;
