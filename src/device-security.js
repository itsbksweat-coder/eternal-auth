export async function deviceBlocked(env, guildId, ...hashes) {
  const unique = [...new Set(hashes.filter(Boolean))];
  if (!unique.length) return false;
  const row = await env.DB.prepare(`SELECT 1 AS blocked FROM hwid_blacklists WHERE guild_id = ? AND hwid_hash IN (${unique.map(() => '?').join(',')}) LIMIT 1`).bind(guildId, ...unique).first();
  return !!row;
}

export async function bindDevice(env, license, deviceHash, timestamp) {
  await env.DB.prepare('UPDATE licenses SET hwid_hash = ?, updated_at = ? WHERE id = ? AND hwid_hash IS NULL AND status = \'active\'')
    .bind(deviceHash, timestamp, license.id).run();
  const current = await env.DB.prepare('SELECT hwid_hash, status FROM licenses WHERE id = ?').bind(license.id).first();
  return current?.status === 'active' && current.hwid_hash === deviceHash;
}

export function hwidCooldownSeconds(env) {
  const minutes = Number(env.HWID_RESET_COOLDOWN_MINUTES ?? 5);
  return (Number.isFinite(minutes) && minutes >= 0 ? minutes : 5) * 60;
}
