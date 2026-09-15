import { spawnSync } from 'node:child_process';
import { mkdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
process.chdir(fileURLToPath(new URL('..', import.meta.url)));
function run(args) {
  const result = spawnSync(process.execPath, ['./node_modules/wrangler/bin/wrangler.js', ...args], {stdio:'inherit'});
  if (result.error || result.status !== 0) process.exit(result.status || 1);
}
const config=JSON.parse(readFileSync('wrangler.jsonc','utf8'));
const db=config.d1_databases?.find(x=>x.binding==='DB');
if(!db?.database_id) throw new Error('An existing D1 database ID is required.');
console.log(`Upgrading ${config.name}, database ${db.database_name}. Existing Worker secrets are retained.`);
run(['whoami']);
mkdirSync('backups',{recursive:true});
const backup=path.join('backups',`before-1.8.8-${new Date().toISOString().replace(/[:.]/g,'-')}.sql`);
run(['d1','export',db.database_name,'--remote',`--output=${backup}`]);
run(['d1','execute',db.database_name,'--remote','--file=./migrations/v1.8.7-device-security.sql']);
run(['d1','execute',db.database_name,'--remote','--file=./migrations/v1.8.8-ffa.sql']);
run(['deploy']);
console.log('Deployment command succeeded. Run npm run commands to register /ffa, then open /api/health and test the dashboard and bot.');
