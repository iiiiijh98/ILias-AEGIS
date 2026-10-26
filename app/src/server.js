'use strict';
// AEGIS v2 실행: 현장·관리·전광판·매핑 금고를 서로 다른 포트(=서로 다른 앱·쿠키·세션)로 띄웁니다.
// 사용: node src/server.js [all|field|admin|board|vault]   (Vault는 별도 프로세스로 띄우는 것을 권장)
const { loadConfig } = require('./config'); const { createDb } = require('./db'); const { MAIN } = require('./schema');
const { createStorage } = require('./storage'); const svc = require('./services'); const auth = require('./auth');
async function createCore(over = {}) {
  const cfg = loadConfig(over); const db = over.db || createDb({ url: cfg.databaseUrl, sqlitePath: cfg.sqlitePath }, MAIN);
  await db.migrate(); await svc.initSettings(db);
  if (await auth.ensureInitialAdmin(db, cfg)) console.log('[AEGIS2] 초기 시스템관리자 계정(andy)을 만들었습니다. 첫 로그인 후 인증 앱을 등록하세요.');
  return { cfg, db, storage: createStorage(cfg) };
}
async function createVaultCore(core, over = {}) { const { createVault } = require('./vault'); const vault = createVault(core.cfg, over); await vault.migrate(); return { ...core, vault }; }
const APPS = {
  field: (c) => require('./apps/field').createFieldApp(c), admin: (c) => require('./apps/admin').createAdminApp(c), board: (c) => require('./apps/board').createBoardApp(c),
};
async function main(which = process.argv[2] || 'all', coreIn = null) {
  const core = coreIn || await createCore(); const list = which === 'all' ? ['field', 'admin', 'board'] : [which];
  // all: Vault는 별도 프로세스(자식 프로세스)로 띄워 메모리·키를 관리 앱과 나눕니다.
  if (which === 'all') { const child = require('child_process').fork(__filename, ['vault'], { stdio: 'inherit' }); process.on('exit', () => child.kill()); }
  for (const name of list) {
    if (name !== 'vault' && !APPS[name]) throw new Error('unknown app ' + name);
    const app = name === 'vault' ? require('./apps/vaultapp').createVaultApp(await createVaultCore(core)) : APPS[name](core);
    app.listen(core.cfg.ports[name], core.cfg.host, () => console.log(`[AEGIS2] ${name} → http://${core.cfg.host}:${core.cfg.ports[name]}`));
  }
  return core;
}
if (require.main === module) main().catch((e) => { console.error('[AEGIS2] 시작 실패:', e.message); process.exit(1); });
module.exports = { createCore, createVaultCore, APPS, main };
