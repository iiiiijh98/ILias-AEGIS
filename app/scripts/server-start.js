'use strict';
// 회사 서버판 시작(systemd aegis.service / 도커 aegis 컨테이너가 실행).
// 4개 앱 = 127.0.0.1:3201~3204 (밖에서는 HTTPS 프록시로만). 매일 자동 백업(데이터+사진, 키 제외).
const fs = require('fs'); const path = require('path'); const crypto = require('crypto');
const E = require('./server-env'); const B = require('./server-backup');
const log = (...a) => console.log('[AEGIS2-server]', ...a);
const kstNow = () => new Date(Date.now() + 9 * 3600e3).toISOString(); // YYYY-MM-DDTHH:MM (한국 시간)
function scheduleBackups() {
  const at = (process.env.AEGIS_BACKUP_TIME || '02:30').trim();
  if (/^off$/i.test(at)) { log('자동 백업 꺼짐(AEGIS_BACKUP_TIME=off)'); return; }
  if (!/^([01]\d|2[0-3]):[0-5]\d$/.test(at)) throw new Error('AEGIS_BACKUP_TIME 형식은 HH:MM (예: 02:30)');
  const marker = path.join(E.DIRS.run, 'last_backup_day');
  const tick = () => {
    const now = kstNow(); const day = now.slice(0, 10); const hm = now.slice(11, 16);
    let last = ''; try { last = fs.readFileSync(marker, 'utf8').trim(); } catch (_) {}
    if (hm < at || last === day) return;
    try { const r = B.runBackup({ reason: 'daily' }); fs.writeFileSync(marker, day); log(`자동 백업 완료: ${r.path} (파일 ${r.files}개${r.removed.length ? `, 오래된 백업 ${r.removed.length}개 정리` : ''})`); }
    catch (e) { log('★ 자동 백업 실패:', e.message); }
  };
  setInterval(tick, 60e3).unref(); setTimeout(tick, 15e3).unref();
  log(`자동 백업: 매일 ${at}(한국 시간) → ${E.DIRS.backup} · 보존 ${process.env.AEGIS_BACKUP_KEEP || 30}개 · 키는 포함하지 않음`);
}
(async () => {
  for (const d of [E.DIRS.data, E.DIRS.run]) fs.mkdirSync(d, { recursive: true, mode: 0o750 });
  const env = E.applyEnv({ create: true });
  if (env.created) log(`처음 실행: 이 서버에서 암호 키를 새로 만들었습니다(${E.SECRETS}, 내용 표시 안 함). 자료 백업과 다른 매체에 따로 백업하세요: aegisctl backup-keys <경로>`);
  if (process.env.AEGIS_CADDYFILE) log('HTTPS 프록시 설정 생성: ' + require('./server-caddy').write());
  process.env.AEGIS2_SETUP_CODE = crypto.randomBytes(6).toString('hex').toUpperCase(); // 사용자 0명일 때만 쓰이는 1회 설정 코드
  const { main } = require('../src/server');
  const core = await main('all');
  for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => { log('종료합니다.'); process.exit(0); });
  const syncSetup = async () => {
    const n = Number((await core.db.get('SELECT COUNT(*) AS n FROM users')).n);
    if (n === 0) { if (!fs.existsSync(E.SETUP_FILE)) { fs.writeFileSync(E.SETUP_FILE, process.env.AEGIS2_SETUP_CODE + '\n', { mode: 0o600 }); log('★ 첫 관리자 만들기: 서버 콘솔에서 "sudo aegisctl setup-code"(도커: ./aegis.sh setup-code)로 설정 코드를 확인해 관리 앱 /setup 에 넣으세요.'); } }
    else if (fs.existsSync(E.SETUP_FILE)) fs.unlinkSync(E.SETUP_FILE);
  };
  try { fs.unlinkSync(E.SETUP_FILE); } catch (_) {} // 이전 실행의 코드는 무효
  await syncSetup(); setInterval(() => syncSetup().catch(() => {}), 30e3).unref();
  scheduleBackups();
  log(`시작 완료 · 장부: ${process.env.AEGIS2_ENV_LABEL} · 데이터 ${E.DIRS.data}`);
})().catch((e) => { console.error('[AEGIS2-server] 시작 실패:', e.message); process.exit(1); });
