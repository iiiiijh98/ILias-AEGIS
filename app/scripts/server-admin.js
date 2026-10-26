'use strict';
// 서버 콘솔 관리 명령(aegisctl / aegis.sh 가 부릅니다). 비밀값 내용은 출력하지 않습니다(설정 코드만 예외: 콘솔 확인용).
const fs = require('fs'); const path = require('path'); const http = require('http');
const E = require('./server-env'); const B = require('./server-backup');
const health = (port) => new Promise((r) => { const q = http.get({ host: '127.0.0.1', port, path: '/healthz', timeout: 1500 }, (res) => { res.resume(); r(res.statusCode === 200); }); q.on('error', () => r(false)); q.on('timeout', () => { q.destroy(); r(false); }); });
const running = async () => (await health(Number(process.env.AEGIS2_FIELD_PORT || 3201))) || (await health(Number(process.env.AEGIS2_ADMIN_PORT || 3202)));
const MB = (n) => (n / 1048576).toFixed(1) + ' MB';
async function verify() {
  E.applyEnv({ create: false });
  const { createCore } = require('../src/server'); const { verifyChain } = require('../src/audit'); const { createVault, decrypt, loadKey } = require('../src/vault');
  const core = await createCore(); const a = await verifyChain(core.db);
  const users = Number((await core.db.get('SELECT COUNT(*) AS n FROM users')).n);
  const vault = createVault(core.cfg); await vault.migrate(); const v = await vault.verifyLog();
  const row = await vault.db.get('SELECT * FROM mappings ORDER BY id DESC LIMIT 1'); let key = '매핑 없음(검사 생략)';
  if (row) { try { decrypt(loadKey(core.cfg.mappingKey), row); key = '정상(현재 키로 복호화됨)'; } catch (_) { key = '실패 — 이 데이터와 키가 짝이 아닙니다. 해당 시점의 키 백업을 복원하세요.'; } }
  console.log(`감사 로그 해시 체인: ${a.ok ? '정상' : '이상(' + (a.brokenAt || '') + ')'} · ${a.count ?? ''}건`);
  console.log(`매핑 열람 기록 체인: ${v.ok ? '정상' : '이상(' + v.brokenAt + ')'} · ${v.count}건`);
  console.log(`매핑 키 확인: ${key}`); console.log(`사용자 수: ${users}`);
  await vault.close?.(); await core.db.close?.();
  return a.ok && v.ok && !/실패/.test(key);
}
const cmds = {
  async init() {
    const s = E.loadSecrets({ create: true });
    console.log(s.created ? `[처음 설치] 이 서버에서 암호 키를 새로 만들었습니다: ${E.SECRETS} (내용은 표시하지 않음)\n ★ 이 키 폴더는 자료 백업과 다른 매체에 따로 백업하세요: aegisctl backup-keys <USB 경로>` : `암호 키가 이미 있습니다(${E.SECRETS}). 새로 만들지 않았습니다.`);
    if (process.env.AEGIS_CADDYFILE) console.log('Caddyfile 생성: ' + require('./server-caddy').write());
  },
  async caddyfile() { console.log('Caddyfile 생성: ' + require('./server-caddy').write()); },
  async 'setup-code'() {
    if (!fs.existsSync(E.SETUP_FILE)) { console.log('설정 코드가 없습니다. 이미 첫 관리자를 만들었거나, 서비스가 아직 시작되지 않았습니다.'); return; }
    console.log('첫 관리자 설정 코드: ' + fs.readFileSync(E.SETUP_FILE, 'utf8').trim() + '   (관리 앱 https://<서버>:8443/setup 에 입력, 서비스를 다시 시작하면 바뀜)');
  },
  async backup() { const r = B.runBackup({ reason: 'manual' }); console.log(`백업 완료: ${r.path} · 파일 ${r.files}개 · ${MB(r.bytes)}${r.removed.length ? ` · 보존 기간 지난 백업 ${r.removed.length}개 정리` : ''}\n(암호 키는 포함하지 않았습니다. 키는 aegisctl backup-keys 로 별도 보관)`); },
  async 'list-backups'() { const l = B.listBackups(); console.log(l.length ? l.map((n) => path.join(E.DIRS.backup, n)).join('\n') : '백업이 없습니다.'); },
  async restore(src) {
    if (!src) throw new Error('복원할 백업 폴더를 지정하세요(aegisctl list-backups).');
    if (await running()) throw new Error('AEGIS가 실행 중입니다. 먼저 서비스를 멈추세요(aegisctl stop).');
    const r = B.restore(src); console.log(`복원 완료: 파일 ${r.restored}개 (백업 시각 ${require('../src/util').kst(r.created_at)} KST)${r.previous ? `\n복원 전 데이터는 ${r.previous} 로 옮겨 두었습니다(확인 후 직접 삭제).` : ''}`);
    if (!(await verify())) { console.log('★ 검사에서 이상이 있습니다. 서비스를 시작하기 전에 확인하세요.'); process.exitCode = 2; }
  },
  async 'backup-keys'(dest, flag) { const r = B.backupKeys(dest, { force: flag === '--force' }); console.log(`키 백업 완료: ${r.path} (${r.copied.join(', ')})\n ★ 경고: 이 폴더와 자료 백업을 함께 가진 사람은 매핑(품명 등)을 풀 수 있습니다. 자료 백업과 다른 매체·다른 보관자에게 두고, 매체는 잠금 보관하세요.`); },
  async 'restore-keys'(src) {
    if (!src) throw new Error('키 백업 폴더(aegis-keys-...)를 지정하세요.');
    if (await running()) throw new Error('AEGIS가 실행 중입니다. 먼저 서비스를 멈추세요.');
    const s = path.join(path.resolve(src), 'secrets.json'); if (!fs.existsSync(s)) throw new Error('secrets.json이 없습니다.');
    const j = JSON.parse(fs.readFileSync(s, 'utf8')); if (!j.mappingKey || Buffer.from(j.mappingKey, 'base64').length !== 32 || !j.vaultLinkSecret) throw new Error('키 파일 형식 오류');
    fs.mkdirSync(E.DIRS.keys, { recursive: true, mode: 0o700 });
    if (fs.existsSync(E.SECRETS)) fs.renameSync(E.SECRETS, E.SECRETS + '.replaced-' + B.stamp());
    fs.copyFileSync(s, E.SECRETS); fs.chmodSync(E.SECRETS, 0o600);
    const an = path.join(path.resolve(src), 'audit_anchors.jsonl'); if (fs.existsSync(an)) { fs.copyFileSync(an, path.join(E.DIRS.keys, 'audit_anchors.jsonl')); fs.chmodSync(path.join(E.DIRS.keys, 'audit_anchors.jsonl'), 0o600); }
    console.log('키 복원 완료(내용은 표시하지 않음). 이전 키 파일은 .replaced-<시각> 으로 남겼습니다.');
  },
  async verify() { if (!(await verify())) process.exitCode = 2; },
};
const [cmd, ...args] = process.argv.slice(2);
if (!cmds[cmd]) { console.log('사용: server-admin.js ' + Object.keys(cmds).join('|')); process.exit(cmd ? 1 : 0); }
cmds[cmd](...args).catch((e) => { console.error('오류:', e.message); process.exit(1); });
