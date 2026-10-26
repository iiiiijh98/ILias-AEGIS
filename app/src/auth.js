'use strict';
// 인증: 앱별 세션(현장/관리), 비밀번호(bcrypt), 관리 앱 MFA(TOTP) 필수, 실패 잠금, 재인증.
const bcrypt = require('bcryptjs');
const totp = require('./totp');
const { sha256, randomToken, nowIso, AppError } = require('./util');
const { canUseApp } = require('./perm');
const COOKIE = { field: 'aegis2_field', admin: 'aegis2_admin', board: 'aegis2_board', vault: 'aegis2_vault' };
function validatePassword(pw) {
  const s = String(pw || '');
  const kinds = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((r) => r.test(s)).length;
  if (s.length < 12 || kinds < 3) throw new AppError('비밀번호는 12자 이상, 영문 대·소문자·숫자·특수문자 중 3종 이상이어야 합니다.');
}
const hashPassword = (pw, rounds) => bcrypt.hash(String(pw), rounds || 12);
const checkPassword = (pw, h) => bcrypt.compare(String(pw || ''), h || '');
async function setting(db, key, d) { const r = await db.get('SELECT value FROM settings WHERE key=$1', [key]); return r ? r.value : d; }
async function ensureInitialAdmin(db, cfg) {
  const n = Number((await db.get('SELECT COUNT(*) AS n FROM users')).n);
  if (n > 0 || !cfg.initAdminPassword) return false;
  try { validatePassword(cfg.initAdminPassword); } catch (_) { console.warn('[AEGIS2] 초기 관리자 비밀번호가 기준 미달이라 계정을 만들지 않았습니다.'); return false; }
  await db.run('INSERT INTO users (username, display_name, password_hash, roles, created_at) VALUES ($1,$2,$3,$4,$5)', ['andy', '시스템관리자', await hashPassword(cfg.initAdminPassword, cfg.bcryptRounds), 'sysadmin', nowIso()]);
  return true;
}
async function createSession(db, app, { userId = null, deviceId = null, stage = 'full', ip }) {
  const token = randomToken(32); const csrf = randomToken(18); const now = nowIso();
  await db.run('INSERT INTO sessions (id_hash, app, user_id, device_id, csrf, stage, created_at, last_seen, ip) VALUES ($1,$2,$3,$4,$5,$6,$7,$7,$8)', [sha256(token), app, userId, deviceId, csrf, stage, now, ip || null]);
  return token;
}
async function destroySession(db, token) { if (token) await db.run('DELETE FROM sessions WHERE id_hash=$1', [sha256(token)]); }
// 세션은 그 앱에서 만든 것만 유효(app 컬럼 비교). 다른 앱 쿠키 값을 넣어도 통과하지 못합니다.
async function loadSession(db, app, token, cfg, userDb) {
  userDb = userDb || db;
  if (!token) return null;
  const s = await db.get('SELECT * FROM sessions WHERE id_hash=$1', [sha256(token)]);
  if (!s || s.app !== app) return null;
  const lim = cfg.session[app]; const now = Date.now();
  if (lim && (now - Date.parse(s.last_seen) > lim.idleMin * 60000 || now - Date.parse(s.created_at) > lim.maxHours * 3600000)) { await db.run('DELETE FROM sessions WHERE id_hash=$1', [s.id_hash]); return { expired: true }; }
  if (now - Date.parse(s.last_seen) > 30000) await db.run('UPDATE sessions SET last_seen=$1 WHERE id_hash=$2', [nowIso(), s.id_hash]);
  if (app === 'board') { const d = await userDb.get('SELECT * FROM devices WHERE id=$1 AND active=1', [s.device_id]); return d ? { session: s, device: d } : null; }
  const user = await userDb.get('SELECT * FROM users WHERE id=$1 AND active=1', [s.user_id]);
  if (!user || !canUseApp(user, app)) { await db.run('DELETE FROM sessions WHERE id_hash=$1', [s.id_hash]); return null; }
  return { session: s, user };
}
// 1단계 로그인. 관리 앱은 다음 단계로 TOTP(미등록이면 등록) 필수.
async function attemptLogin(db, app, username, password, ip) {
  const u = await db.get('SELECT * FROM users WHERE username=$1', [String(username || '').trim().toLowerCase()]);
  const fail = new AppError('아이디 또는 비밀번호가 올바르지 않습니다.', 401);
  if (!u || !u.active) { await checkPassword(password, '$2a$12$' + 'x'.repeat(53)); throw fail; }
  if (u.locked_until && Date.parse(u.locked_until) > Date.now()) throw new AppError('로그인 실패가 반복되어 잠긴 계정입니다. 관리자에게 문의하세요.', 423);
  if (!(await checkPassword(password, u.password_hash))) {
    const th = Number(await setting(db, 'lockout_threshold', 5)); const mins = Number(await setting(db, 'lockout_minutes', 15));
    const n = Number(u.failed_count) + 1;
    await db.run('UPDATE users SET failed_count=$1, locked_until=$2 WHERE id=$3', [n, n >= th ? new Date(Date.now() + mins * 60000).toISOString() : null, u.id]);
    throw fail;
  }
  if (!canUseApp(u, app)) throw new AppError(app === 'admin' ? '관리 앱을 쓸 수 있는 역할이 없습니다.' : '현장 앱을 쓸 수 있는 역할이 없습니다.', 403);
  await db.run('UPDATE users SET failed_count=0, locked_until=NULL WHERE id=$1', [u.id]);
  let stage = 'full';
  if (app === 'admin') stage = u.totp_enabled ? 'totp' : 'mfa_setup';
  else if (u.totp_enabled) stage = 'totp';
  const token = await createSession(db, app, { userId: u.id, stage, ip });
  if (stage === 'full') await db.run('UPDATE users SET last_login_at=$1 WHERE id=$2', [nowIso(), u.id]);
  return { token, stage, user: u };
}
async function promote(db, s) { await db.run("UPDATE sessions SET stage='full' WHERE id_hash=$1", [s.id_hash]); await db.run('UPDATE users SET last_login_at=$1 WHERE id=$2', [nowIso(), s.user_id]); }
async function reauth(user, password) { if (!(await checkPassword(password, user.password_hash))) throw new AppError('재인증 실패: 비밀번호가 올바르지 않습니다.', 403); }
// 관리 앱 민감 작업: 비밀번호 + TOTP 재확인
async function reauthStrong(user, password, code) { await reauth(user, password); if (!user.totp_enabled || !totp.verify(user.totp_secret, code)) throw new AppError('재인증 실패: 인증 앱 6자리 코드를 확인하세요.', 403); }
module.exports = { COOKIE, validatePassword, hashPassword, checkPassword, ensureInitialAdmin, createSession, destroySession, loadSession, attemptLogin, promote, reauth, reauthStrong, totp, setting };
