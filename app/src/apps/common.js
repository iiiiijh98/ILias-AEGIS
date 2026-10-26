'use strict';
// 현장·관리 앱 공통 로그인/계정 라우트
const auth = require('../auth'); const { writeAudit } = require('../audit'); const { wrap, csrfAfterUpload } = require('../http');
const V = require('../views'); const { AppError, kst } = require('../util'); const { fmt } = require('../units');
const ipOf = (req) => (req.app.get('trust proxy') ? req.ip : req.socket.remoteAddress);
const ctxOf = (req) => ({ db: req.app.locals.core.db, storage: req.app.locals.core.storage, cfg: req.cfg, user: req.user, app: req.appName, ip: ipOf(req) });
function loginRoutes(app, { title }) {
  const db = app.locals.core.db; const appName = app.locals.appName;
  app.get('/login', (req, res) => res.send(V.loginPage(req, { title, sub: appName === 'admin' ? '관리 앱 — 비밀번호 + 인증 앱(TOTP) 필수' : '현장 앱 — 등록 사용자만' })));
  app.post('/login', wrap(async (req, res) => {
    try {
      const r = await auth.attemptLogin(db, appName, req.body.username, req.body.password, ipOf(req));
      app.setCookie(res, r.token);
      await db.tx((t) => writeAudit(t, { app: appName, user: r.user, ip: ipOf(req) }, 'LOGIN_PASSWORD_OK', 'user', r.user.id, null, { stage: r.stage }));
      return res.redirect(303, r.stage === 'full' ? '/' : r.stage === 'totp' ? '/login/totp' : '/login/mfa-setup');
    } catch (e) {
      await db.tx((t) => writeAudit(t, { app: appName, actorName: String(req.body.username || '').slice(0, 30), ip: ipOf(req) }, 'LOGIN_FAIL', 'user', null, null, { status: e.status || 500 }));
      res.flash('err', e.message); return res.redirect(303, '/login');
    }
  }));
  app.get('/login/totp', (req, res) => (req.session && req.session.stage === 'totp' ? res.send(V.loginPage(req, { title: '2단계 인증', sub: '인증 앱의 6자리 코드', action: '/login/totp', extra: '<label>6자리 코드</label><input name="code" inputmode="numeric" autocomplete="one-time-code" required>' })) : res.redirect('/login')));
  app.post('/login/totp', wrap(async (req, res) => {
    if (!req.session || req.session.stage !== 'totp') return res.redirect(303, '/login');
    if (!auth.totp.verify(req.user.totp_secret, req.body.code)) { res.flash('err', '코드가 맞지 않습니다.'); return res.redirect(303, '/login/totp'); }
    await auth.promote(db, req.session); return res.redirect(303, '/');
  }));
  // 관리 앱: TOTP 미등록이면 등록부터(등록 전에는 어떤 화면도 못 봄)
  app.get('/login/mfa-setup', wrap(async (req, res) => {
    if (!req.session || req.session.stage !== 'mfa_setup') return res.redirect('/login');
    let sec = req.user.totp_secret; if (!sec || req.user.totp_enabled) { sec = auth.totp.generateSecret(); await db.run('UPDATE users SET totp_secret=$1 WHERE id=$2', [sec, req.user.id]); }
    const uri = `otpauth://totp/ILias%20AEGIS%20v2:${encodeURIComponent(req.user.username)}?secret=${sec}&issuer=ILias%20AEGIS%20v2`;
    const qr = await require('qrcode').toDataURL(uri);
    res.send(V.loginPage(req, { title: '인증 앱 등록(필수)', sub: '관리 앱은 2단계 인증 없이 쓸 수 없습니다. QR을 인증 앱으로 찍고 6자리 코드를 넣으세요.', action: '/login/mfa-setup', extra: `<img src="${qr}" alt="QR" style="width:200px"><p class="mono small">${V.esc(sec)}</p><label>6자리 코드</label><input name="code" inputmode="numeric" required>` }));
  }));
  app.post('/login/mfa-setup', wrap(async (req, res) => {
    if (!req.session || req.session.stage !== 'mfa_setup') return res.redirect(303, '/login');
    const u = await db.get('SELECT * FROM users WHERE id=$1', [req.user.id]);
    if (!u.totp_secret || !auth.totp.verify(u.totp_secret, req.body.code)) { res.flash('err', '코드가 맞지 않습니다.'); return res.redirect(303, '/login/mfa-setup'); }
    await db.tx(async (t) => { await t.run('UPDATE users SET totp_enabled=1 WHERE id=$1', [u.id]); await writeAudit(t, ctxOf(req), 'MFA_ENABLE', 'user', u.id, null, { totp: true }); });
    await auth.promote(db, req.session); res.redirect(303, '/');
  }));
  app.post('/logout', wrap(async (req, res) => { await auth.destroySession(db, req.token); app.clearCookie(res); res.redirect(303, '/login'); }));
  app.get('/me/password', (req, res) => res.send(V.page(req, { title: '비밀번호 변경', body: `<div class="card" style="max-width:480px"><h1>비밀번호 변경</h1><form class="f" method="post">${V.csrf(req)}<label>현재 비밀번호</label><input type="password" name="password" required><label>새 비밀번호(12자 이상, 3종)</label><input type="password" name="new_password" required><button>변경</button></form></div>` })));
  app.post('/me/password', wrap(async (req, res) => {
    await auth.reauth(req.user, req.body.password); auth.validatePassword(req.body.new_password);
    await db.tx(async (t) => { await t.run('UPDATE users SET password_hash=$1, must_change_pw=0 WHERE id=$2', [await auth.hashPassword(req.body.new_password, req.cfg.bcryptRounds), req.user.id]); await t.run('DELETE FROM sessions WHERE user_id=$1 AND id_hash<>$2', [req.user.id, req.session.id_hash]); await writeAudit(t, ctxOf(req), 'PASSWORD_CHANGE', 'user', req.user.id, null, {}); });
    res.flash('ok', '비밀번호를 바꿨습니다.'); res.redirect(303, '/');
  }));
}
// 로그인 필수(완료 단계) + 첫 로그인 비밀번호 변경 강제
const requireFull = (req, res, next) => {
  if (['/login', '/login/totp', '/login/mfa-setup', '/logout', '/healthz', '/setup'].includes(req.path) || req.path.startsWith('/static/')) return next();
  if (!req.user || !req.session || req.session.stage !== 'full') { if (req.method === 'GET') return res.redirect('/login'); return next(new AppError('로그인이 필요합니다.', 401)); }
  if (req.user.must_change_pw && !req.path.startsWith('/me/password')) return res.redirect('/me/password');
  next();
};
// 업로드 라우트: multer → CSRF 검사 → 처리
const upload = (app, fields) => [app.upload.fields(fields.map((name) => ({ name, maxCount: 1 }))), (req, res, next) => { try { csrfAfterUpload(req); next(); } catch (e) { next(e); } }];
// 계량 기록 표(완료·차단 뒤에만 보여 줌 → 블라인드 유지)
async function readingsTable(db, refType, refId, done) {
  if (!done) return '<div class="blind">입회 판독이 끝나기 전에는 계량값과 판정을 표시하지 않습니다(블라인드).</div>';
  const rows = await db.all('SELECT w.*, s.scale_id AS sid, u.display_name FROM weighings w LEFT JOIN scales s ON s.id=w.scale_id LEFT JOIN users u ON u.id=w.by_user WHERE w.ref_type=$1 AND w.ref_id=$2 ORDER BY w.id', [refType, refId]);
  return V.table(['단계', '칸', '역할', '회차', '값', '저울', '방식', '입력자', '시각'], rows.map((w) => [V.esc(w.purpose), V.esc(w.slot), w.role === 'witness' ? '입회(블라인드)' : '계량', String(w.attempt), fmt(w.value_ug), V.esc(w.sid || '-'), V.esc(w.method), V.esc(w.display_name || ''), kst(w.at, true)]));
}
const scaleOptions = async (db) => (await db.all('SELECT * FROM scales WHERE active=1 ORDER BY scale_id')).map((s) => `<option value="${s.id}">${V.esc(s.scale_id)} (d=${fmt(s.resolution_ug, 6)}, 교정 ${V.esc(s.calib_due || '미등록')})</option>`).join('');
module.exports = { loginRoutes, requireFull, upload, readingsTable, scaleOptions, ctxOf, ipOf };
