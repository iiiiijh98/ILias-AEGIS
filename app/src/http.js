'use strict';
// 앱 공통 HTTP 뼈대: 앱별 쿠키·세션(app 컬럼), CSRF, 업로드, 오류. 다른 앱 쿠키는 통과하지 못합니다.
const express = require('express'); const path = require('path'); const multer = require('multer');
const auth = require('./auth'); const { AppError } = require('./util');
const { buildAllowList } = require('./netallow');
function parseCookies(h) { const o = {}; String(h || '').split(';').forEach((p) => { const i = p.indexOf('='); if (i > 0) o[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim()); }); return o; }
function base(core, appName, { allowCidrs } = {}) {
  const { cfg } = core; const app = express();
  app.disable('x-powered-by'); if (cfg.trustProxy) app.set('trust proxy', 1);
  app.locals.core = core; app.locals.appName = appName;
  if (allowCidrs && allowCidrs !== '*') {
    const allow = buildAllowList(allowCidrs);
    app.use((req, res, next) => (allow.check(cfg.trustProxy ? req.ip : req.socket.remoteAddress) ? next() : res.status(403).type('text/plain; charset=utf-8').send('403 허용되지 않은 네트워크입니다.')));
  }
  app.use((req, res, next) => { res.set({ 'X-Frame-Options': 'DENY', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'Cache-Control': 'no-store', 'Content-Security-Policy': "default-src 'self'; img-src 'self' blob: data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'; form-action 'self'" }); next(); });
  app.use('/static', express.static(path.join(cfg.root, 'public'), { maxAge: '1h', index: false }));
  app.get('/healthz', (req, res) => res.json({ ok: true, app: appName }));
  app.use(express.urlencoded({ extended: true, limit: '200kb' }));
  const cookieName = (cfg.cookieSecure ? '__Host-' : '') + auth.COOKIE[appName];
  app.locals.cookieName = cookieName;
  // 알림(flash) 쿠키도 앱별 이름: 서버판은 한 호스트의 여러 HTTPS 포트에 앱을 두므로(쿠키는 포트를 구분하지 않음) 섞이지 않게 합니다.
  const flashName = `${auth.COOKIE[appName]}_flash`;
  app.setCookie = (res, token) => res.append('Set-Cookie', `${cookieName}=${token}; Path=/; HttpOnly; SameSite=${appName === 'field' ? 'Lax' : 'Strict'}${cfg.cookieSecure ? '; Secure' : ''}`);
  app.clearCookie = (res) => res.append('Set-Cookie', `${cookieName}=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict${cfg.cookieSecure ? '; Secure' : ''}`);
  app.use(async (req, res, next) => {
    try {
      req.cfg = cfg; req.appName = appName; req.cookies = parseCookies(req.headers.cookie);
      req.token = req.cookies[cookieName];
      const fl = req.cookies[flashName]; if (fl) { try { req.flash = JSON.parse(Buffer.from(fl, 'base64url').toString()); } catch (_) {} res.append('Set-Cookie', `${flashName}=; Path=/; Max-Age=0`); }
      res.flash = (type, msg) => res.append('Set-Cookie', `${flashName}=${Buffer.from(JSON.stringify({ type, msg })).toString('base64url')}; Path=/; HttpOnly; SameSite=Lax`);
      next();
    } catch (e) { next(e); }
  });
  app.upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: cfg.maxUploadBytes, files: 4 } });
  return app;
}
// 세션 로드 + CSRF(POST). sessionDb = 세션 테이블이 있는 DB(현장·관리 = 업무 DB, Vault = 매핑 DB)
function sessionMw(app, sessionDb, userDb, { publicPaths = [] } = {}) {
  const cfg = app.locals.core.cfg; const appName = app.locals.appName;
  return async (req, res, next) => {
    try {
      const s = await auth.loadSession(sessionDb, appName === 'vault' ? 'vault' : appName, req.token, { ...cfg, session: { ...cfg.session, vault: { idleMin: 5, maxHours: 1 } } }, userDb);
      if (s && s.session) { req.session = s.session; req.user = s.user; req.device = s.device; }
      if (req.method === 'POST' && !publicPaths.includes(req.path)) {
        const tok = (req.body && req.body._csrf) || req.headers['x-csrf-token'];
        if (!req.session || !tok || tok !== req.session.csrf) {
          if (req.is('multipart/form-data') && req.session) return next(); // multipart는 라우트에서 업로드 처리 뒤 검사
          throw new AppError('보안 토큰이 맞지 않습니다. 화면을 새로고침한 뒤 다시 시도하세요.', 403);
        }
      }
      next();
    } catch (e) { next(e); }
  };
}
const csrfAfterUpload = (req) => { if (!req.session || !req.body || req.body._csrf !== req.session.csrf) throw new AppError('보안 토큰이 맞지 않습니다.', 403); };
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
function errors(app, renderErr) {
  app.use((req, res) => res.status(404).type('text/plain; charset=utf-8').send('404 찾을 수 없습니다.'));
  app.use((err, req, res, _next) => {
    const status = err.status || (err.code === 'LIMIT_FILE_SIZE' ? 413 : 500); const msg = err.expose || status < 500 ? err.message : '처리 중 오류가 났습니다.';
    if (status >= 500 && !err.expose) console.error('[AEGIS2]', err && err.stack ? err.stack.split('\n').slice(0, 3).join(' | ') : err);
    if (req.method === 'POST' && req.headers.referer && status < 500 && status !== 403) { res.flash('err', msg); return res.redirect(303, new URL(req.headers.referer).pathname + (new URL(req.headers.referer).search || '')); }
    res.status(status); if (req.accepts(['html', 'json']) === 'json') return res.json({ error: msg }); res.type('html').send(renderErr ? renderErr(req, status, msg) : `<p>${status} ${msg}</p>`);
  });
}
module.exports = { base, sessionMw, csrfAfterUpload, wrap, errors, parseCookies };
