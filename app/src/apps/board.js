'use strict';
// 전광판(상황판): 사람 로그인 없음. 관리 앱에서 발급한 단말 연결 코드로만 연결, 읽기 전용, 허용 목록 집계만 표시.
// 품목명·코드·건번호·사람 이름·매핑 관련 정보는 화면 데이터에 아예 넣지 않습니다(v1 화면 구성은 유지).
const http = require('../http'); const { wrap } = http; const V = require('../views'); const svc = require('../services');
const auth = require('../auth'); const { sha256, kst, nowIso, AppError } = require('../util'); const { buildAllowList } = require('../netallow'); const { writeAudit } = require('../audit');
const C = require('./common');
function bars(series, labels, colors) {
  const W = 520, H = 300, max = Math.max(1, ...series.flat()); const gw = W / labels.length; const bw = (gw - 16) / series.length;
  let s = `<svg viewBox="0 0 ${W} ${H + 30}" width="100%">`;
  labels.forEach((l, i) => { series.forEach((ser, j) => { const h = Math.round((ser[i] / max) * H); s += `<rect x="${i * gw + 8 + j * bw}" y="${H - h}" width="${bw - 2}" height="${h}" fill="${colors[j]}"/>`; }); s += `<text x="${i * gw + gw / 2}" y="${H + 20}" fill="#7fb3ae" font-size="13" text-anchor="middle">${V.esc(l)}</text>`; });
  return s + '</svg>';
}
function createBoardApp(core) {
  const app = http.base(core, 'board', { allowCidrs: core.cfg.boardAllowCidrs }); const db = core.db; const esc = V.esc;
  // 쓰기 동작 없음: 연결(/pair) 외 GET 아닌 요청은 모두 거부
  app.use((req, res, next) => (req.method === 'GET' || req.method === 'HEAD' || (req.method === 'POST' && req.path === '/pair') ? next() : next(new AppError('전광판은 읽기 전용입니다.', 405))));
  app.use(http.sessionMw(app, db, db, { publicPaths: ['/pair'] }));
  const pairPage = (req, msg) => V.head('전광판 연결') + `<body class="wb"><div class="wtop"><img src="/static/ilias_ai_logo_on_dark.png" alt="ILias AI"><b>AEGIS v2 · 상황판 연결</b></div><div style="max-width:560px;margin:80px auto"><p>관리 앱(전광판 단말)에서 받은 연결 코드를 넣으세요. 이 화면은 읽기 전용입니다.</p>${msg ? `<p style="color:#f87171">${esc(msg)}</p>` : ''}<form method="post" action="/pair"><input name="token" style="width:100%;font-size:20px" autocomplete="off" required><button>연결</button></form><p style="opacity:.6;font-size:12px;margin-top:40px">${V.ABOUT}</p></div></body></html>`;
  app.get('/pair', (req, res) => res.send(pairPage(req)));
  app.post('/pair', wrap(async (req, res) => {
    const d = await db.get("SELECT * FROM devices WHERE token_hash=$1 AND kind='board' AND active=1", [sha256(String(req.body.token || '').trim())]);
    const ip = C.ipOf(req);
    if (!d || (d.allow_cidrs && !buildAllowList(d.allow_cidrs).check(ip))) { await db.tx((t) => writeAudit(t, { app: 'board', actorName: 'board', ip }, 'DEVICE_PAIR_FAIL', 'device', d ? d.id : null, null, {})); return res.status(403).send(pairPage(req, '연결 코드가 맞지 않거나 허용되지 않은 위치입니다.')); }
    const token = await auth.createSession(db, 'board', { deviceId: d.id, ip }); app.setCookie(res, token);
    await db.run('UPDATE devices SET last_seen=$1 WHERE id=$2', [nowIso(), d.id]);
    await db.tx((t) => writeAudit(t, { app: 'board', actorName: `device:${d.id}`, ip }, 'DEVICE_PAIR', 'device', d.id, null, {}));
    res.redirect(303, '/');
  }));
  const needDevice = (req, res, next) => { if (!req.device) return req.accepts(['html', 'json']) === 'json' ? res.status(401).json({ error: 'pair' }) : res.redirect('/pair'); if (req.device.allow_cidrs && !buildAllowList(req.device.allow_cidrs).check(C.ipOf(req))) return next(new AppError('허용되지 않은 위치입니다.', 403)); next(); };
  app.get('/api/board', needDevice, wrap(async (req, res) => res.json(await svc.boardData(db))));
  app.get('/', needDevice, wrap(async (req, res) => {
    const b = await svc.boardData(db); const k = b.k;
    const cells = [['보관 용기', k.containers, ''], ['오늘 반출', k.todayOut, ''], ['반납 대기', k.outstanding, k.outstanding ? 'warn' : ''], ['미해소 이상', k.openAnomalies, k.openAnomalies ? 'err' : ''], ['입회 대기', k.pendingWitness, k.pendingWitness ? 'warn' : ''], ['사고 보고 진행', k.incidentsOpen, k.incidentsOpen ? 'err' : '']];
    const series = [b.series.out, b.series.ret]; if (b.showAmounts) series.push(b.series.amountOut);
    const body = `<body class="wb"><div class="wtop"><img src="/static/ilias_ai_logo_on_dark.png" alt="ILias AI"><b>AEGIS · 상황판</b><span style="color:#7fb3ae">읽기 전용 · 30초마다 자동 갱신 · 갱신 ${kst(new Date().toISOString(), true)} KST</span><span class="clock" id="clock"></span></div>
    <div class="cnt">${cells.map(([l, v, c]) => `<div class="c ${c}"><div class="l">${l}</div><div class="v">${v}</div></div>`).join('')}</div>
    <div class="wgrid"><div class="p"><h3>보관 위치 상태</h3>${b.locs.map((l) => `<div class="vault"><span><span class="dot ${l.q ? 'w' : ''}"></span>${esc(l.name)}</span><span>용기 ${l.cnt}${l.q ? ` · 격리·보류 ${l.q}` : ''}</span></div>`).join('') || '<p style="color:#7fb3ae">등록된 위치 없음</p>'}</div>
    <div class="p"><h3>진행 단계별 건수</h3><table><tr><th>단계</th><th>건수</th></tr>${b.stages.map((s) => `<tr><td>${esc(svc.CO_STATUS[s.status] || s.status)}</td><td>${Number(s.n)}</td></tr>`).join('') || '<tr><td colspan="2">진행 건 없음</td></tr>'}</table></div>
    <div class="p bars"><h3>최근 7일 추이(건수${b.showAmounts ? ' · 반출 g' : ''})</h3>${bars(series, b.days.map((d) => d.slice(5)), ['#14b8a6', '#60a5fa', '#fbbf24'])}</div></div>
    <div class="stream">${b.stream.map((s) => `<div>[${kst(s.at, true)}] ${esc(s.cat)}</div>`).join('')}</div><div style="opacity:.55;font-size:11px;text-align:center;padding:6px">${V.ABOUT}</div><script src="/static/app.js"></script></body></html>`;
    res.send(V.head('상황판', '<meta http-equiv="refresh" content="30">') + body);
  }));
  http.errors(app, (req, s, m) => `<p>${s} ${esc(m)}</p>`);
  return app;
}
module.exports = { createBoardApp };
