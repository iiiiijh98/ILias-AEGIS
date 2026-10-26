'use strict';
// 매핑 금고(Vault) — 별도 프로세스·별도 포트·별도 DB·별도 로그인(비밀번호 + 인증 앱 코드를 매번).
// 관리 앱 API로는 닿을 수 없고, 관리 앱은 /internal/meta(HMAC 서명, 건수만)만 호출할 수 있습니다.
const http = require('../http'); const { wrap } = http; const V = require('../views');
const auth = require('../auth'); const { rolesOf, ROLES } = require('../perm'); const { kst, kstDate, nowIso, AppError } = require('../util'); const { fmt } = require('../units');
const link = require('./vaultlink'); const C = require('./common');
const REASONS = { INSPECTION: '관청 점검 대응', LEGAL_LEDGER: '법정 장부 기재', MONTHLY_REPORT: '정기 보고 작성', INCIDENT: '사고 보고 작성', REGISTRATION_CHECK: '등록 내용 확인' };
function createVaultApp(core) {
  // core: { cfg, db: 업무 DB(사용자 확인·코드·기록 읽기), vault: createVault() }
  const app = http.base(core, 'vault', { allowCidrs: core.cfg.vaultAllowCidrs }); const db = core.db; const vault = core.vault; const esc = V.esc;
  // 관리 앱 서명 메타 조회 — 세션·CSRF 앞에서 처리, 내용 없이 건수만
  app.get('/internal/meta', wrap(async (req, res) => {
    const q = { ts: req.get('x-aegis-ts'), path: '/internal/meta', actor: req.get('x-aegis-actor'), sig: req.get('x-aegis-sig') };
    if (!link.verify(core.cfg.vaultLinkSecret, q)) { await vault.log({ actorName: 'admin-link', ip: C.ipOf(req) }, 'meta_denied', null, '서명 불일치'); return res.status(401).json({ error: 'signature' }); }
    await vault.log({ actorName: `admin:${String(q.actor).slice(0, 30)}`, ip: C.ipOf(req) }, 'meta', null, '관리 앱 메타 조회');
    const mapped = await vault.mappedCodes(); const lv = await vault.verifyLog();
    res.json({ enabled: vault.enabled, mappedCount: Object.keys(mapped).length, pendingRequests: (await vault.pending()).length, hasPermit: await vault.hasPermit(), logOk: lv.ok });
  }));
  app.use(http.sessionMw(app, vault.db, db, { publicPaths: ['/login'] }));
  const ctx = (req) => ({ user: req.user, app: 'vault', ip: C.ipOf(req) });
  const login = (req, msg) => V.loginPage(req, { title: '매핑 금고 로그인', sub: '비밀번호와 인증 앱 코드가 모두 필요합니다. 모든 접속·열람은 기록됩니다.', extra: `${msg ? `<p class="lvl-err">${esc(msg)}</p>` : ''}<label>아이디</label><input name="username" autocomplete="username" required><label>비밀번호</label><input type="password" name="password" required><label>인증 앱 6자리</label><input name="code" inputmode="numeric" required>` });
  app.get('/login', (req, res) => res.send(login(req)));
  app.post('/login', wrap(async (req, res) => {
    const name = String(req.body.username || '').trim().toLowerCase(); const ip = C.ipOf(req);
    const u = await db.get('SELECT * FROM users WHERE username=$1 AND active=1', [name]);
    const ok = u && !(u.locked_until && Date.parse(u.locked_until) > Date.now()) && (await auth.checkPassword(req.body.password, u.password_hash)) && u.totp_enabled && auth.totp.verify(u.totp_secret, req.body.code) && rolesOf(u).some((r) => ['sysadmin', 'mapping_deputy', 'permit_holder'].includes(r));
    if (!ok) { await vault.log({ actorName: name.slice(0, 30) || '-', ip }, 'login_fail', null, '-'); return res.status(401).send(login(req, '로그인할 수 없습니다(아이디·비밀번호·인증 코드·권한 확인).')); }
    const token = await auth.createSession(vault.db, 'vault', { userId: u.id, ip }); app.setCookie(res, token);
    await vault.log({ user: u, ip }, 'login', null, '-'); res.redirect(303, '/');
  }));
  app.post('/logout', wrap(async (req, res) => { await auth.destroySession(vault.db, req.token); app.clearCookie(res); res.redirect(303, '/login'); }));
  app.use((req, res, next) => { if (!req.user) return req.method === 'GET' ? res.redirect('/login') : next(new AppError('로그인이 필요합니다.', 401)); next(); });
  const has = (req, ...r) => rolesOf(req.user).some((x) => r.includes(x));
  const nav = (req) => [['/', '금고'], has(req, 'sysadmin') && ['/mappings', '매핑'], has(req, 'mapping_deputy') && ['/requests', '승인 대기'], has(req, 'mapping_deputy') && ['/emergency', '비상 열람'], has(req, 'sysadmin') && ['/permit', '허가 정보'], ['/ledger', '점검 대장'], ['/log', '열람 기록']].filter(Boolean);
  const wm = (req) => `<div class="wm">${Array.from({ length: 24 }, () => `${esc(req.user.username)} · ${kst(nowIso(), true)} · 외부 반출 금지`).map((t) => `<span>${t}</span>`).join('')}</div>`;
  const maskJs = '<script>(function(){var b=document.body;function m(){b.classList.add("mask")}setTimeout(m,30000);window.addEventListener("blur",m);document.addEventListener("visibilitychange",function(){if(document.hidden)m()});})();</script>';
  const pg = (req, title, body, secret = false) => V.page(req, { title, body: (secret ? wm(req) : '') + body + (secret ? maskJs : ''), nav: nav(req) });
  const reasonSel = () => `<label>열람 사유</label><select name="reason_code">${Object.entries(REASONS).map(([k, v]) => `<option value="${k}">${v}</option>`).join('')}</select><label>상세(선택, 품명 쓰지 않음)</label><input name="reason_note">`;
  const reasonOf = (b) => { if (!REASONS[b.reason_code]) throw new AppError('사유를 고르세요.'); return `${b.reason_code}${b.reason_note ? ': ' + String(b.reason_note).slice(0, 200) : ''}`; };
  const fieldsTable = (f) => `<table class="secret">${vault.FIELDS.map(([k, l]) => `<tr><th>${esc(l)}</th><td>${esc(f[k] || '')}</td></tr>`).join('')}</table>`;
  const done = (res, msg, to) => { res.flash('ok', msg); res.redirect(303, to); };

  app.get('/', wrap(async (req, res) => {
    const lv = await vault.verifyLog();
    res.send(pg(req, '매핑 금고', `<h1>매핑 금고</h1><div class="card">${vault.enabled ? V.badge('매핑 기능 사용', 'ok') : V.badge(vault.onCloud ? '클라우드 실행 — 매핑 꺼짐' : '키 없음 — 매핑 꺼짐', 'warn')} · 내 역할 ${esc(rolesOf(req.user).map((r) => ROLES[r]).join(', '))} · 열람 기록 체인 ${lv.ok ? `정상(${lv.count}건)` : V.badge('이상', 'err')}</div><div class="card small muted">화면은 30초 뒤 또는 창을 벗어나면 가려집니다. 화면 촬영·복사·외부 전송 금지.</div>`));
  }));
  // ── 매핑(시스템관리자)
  app.get('/mappings', wrap(async (req, res) => {
    if (!has(req, 'sysadmin')) throw new AppError('시스템관리자만 볼 수 있습니다.', 403);
    const codes = await db.all('SELECT code FROM item_codes ORDER BY code'); const mapped = await vault.mappedCodes();
    res.send(pg(req, '매핑', `<h1>코드 매핑</h1><div class="card">${V.table(['코드', '매핑 버전', '열람', '등록·변경 요청'], codes.map((c) => [`<span class="mono">${esc(c.code)}</span>`, mapped[c.code] ? `v${mapped[c.code]}` : V.badge('미등록', 'warn'), mapped[c.code] ? `<form method="post" action="/mappings/view" class="flex">${V.csrf(req)}<input type="hidden" name="code" value="${esc(c.code)}">${reasonSel()}<input type="password" name="password" placeholder="비밀번호 재인증" required><button class="s">열람</button></form>` : '', `<a href="/mappings/request?code=${encodeURIComponent(c.code)}">요청</a>`]))}</div>`));
  }));
  app.post('/mappings/view', wrap(async (req, res) => {
    await auth.reauth(req.user, req.body.password); const reason = reasonOf(req.body);
    const r = await vault.view(ctx(req), String(req.body.code), reason);
    res.send(pg(req, '매핑 열람', `<h1>${esc(req.body.code)} 매핑 v${r ? r.version : '-'}</h1><div class="card">${r ? fieldsTable(r.fields) : '없음'}<p class="small muted">이 열람은 기록되었습니다(사유: ${esc(reason)}).</p></div>`, true));
  }));
  app.get('/mappings/request', wrap(async (req, res) => {
    if (!has(req, 'sysadmin')) throw new AppError('권한이 없습니다.', 403);
    res.send(pg(req, '매핑 요청', `<form class="f card" method="post" action="/mappings/request">${V.csrf(req)}<h1>매핑 등록·변경 요청</h1><p class="muted">지정 대행자(본인 외) 승인 후 반영됩니다.</p><label>코드</label><input name="code" value="${esc(req.query.code || '')}" required>${vault.FIELDS.map(([k, l]) => `<label>${esc(l)}</label><input name="${k}" autocomplete="off">`).join('')}<label>요청 사유</label><input name="reason" required>${V.pw()}<button>요청</button></form>`, true));
  }));
  app.post('/mappings/request', wrap(async (req, res) => {
    await auth.reauth(req.user, req.body.password); const code = String(req.body.code || '').trim();
    if (!(await db.get('SELECT id FROM item_codes WHERE code=$1', [code]))) throw new AppError('발급된 코드가 아닙니다.');
    if (!String(req.body.reason || '').trim()) throw new AppError('사유를 입력하세요.');
    await vault.request(ctx(req), code, req.body, String(req.body.reason).slice(0, 300)); done(res, '요청했습니다. 지정 대행자 승인을 기다립니다.', '/mappings');
  }));
  // ── 승인(지정 대행자)
  app.get('/requests', wrap(async (req, res) => {
    if (!has(req, 'mapping_deputy')) throw new AppError('권한이 없습니다.', 403);
    const rows = await vault.pending();
    const batches = [...new Set(rows.filter((r) => Number(r.requested_by) !== req.user.id).map((r) => r.reason))];
    res.send(pg(req, '승인 대기', `<h1>매핑 승인 대기</h1>${batches.map((b) => `<form class="flex card" method="post" action="/requests/bulk">${V.csrf(req)}<input type="hidden" name="reason" value="${esc(b)}"><span>묶음 <b>${esc(b)}</b> · ${rows.filter((r) => r.reason === b && Number(r.requested_by) !== req.user.id).length}건</span><input type="password" name="password" placeholder="비밀번호" required><input name="code" placeholder="인증 앱 6자리" required><button class="s">묶음 전체 승인(각 건 기록)</button></form>`).join('')}<div class="card">${V.table(['#', '코드', '버전', '사유', ''], rows.map((r) => [String(r.id), `<span class="mono">${esc(r.code)}</span>`, `v${r.version}`, esc(r.reason), Number(r.requested_by) === req.user.id ? '본인 요청' : `<form method="post" action="/requests/${r.id}/review" class="flex">${V.csrf(req)}<input type="password" name="password" placeholder="비밀번호" required><button class="s">내용 확인</button></form>`]))}</div>`));
  }));
  app.post('/requests/bulk', wrap(async (req, res) => {
    if (!has(req, 'mapping_deputy')) throw new AppError('권한이 없습니다.', 403);
    await auth.reauthStrong(req.user, req.body.password, req.body.code);
    const rows = (await vault.pending()).filter((r) => r.reason === String(req.body.reason || '') && Number(r.requested_by) !== req.user.id);
    for (const r of rows) await vault.decide(ctx(req), r.id, true, '묶음 승인');
    done(res, `${rows.length}건 승인했습니다.`, '/requests');
  }));
  app.post('/requests/:id/review', wrap(async (req, res) => {
    await auth.reauth(req.user, req.body.password); const r = await vault.viewRequest(ctx(req), Number(req.params.id), '승인 전 검토');
    res.send(pg(req, '검토', `<h1>${esc(r.code)} v${r.version} 요청 검토</h1><div class="card">${fieldsTable(r.fields)}<p>사유: ${esc(r.reason)}</p><form class="f" method="post" action="/requests/${r.id}/decide">${V.csrf(req)}<input name="note" placeholder="메모">${V.pw()}<button name="d" value="approve">승인</button><button class="o" name="d" value="reject">반려</button></form></div>`, true));
  }));
  app.post('/requests/:id/decide', wrap(async (req, res) => { await auth.reauth(req.user, req.body.password); await vault.decide(ctx(req), Number(req.params.id), req.body.d === 'approve', String(req.body.note || '').slice(0, 300)); done(res, '처리했습니다.', '/requests'); }));
  // ── 비상 열람(대행자 2인)
  app.get('/emergency', wrap(async (req, res) => {
    if (!has(req, 'mapping_deputy')) throw new AppError('권한이 없습니다.', 403);
    const gs = await vault.grants(); const g = await vault.activeGrant(req.user.id); const codes = Object.keys(await vault.mappedCodes());
    res.send(pg(req, '비상 열람', `<h1>비상 열람</h1><div class="sub">시스템관리자 부재 시: 대행자 A 요청 → 대행자 B 승인 → A가 30분간 열람.</div>
    <form class="f card" method="post" action="/emergency">${V.csrf(req)}<label>사유</label><input name="reason" required>${V.pw()}<button>비상 열람 요청</button></form>
    <div class="card">${V.table(['#', '요청자', '사유', '상태', '만료', ''], gs.map((x) => [String(x.id), String(x.requested_by), esc(x.reason), esc(x.status), x.expires_at ? kst(x.expires_at, true) : '-', x.status === 'pending' && Number(x.requested_by) !== req.user.id ? `<form method="post" action="/emergency/${x.id}/decide" class="flex">${V.csrf(req)}<input type="password" name="password" placeholder="비밀번호" required><button name="d" value="approve" class="s">승인</button><button name="d" value="reject" class="o s">반려</button></form>` : '']))}</div>
    ${g ? `<form class="f card" method="post" action="/emergency/view">${V.csrf(req)}<h2>비상 열람(유효 ${kst(g.expires_at, true)}까지)</h2><select name="code">${codes.map((c) => `<option>${esc(c)}</option>`).join('')}</select>${reasonSel()}${V.pw()}<button>열람</button></form>` : ''}`));
  }));
  app.post('/emergency', wrap(async (req, res) => { await auth.reauth(req.user, req.body.password); if (!String(req.body.reason || '').trim()) throw new AppError('사유를 입력하세요.'); await vault.requestEmergency(ctx(req), String(req.body.reason).slice(0, 300)); done(res, '요청했습니다. 다른 대행자의 승인이 필요합니다.', '/emergency'); }));
  app.post('/emergency/:id/decide', wrap(async (req, res) => { await auth.reauth(req.user, req.body.password); await vault.decideEmergency(ctx(req), Number(req.params.id), req.body.d === 'approve'); done(res, '처리했습니다.', '/emergency'); }));
  app.post('/emergency/view', wrap(async (req, res) => { await auth.reauth(req.user, req.body.password); const reason = reasonOf(req.body); const r = await vault.view(ctx(req), String(req.body.code), reason, { emergency: true }); res.send(pg(req, '비상 열람', `<h1>${esc(req.body.code)} (비상)</h1><div class="card">${r ? fieldsTable(r.fields) : '없음'}</div>`, true)); }));
  // ── 허가 정보(법정 장부 머리)
  app.get('/permit', wrap(async (req, res) => { if (!has(req, 'sysadmin')) throw new AppError('권한이 없습니다.', 403); res.send(pg(req, '허가 정보', `<form class="f card" method="post" action="/permit">${V.csrf(req)}<h1>허가 정보 ${await vault.hasPermit() ? '(등록됨 — 새 버전으로 저장)' : '(미등록)'}</h1>${vault.PERMIT_FIELDS.map(([k, l]) => `<label>${esc(l)}</label><input name="${k}" autocomplete="off">`).join('')}<label>사유</label><input name="reason" required>${V.pw()}<button>저장(암호화)</button></form>`, true)); }));
  app.post('/permit', wrap(async (req, res) => { await auth.reauth(req.user, req.body.password); await vault.setPermit(ctx(req), req.body, String(req.body.reason || '').slice(0, 200) || '-'); done(res, '저장했습니다.', '/'); }));
  // ── 점검 대장(코드 + 품명). 2인 해제 후 요청자만 60분간 출력. 출력마다 번호·워터마크·기록.
  app.get('/ledger', wrap(async (req, res) => {
    const us = await vault.ledgerUnlocks(); const act = await vault.activeLedgerUnlock(req.user.id);
    res.send(pg(req, '점검 대장', `<h1>점검 대장 출력</h1><div class="sub">관청 점검 시 즉시 제시용. 시스템관리자·지정 대행자·허가 명의자 중 2명이 해제해야 출력됩니다. 법정 장부 쪽·행 번호로 대조합니다.</div>
    <form class="f card" method="post" action="/ledger/unlock">${V.csrf(req)}<label>사유</label><select name="reason_code">${Object.entries(REASONS).map(([k, v]) => `<option value="${k}">${v}</option>`).join('')}</select><label>점검자 소속(선택)</label><input name="inspector"><label>범위(예: 2026-10)</label><input name="scope">${V.pw()}<button>해제 요청</button></form>
    <div class="card">${V.table(['#', '요청자', '사유', '상태', '만료', '출력 수', ''], us.map((x) => [String(x.id), String(x.requested_by), esc(x.reason), esc(x.status), x.expires_at ? kst(x.expires_at, true) : '-', String(x.outputs), x.status === 'pending' && Number(x.requested_by) !== req.user.id ? `<form method="post" action="/ledger/unlock/${x.id}/decide" class="flex">${V.csrf(req)}<input type="password" name="password" placeholder="비밀번호" required><button name="d" value="approve" class="s">승인</button><button name="d" value="reject" class="o s">반려</button></form>` : '']))}</div>
    ${act ? `<div class="card"><h2>출력 가능(${kst(act.expires_at, true)}까지)</h2><form method="post" action="/ledger/output" class="flex">${V.csrf(req)}<button name="fmt" value="html">화면·인쇄</button><button name="fmt" value="csv" class="o">CSV</button></form></div>` : ''}`));
  }));
  app.post('/ledger/unlock', wrap(async (req, res) => { await auth.reauth(req.user, req.body.password); await vault.requestLedgerUnlock(ctx(req), reasonOf(req.body), String(req.body.inspector || '').slice(0, 60), String(req.body.scope || '').slice(0, 40)); done(res, '요청했습니다. 다른 1명의 승인이 필요합니다.', '/ledger'); }));
  app.post('/ledger/unlock/:id/decide', wrap(async (req, res) => { await auth.reauth(req.user, req.body.password); await vault.decideLedgerUnlock(ctx(req), Number(req.params.id), req.body.d === 'approve'); done(res, '처리했습니다.', '/ledger'); }));
  app.post('/ledger/output', wrap(async (req, res) => {
    const outputNo = `LO-${kstDate().replace(/-/g, '')}-${Date.now().toString(36).toUpperCase()}`;
    const rec = await db.all("SELECT r.no, r.received_at, r.doc_no, i.code, (SELECT COALESCE(SUM(g.delta_ug),0) FROM ledger g JOIN containers c ON c.id=g.container_id WHERE c.lot_id=r.lot_id AND g.type='RECEIPT') AS net FROM receipts r JOIN item_codes i ON i.id=r.code_id WHERE r.status='completed' ORDER BY r.id");
    const use = await db.all("SELECT u.used_on, u.amount_ug, u.research_summary, u.experiment_no, u.legal_row_no, i.code FROM usage_logs u JOIN checkouts k ON k.id=u.checkout_id JOIN item_codes i ON i.id=k.code_id WHERE u.status='confirmed' ORDER BY u.used_on, u.id");
    const dsp = await db.all("SELECT d.no, d.result_on, d.result_doc_no, d.handover_ug, d.legal_row_no, i.code FROM disposals d JOIN item_codes i ON i.id=d.code_id WHERE d.status='completed' ORDER BY d.id");
    const codes = [...new Set([...rec, ...use, ...dsp].map((r) => r.code))];
    const L = await vault.ledgerData(ctx(req), codes, outputNo); const nm = (c) => L.names[c] || '【매핑 없음】'; const p = L.permit || {};
    const g = (ug) => fmt(ug, 4).replace(/\s*g$/, '');
    const useRows = use.map((u, i) => [i + 1, u.used_on, u.code, nm(u.code), g(u.amount_ug), u.research_summary, u.experiment_no, u.legal_row_no]);
    const recRows = rec.map((r, i) => [i + 1, kstDate(r.received_at), r.code, nm(r.code), g(r.net), r.doc_no, r.no]);
    const dspRows = dsp.map((d, i) => [i + 1, d.result_on, d.code, nm(d.code), d.handover_ug === null ? '' : g(d.handover_ug), d.result_doc_no, d.legal_row_no]);
    const hdr = vault.PERMIT_FIELDS.map(([k, l]) => `${l}: ${p[k] || '【미등록】'}`);
    if (req.body.fmt === 'csv') {
      const q = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`; const line = (a) => a.map(q).join(',');
      const out = [line([`출력번호 ${outputNo}`, `출력자 ${req.user.username}`, kst(nowIso(), true), '사내 보조 기록 — 법정 장부를 대신하지 않음']), ...hdr.map((h) => line([h])), '', line(['[사용]']), line(['행', '사용일', '코드', '품명', '수량(g)', '연구내용', '실험번호', '법정 장부 쪽·행']), ...useRows.map(line), '', line(['[입고]']), line(['행', '인수일', '코드', '품명', '순량(g)', '인수 문서', '입고 번호']), ...recRows.map(line), '', line(['[폐기]']), line(['행', '결과 공문일', '코드', '품명', '인계량(g)', '결과 공문', '법정 장부 쪽·행']), ...dspRows.map(line)].join('\r\n');
      res.set({ 'Content-Type': 'text/csv; charset=utf-8', 'Content-Disposition': `attachment; filename="${outputNo}.csv"` }); return res.send('\uFEFF' + out);
    }
    const T = (h, rows) => V.table(h, rows.map((r) => r.map((c) => esc(c))));
    res.send(pg(req, '점검 대장', `<h1>점검 대장 · 출력번호 ${esc(outputNo)}</h1><div class="card small">${hdr.map(esc).join(' · ')}<br>출력자 ${esc(req.user.username)} · ${kst(nowIso(), true)} KST · ${esc(V.NOTICE)}</div>
    <div class="card"><h2>사용</h2>${T(['행', '사용일', '코드', '품명', '수량(g)', '연구내용', '실험번호', '법정 장부 쪽·행'], useRows)}</div><div class="card"><h2>입고</h2>${T(['행', '인수일', '코드', '품명', '순량(g)', '인수 문서', '입고 번호'], recRows)}</div><div class="card"><h2>폐기</h2>${T(['행', '결과 공문일', '코드', '품명', '인계량(g)', '결과 공문', '법정 장부 쪽·행'], dspRows)}</div><button onclick="window.print()">인쇄</button>`, true));
  }));
  app.get('/log', wrap(async (req, res) => { const rows = await vault.accessLog(200); const v = await vault.verifyLog(); res.send(pg(req, '열람 기록', `<h1>열람 기록(해시 체인)</h1><div class="card">${v.ok ? V.badge(`정상 ${v.count}건`, 'ok') : V.badge(`이상 #${v.brokenAt}`, 'err')}${V.table(['#', '시각', '사용자', '종류', '코드', '사유', 'IP'], rows.map((r) => [String(r.id), kst(r.at, true), esc(r.username), esc(r.kind), `<span class="mono">${esc(r.code || '')}</span>`, esc(r.reason), esc(r.ip || '')]))}</div>`)); }));
  http.errors(app, (req, s, m) => V.page(req, { title: '오류', body: `<div class="card"><h1>${s}</h1><p>${esc(m)}</p><a href="/">처음으로</a></div>`, nav: req.user ? nav(req) : [] }));
  return app;
}
module.exports = { createVaultApp, REASONS };
