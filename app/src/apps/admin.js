'use strict';
// 관리 앱: MFA(TOTP) 필수 + 허용 IP 대역. 승인·2인 종결·사고 보고·폐기 P2~P5·기준 정보·감사.
// 매핑(품명)은 이 앱에서 볼 수 없습니다. Vault는 별도 프로세스이며 여기서는 서명된 메타 조회(건수·상태)만 합니다.
const fs = require('fs');
const http = require('../http'); const { wrap } = http; const V = require('../views'); const svc = require('../services');
const { can, ROLES, rolesOf } = require('../perm'); const { kst, kstDate, AppError } = require('../util'); const { fmt } = require('../units');
const { verifyChain, anchor, checkAnchors, writeAudit } = require('../audit'); const { CATEGORIES, FORMS } = require('../codes');
const C = require('./common'); const link = require('./vaultlink'); const J = require('../judge');
function createAdminApp(core) {
  const app = http.base(core, 'admin', { allowCidrs: core.cfg.adminAllowCidrs }); const db = core.db; const esc = V.esc;
  app.use(http.sessionMw(app, db, db, { publicPaths: ['/login', '/setup'] }));
  C.loginRoutes(app, { title: 'AEGIS v2 관리 앱' });
  // 첫 실행 설정(오프라인 PC): 사용자가 0명이고 시작 스크립트가 만든 설정 코드가 있을 때만
  const setupOpen = async () => !!core.cfg.setupCode && Number((await db.get('SELECT COUNT(*) AS n FROM users')).n) === 0;
  app.get('/setup', wrap(async (req, res, next) => {
    if (!(await setupOpen())) return next();
    res.send(V.loginPage(req, { title: '첫 실행 — 시스템관리자 만들기', sub: '시작 창(검은 창)에 표시된 설정 코드를 넣고 관리자 계정을 만드세요. 다음 화면에서 인증 앱(TOTP)을 등록합니다.', action: '/setup', extra: '<label>설정 코드</label><input name="setup_code" autocomplete="off" required><label>아이디(영문 소문자)</label><input name="username" value="andy" required><label>표시 이름</label><input name="display_name" value="시스템관리자" required><label>비밀번호(12자 이상, 3종)</label><input type="password" name="password" autocomplete="new-password" required><label>비밀번호 확인</label><input type="password" name="password2" autocomplete="new-password" required>' }));
  }));
  app.post('/setup', wrap(async (req, res, next) => {
    if (!(await setupOpen())) return next();
    const crypto = require('crypto'); const a = Buffer.from(String(req.body.setup_code || '').trim()); const b = Buffer.from(core.cfg.setupCode);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) { res.flash('err', '설정 코드가 맞지 않습니다.'); return res.redirect(303, '/setup'); }
    const auth = require('../auth'); const username = String(req.body.username || '').trim().toLowerCase();
    try { if (!/^[a-z0-9._-]{3,30}$/.test(username)) throw new AppError('아이디는 영문 소문자·숫자 3~30자'); if (req.body.password !== req.body.password2) throw new AppError('비밀번호 확인이 다릅니다.'); auth.validatePassword(req.body.password); }
    catch (e) { res.flash('err', e.message); return res.redirect(303, '/setup'); }
    const { nowIso } = require('../util');
    await db.tx(async (t) => { const n = Number((await t.get('SELECT COUNT(*) AS n FROM users')).n); if (n) throw new AppError('이미 설정되었습니다.', 409);
      const r = await t.get("INSERT INTO users (username, display_name, password_hash, roles, created_at) VALUES ($1,$2,$3,'sysadmin',$4) RETURNING id", [username, String(req.body.display_name || '시스템관리자').slice(0, 40), await auth.hashPassword(req.body.password, req.cfg.bcryptRounds), nowIso()]);
      await writeAudit(t, { app: 'admin', actorName: 'setup', ip: C.ipOf(req) }, 'SETUP_FIRST_ADMIN', 'user', r.id, null, { username }); });
    res.flash('ok', '관리자 계정을 만들었습니다. 로그인하면 인증 앱 등록 화면이 나옵니다.'); res.redirect(303, '/login');
  }));
  app.use(C.requireFull);
  const P = (...perms) => (req, res, next) => (perms.some((p) => can(req.user, p, 'admin')) ? next() : next(new AppError('권한이 없습니다.', 403)));
  const nav = (req) => { const u = req.user; const c = (p) => can(u, p, 'admin'); return [['/', '현황'], c('code.view') && ['/codes', '코드'], c('checkout.approve') && ['/checkouts', '반출 승인'], c('inventory.admin') && ['/inventory', '재고'], (c('inventory.admin') || c('master.manage')) && ['/receipts', '가져온 입고'], c('anomaly.view') && ['/anomalies', '이상 징후'], c('incident.view') && ['/incidents', '사고 보고'], (c('disposal.manage') || c('inventory.admin')) && ['/disposals', '폐기'], c('master.manage') && ['/master', '기준 정보'], c('settings.manage') && ['/settings', '설정'], c('user.manage') && ['/users', '사용자'], c('device.manage') && ['/devices', '전광판 단말'], c('audit.view') && ['/audit', '감사 로그'], rolesOf(u).some((r) => ['sysadmin', 'mapping_deputy', 'permit_holder'].includes(r)) && ['/vault', '매핑 금고']].filter(Boolean); };
  const pg = (req, title, body) => V.page(req, { title, body, nav: nav(req) });
  const ctx = C.ctxOf; const done = (res, msg, to) => { res.flash('ok', msg); res.redirect(303, to); };
  const totpIn = '<label>인증 앱 6자리</label><input name="code" inputmode="numeric" autocomplete="one-time-code" required>';

  app.get('/', wrap(async (req, res) => {
    const al = await svc.alerts(db); const b = await svc.boardData(db);
    res.send(pg(req, '현황', `<h1>현황</h1><div class="grid g4 mb">${[['보관 용기', b.k.containers], ['반출 중', b.k.outstanding], ['열린 이상 징후', b.k.openAnomalies], ['잠긴 코드', b.k.lockedCodes], ['입회 대기', b.k.pendingWitness], ['사고 보고 진행', b.k.incidentsOpen]].map(([l, n]) => `<div class="card"><div class="muted small">${l}</div><div style="font-size:28px;font-weight:700">${n}</div></div>`).join('')}</div>
    <div class="card"><h2>알림</h2>${al.map((a) => `<div class="lvl-${a.level}">● [${esc(a.kind)}] <a href="${esc(a.link)}">${esc(a.text)}</a></div>`).join('') || '<p class="muted">없음</p>'}</div>`));
  }));
  // ── 코드(2인 승인 발급)
  app.get('/codes', P('code.view'), wrap(async (req, res) => {
    const codes = await db.all('SELECT * FROM item_codes ORDER BY code'); const ap = await db.all("SELECT a.*, u.display_name FROM approvals a JOIN users u ON u.id=a.requested_by WHERE a.status='pending' ORDER BY a.id");
    res.send(pg(req, '코드', `<h1>코드 레지스트리</h1><div class="sub">형식 SMP-###-검증숫자. 품명은 이 앱에 없습니다(매핑 금고에서만).</div>
    <div class="card">${V.table(['코드', '분류', '형태', '반납 기한', '상태'], codes.map((c) => [`<span class="mono">${esc(c.code)}</span>`, esc(c.category), esc(FORMS[c.form] || c.form), c.return_days ? `${c.return_days}일` : '기본', c.locked ? V.badge('잠김', 'err') : esc(c.status)]))}</div>
    ${can(req.user, 'code.request', 'admin') ? `<form class="f card" method="post" action="/codes/request">${V.csrf(req)}<h2>코드 발급 요청</h2><label>분류</label><select name="category">${CATEGORIES.map((c) => `<option>${c}</option>`).join('')}</select><label>형태</label><select name="form">${Object.entries(FORMS).map(([k, v]) => `<option value="${k}">${v}</option>`).join('')}</select><label>개수</label><input name="count" value="1"><label>반납 기한(일, 비우면 기본)</label><input name="return_days"><label>요청 사유</label><input name="reason" required><button>요청(다른 관리책임자 승인 필요)</button></form>` : ''}
    <div class="card"><h2>승인 대기</h2>${V.table(['#', '요청자', '내용', '사유', ''], ap.map((a) => [String(a.id), esc(a.display_name), esc(a.payload), esc(a.reason), can(req.user, 'code.approve', 'admin') && Number(a.requested_by) !== req.user.id ? `<form method="post" action="/approvals/${a.id}" class="flex">${V.csrf(req)}<input type="password" name="password" placeholder="비밀번호 재인증" required><input name="note" placeholder="메모"><button name="d" value="approve">승인</button><button class="o" name="d" value="reject">반려</button></form>` : '<span class="muted">다른 사람 승인 대기</span>']))}</div>`));
  }));
  app.post('/codes/request', P('code.request'), wrap(async (req, res) => { await svc.requestCode(ctx(req), req.body); done(res, '요청했습니다. 다른 관리책임자가 승인해야 발급됩니다.', '/codes'); }));
  app.post('/approvals/:id', P('code.approve'), wrap(async (req, res) => { const c = await svc.decideApproval(ctx(req), Number(req.params.id), req.body.d === 'approve', req.body.note, req.body.password); done(res, c.length ? `발급: ${c.join(', ')}` : '처리했습니다.', '/codes'); }));
  // ── 반출 승인
  app.get('/checkouts', P('checkout.approve'), wrap(async (req, res) => {
    const rows = await db.all('SELECT k.*, i.code, i.locked, u.display_name, c.cid FROM checkouts k JOIN item_codes i ON i.id=k.code_id JOIN users u ON u.id=k.requester_id JOIN containers c ON c.id=k.container_id ORDER BY k.id DESC LIMIT 100');
    res.send(pg(req, '반출 승인', `<h1>반출 승인</h1><div class="card">${V.table(['번호', '코드', '용기', '요청자', '요청량', '목적', '상태', '판정', ''], rows.map((k) => [esc(k.no), `<span class="mono">${esc(k.code)}</span>${k.locked ? V.badge('잠김', 'err') : ''}`, esc(k.cid), esc(k.display_name), k.mode === 'whole' ? '용기째' : fmt(k.requested_ug), esc(k.purpose), esc(svc.CO_STATUS[k.status]), k.judgment ? `<span class="j-${esc(k.judgment)}">${esc(J.LABEL[k.judgment] || k.judgment)}</span>` : '',
      k.status === 'requested' && Number(k.requester_id) !== req.user.id ? `<form method="post" action="/checkouts/${k.id}/decide" class="flex">${V.csrf(req)}<input type="password" name="password" placeholder="비밀번호" required><input name="note" placeholder="메모(반려 시 필수)"><button name="d" value="approve">승인</button><button class="o" name="d" value="reject">반려</button></form>` : '']))}</div>`));
  }));
  app.post('/checkouts/:id/decide', P('checkout.approve'), wrap(async (req, res) => { await svc.decideCheckout(ctx(req), Number(req.params.id), req.body.d === 'approve', req.body.note, req.body.password); done(res, '처리했습니다.', '/checkouts'); }));
  app.get('/receipts', P('inventory.admin', 'master.manage'), wrap(async (req, res) => {
    const rows = await db.all("SELECT r.*, i.code, i.category, (SELECT GROUP_CONCAT(c.status) FROM containers c WHERE c.lot_id=r.lot_id) AS cst FROM receipts r JOIN item_codes i ON i.id=r.code_id WHERE r.status IN ('imported','imported_check') ORDER BY r.id");
    const m = can(req.user, 'master.manage', 'admin');
    res.send(pg(req, '가져온 입고', `<h1>가져온 입고(CSV)</h1><div class="sub">품명·사건번호는 매핑 금고에만 있습니다. 도착·인수 일시는 비어 있으면 여기서 1회 입력합니다. 손글씨 무게는 입회 계량 전 참고값입니다.</div><div class="card">${V.table(['입고', '코드', '분류', '근거', '상태', '용기', '도착', '인수', ''], rows.map((r) => [esc(r.no), `<span class="mono">${esc(r.code)}</span>`, esc(r.category), esc(r.source_ref), r.status === 'imported_check' ? V.badge('확인 필요', 'warn') : '가져옴', esc(r.cst || ''), r.arrival_at ? kst(r.arrival_at) : V.badge('미입력', 'warn'), r.received_at ? kst(r.received_at) : '-',
      m && !r.arrival_at ? `<form method="post" action="/receipts/${r.id}/times" class="flex">${V.csrf(req)}<input type="datetime-local" name="arrival_at" required><input type="datetime-local" name="received_at" required><input type="password" name="password" placeholder="비밀번호" required><button class="s">저장</button></form>` : '']))}</div>`));
  }));
  app.post('/receipts/:id/times', P('master.manage'), wrap(async (req, res) => { await require('../auth').reauth(req.user, req.body.password); await svc.setReceiptTimes(ctx(req), Number(req.params.id), req.body); done(res, '저장했습니다.', '/receipts'); }));
  app.get('/inventory', P('inventory.admin'), wrap(async (req, res) => {
    const rows = await svc.inventory(db); const led = await db.all('SELECT g.*, c.cid FROM ledger g JOIN containers c ON c.id=g.container_id ORDER BY g.id DESC LIMIT 50');
    res.send(pg(req, '재고', `<h1>보관 재고(용기 단위)</h1><div class="card">${V.table(['코드', '용기', '위치', '상태', '보관 순량', '용기 무게'], rows.map((c) => [`<span class="mono">${esc(c.code)}</span>`, esc(c.cid), esc(c.location || '-'), esc(c.status), fmt(c.balance_ug), c.tare_ug === null ? '미확정' : fmt(c.tare_ug)]))}</div>
    <div class="card"><h2>원장(최근 50) — 추가 전용</h2>${V.table(['#', '시각', '용기', '종류', '증감', '근거'], led.map((g) => [String(g.id), kst(g.at, true), esc(g.cid), esc(g.type), V.fmt(g.delta_ug), esc(g.ref_type + ' ' + (g.note || ''))]))}</div>`));
  }));
  // ── 이상 징후(2인 종결)
  app.get('/anomalies', P('anomaly.view'), wrap(async (req, res) => {
    const rows = await db.all('SELECT a.*, i.code FROM anomalies a LEFT JOIN item_codes i ON i.id=a.code_id ORDER BY a.id DESC LIMIT 100');
    res.send(pg(req, '이상 징후', `<h1>이상 징후</h1><div class="sub">이상 등급은 관리책임자 2명(1차 확인 → 다른 사람 최종)이 종결해야 잠금이 풀립니다. 사고 보고 기한은 종결과 별개로 흐릅니다.</div>${can(req.user, 'anomaly.manage', 'admin') ? '<a class="btn" href="/anomalies/new">수동 신고</a>' : ''}<div class="card">${V.table(['번호', '종류', '등급', '코드', '차이', '상태', ''], rows.map((a) => [esc(a.no), esc(svc.AN_TYPES[a.type] || a.type), a.severity === 'anomaly' ? V.badge('이상', 'err') : V.badge('경고', 'warn'), `<span class="mono">${esc(a.code || '-')}</span>`, a.diff_ug === null ? '' : V.fmt(a.diff_ug), esc(a.status), `<a href="/anomalies/${a.id}">열기</a>`]))}</div>`));
  }));
  app.get('/anomalies/new', P('anomaly.manage'), wrap(async (req, res) => { const codes = await db.all('SELECT id, code FROM item_codes ORDER BY code'); res.send(pg(req, '수동 신고', `<form class="f card" method="post" action="/anomalies">${V.csrf(req)}<h1>이상 징후 수동 신고</h1><label>코드</label><select name="code_id"><option value="">(없음)</option>${codes.map((c) => `<option value="${c.id}">${esc(c.code)}</option>`).join('')}</select><label>등급</label><select name="severity"><option value="warning">경고</option><option value="anomaly">이상(코드 잠금 + 사고 보고 시작)</option></select><label>내용(품목명·개인 정보 쓰지 않음)</label><textarea name="description" required></textarea><button>신고</button></form>`)); }));
  app.post('/anomalies', P('anomaly.manage'), wrap(async (req, res) => { const id = await svc.reportAnomaly(ctx(req), req.body); done(res, '신고했습니다.', `/anomalies/${id}`); }));
  app.get('/anomalies/:id', P('anomaly.view'), wrap(async (req, res) => {
    const a = await db.get('SELECT a.*, i.code FROM anomalies a LEFT JOIN item_codes i ON i.id=a.code_id WHERE a.id=$1', [Number(req.params.id)]); if (!a) throw new AppError('없음', 404);
    const acts = await db.all('SELECT x.*, u.display_name FROM anomaly_actions x JOIN users u ON u.id=x.user_id WHERE anomaly_id=$1 ORDER BY x.id', [a.id]);
    const canAct = can(req.user, 'anomaly.manage', 'admin') && a.status !== 'resolved' && Number(a.resolve_first_by) !== req.user.id;
    res.send(pg(req, a.no, `<h1>이상 징후 ${esc(a.no)}</h1><div class="card">${esc(svc.AN_TYPES[a.type] || a.type)} · ${a.severity === 'anomaly' ? V.badge('이상', 'err') : V.badge('경고', 'warn')} · 코드 <span class="mono">${esc(a.code || '-')}</span> · 상태 ${esc(a.status)}${a.locks_code ? ' · 코드 잠금' : ''}<br>${esc(a.description)}${a.adjust_container_id ? `<br>종결 시 원장 조정: 용기 #${a.adjust_container_id} → ${fmt(a.adjust_to_ug)}` : ''}${a.incident_id ? `<br>사고 보고 트랙: <a href="/incidents/${a.incident_id}">열기</a>` : ''}</div>
    <div class="card"><h2>조치 기록</h2>${V.table(['시각', '단계', '담당', '내용'], acts.map((x) => [kst(x.at, true), x.action === 'first' ? '1차 확인' : '최종 종결', esc(x.display_name), esc(x.note)]))}</div>
    ${canAct ? `<form class="f card" method="post" action="/anomalies/${a.id}/resolve">${V.csrf(req)}<h2>${a.resolve_first_by ? '최종 종결(2인째)' : a.severity === 'anomaly' || a.locks_code ? '1차 확인(1인째)' : '종결'}</h2><label>조사·조치 내용</label><textarea name="note" required></textarea>${V.pw()}<button>제출</button></form>` : ''}`));
  }));
  app.post('/anomalies/:id/resolve', P('anomaly.manage'), wrap(async (req, res) => { const r = await svc.resolveAnomaly(ctx(req), Number(req.params.id), req.body); done(res, r.stage === 'first' ? '1차 확인 — 다른 관리책임자의 최종 종결이 필요합니다.' : '종결했습니다.', `/anomalies/${req.params.id}`); }));
  // ── 사고 보고 트랙
  app.get('/incidents', P('incident.view'), wrap(async (req, res) => {
    const rows = await db.all('SELECT n.*, i.code FROM incidents n LEFT JOIN item_codes i ON i.id=n.code_id ORDER BY n.id DESC LIMIT 100');
    res.send(pg(req, '사고 보고', `<h1>사고 보고 트랙</h1><div class="sub">인지 시점부터 ${'24'}시간 안 1차 판정, 보고 기한은 설정값(기본 5일·초일 포함) — 이상 징후 종결과 별개.</div>${can(req.user, 'incident.manage', 'admin') ? `<form class="flex card" method="post" action="/incidents">${V.csrf(req)}<label>발견 일시(KST)</label><input type="datetime-local" name="discovered_at"><button>수동 개시</button></form>` : ''}<div class="card">${V.table(['번호', '코드', '인지', '보고 기한', '경과', '상태', ''], rows.map((n) => { const c = svc.incidentClock(n); return [esc(n.no), `<span class="mono">${esc(n.code || '-')}</span>`, kst(n.aware_at), kst(n.report_due), `<span class="lvl-${c.level}">D+${c.dayIdx}</span>`, esc(svc.INC_STATUS[n.status]), `<a href="/incidents/${n.id}">열기</a>`]; }))}</div>`));
  }));
  app.post('/incidents', P('incident.manage'), wrap(async (req, res) => { const id = await svc.openIncidentManual(ctx(req), req.body); done(res, '개시했습니다.', `/incidents/${id}`); }));
  app.get('/incidents/:id', P('incident.view'), wrap(async (req, res) => {
    const n = await db.get('SELECT * FROM incidents WHERE id=$1', [Number(req.params.id)]); if (!n) throw new AppError('없음', 404); const c = svc.incidentClock(n); const m = can(req.user, 'incident.manage', 'admin');
    res.send(pg(req, n.no, `<h1>사고 ${esc(n.no)}</h1><div class="card">인지 ${kst(n.aware_at, true)} · 1차 판정 기한 ${kst(n.determine_due)} · 사내 목표 ${kst(n.internal_target)} · <b>보고 기한 ${kst(n.report_due)}</b><br><span class="lvl-${c.level}">D+${c.dayIdx} · 남은 시간 ${c.hoursLeft}시간</span>${c.determineOverdue ? ' ' + V.badge('1차 판정 기한 경과', 'err') : ''} · 상태 ${esc(svc.INC_STATUS[n.status])}<br>판정 ${esc(n.determination || '-')} ${esc(n.determination_note || '')}<br>증명 ${esc(n.evidence_kind || '-')} ${esc(n.evidence_no || '')} · 제출 ${esc(n.report_authority || '-')} ${n.reported_at ? kst(n.reported_at) : ''} ${esc(n.report_receipt_no || '')}</div>
    ${m && n.status === 'awaiting_determination' ? `<form class="f card" method="post" action="/incidents/${n.id}/determine">${V.csrf(req)}<h2>1차 판정</h2><select name="determination"><option value="weigh_error">계량 오류(보고 대상 아님 — 근거 필수)</option><option value="reportable">사고(보고 대상)</option><option value="unknown">원인 불명(보고 대상으로 처리)</option></select><label>근거</label><textarea name="note" required></textarea>${V.pw()}<button>저장</button></form>` : ''}
    ${m && n.status === 'report_pending' ? `<form class="f card" method="post" action="/incidents/${n.id}/evidence">${V.csrf(req)}<h2>증명서류(도난·분실 시)</h2><input name="evidence_kind" placeholder="종류"><input name="evidence_no" placeholder="접수·발급 번호">${V.pw()}<button>저장</button></form>
    <form class="f card" method="post" action="/incidents/${n.id}/report">${V.csrf(req)}<h2>보고서 제출 기록</h2><label>제출 기관(허가관청)</label><input name="report_authority" required><label>제출 일시(KST)</label><input type="datetime-local" name="reported_at" required><label>접수번호</label><input name="report_receipt_no" required><label>문서 해시(선택)</label><input name="doc_sha"><label>법정 장부 쪽·행</label><input name="legal_row_no">${V.pw()}<button>저장</button></form>` : ''}`));
  }));
  app.post('/incidents/:id/:step(determine|evidence|report)', P('incident.manage'), wrap(async (req, res) => { await svc.incidentStep(ctx(req), Number(req.params.id), req.params.step, req.body); done(res, '저장했습니다.', `/incidents/${req.params.id}`); }));
  // ── 폐기 P2~P5
  app.get('/disposals', P('disposal.manage', 'inventory.admin'), wrap(async (req, res) => {
    const rows = await db.all('SELECT d.*, c.cid FROM disposals d JOIN containers c ON c.id=d.container_id ORDER BY d.id DESC LIMIT 100');
    res.send(pg(req, '폐기', `<h1>폐기(관청 신청 → 공무원 참관 → 결과 공문)</h1><div class="sub">사내 직접·위탁·소각·중화 폐기 경로는 없습니다. 결과 공문 기록 시에만 원장에서 차감합니다.</div><div class="card">${V.table(['번호', '용기', '사유', '상태', ''], rows.map((d) => [esc(d.no), esc(d.cid), esc(svc.DISPOSAL_REASONS[d.reason_code]), esc(d.status), `<a href="/disposals/${d.id}">열기</a>`]))}</div>`));
  }));
  app.get('/disposals/:id', P('disposal.manage', 'inventory.admin'), wrap(async (req, res) => {
    const d = await db.get('SELECT d.*, c.cid FROM disposals d JOIN containers c ON c.id=d.container_id WHERE d.id=$1', [Number(req.params.id)]); if (!d) throw new AppError('없음', 404); const m = can(req.user, 'disposal.manage', 'admin');
    const f = { pending_application: ['apply', 'P2 관청 신청 기록', '<label>신청인(허가 명의자)</label><input name="applicant" required><label>제출 기관(허가관청)</label><input name="authority" required><label>제출일</label><input type="date" name="applied_on" required><label>접수번호</label><input name="application_no" required><label>문서 해시(선택)</label><input name="doc_sha">'],
      applied: ['observe', 'P3 공무원 참관 기록', `<label>참관 일자</label><input type="date" name="observed_on" required><label>참관 공무원 소속</label><input name="official_affiliation" required><label>사내 입회자 1 아이디</label><input name="witness1" required><label>사내 입회자 2 아이디</label><input name="witness2" required>${V.unitSel()}<label>인계 총중량</label><input name="handover_gross" inputmode="decimal" required>`],
      observed: ['result', 'P5 결과 공문 기록(원장 차감)', '<label>결과 공문 번호</label><input name="result_doc_no" required><label>시행일</label><input type="date" name="result_on" required><label>문서 해시(선택)</label><input name="doc_sha"><label>법정 장부 쪽·행</label><input name="legal_row_no">'] }[d.status];
    res.send(pg(req, d.no, `<h1>폐기 ${esc(d.no)}</h1><div class="card">용기 ${esc(d.cid)} · 사유 ${esc(svc.DISPOSAL_REASONS[d.reason_code])} · 상태 <b>${esc(d.status)}</b> · 격리 계량 ${d.amount_ug === null ? '-' : fmt(d.amount_ug)}<br>신청 ${esc(d.authority || '-')} ${esc(d.applied_on || '')} ${esc(d.application_no || '')} · 참관 ${esc(d.observed_on || '-')} ${esc(d.official_affiliation || '')} · 결과 ${esc(d.result_doc_no || '-')}${d.incident_id ? ` · <a href="/incidents/${d.incident_id}">사고 보고 트랙</a>` : ''}</div>
    ${m && f ? `<form class="f card" method="post" action="/disposals/${d.id}/${f[0]}">${V.csrf(req)}<h2>${f[1]}</h2>${f[2]}${V.pw()}<button>저장</button></form>` : ''}`));
  }));
  app.post('/disposals/:id/:step(apply|observe|result)', P('disposal.manage'), wrap(async (req, res) => { await svc.disposalStep(ctx(req), Number(req.params.id), req.params.step, req.body); done(res, '저장했습니다.', `/disposals/${req.params.id}`); }));
  // ── 기준 정보
  app.get('/master', P('master.manage'), wrap(async (req, res) => {
    const locs = await db.all('SELECT * FROM locations ORDER BY kind, name'); const sc = await db.all('SELECT * FROM scales ORDER BY scale_id');
    res.send(pg(req, '기준 정보', `<h1>기준 정보</h1><div class="grid g2"><div class="card"><h2>위치</h2>${V.table(['이름', '종류', '허가 소재지'], locs.map((l) => [esc(l.name), esc(l.kind), l.in_permit_site ? '안' : V.badge('밖', 'err')]))}<form class="f" method="post" action="/locations">${V.csrf(req)}<input name="name" placeholder="이름" required><select name="kind"><option value="vault">금고</option><option value="lab">실험실</option><option value="quarantine">격리 칸</option></select><select name="in_permit_site"><option value="1">허가 소재지 안</option><option value="0">밖</option></select><button>추가</button></form></div>
    <div class="card"><h2>저울</h2>${V.table(['ID', '분해능 d', '반복성 s', '교정 기한', '방식'], sc.map((s) => [esc(s.scale_id), fmt(s.resolution_ug, 6), s.repeatability_ug ? fmt(s.repeatability_ug, 6) : V.badge('미등록 — 판정 불가', 'err'), esc(s.calib_due || '-'), esc(s.adapter)]))}<form class="f" method="post" action="/scales">${V.csrf(req)}<input name="scale_id" placeholder="저울 ID" required><input name="model" placeholder="모델"><select name="res_unit"><option value="mg">mg</option><option value="g">g</option></select><input name="resolution" placeholder="분해능 d" required><input name="repeatability" placeholder="반복성 s(성적서)"><label>교정 기한</label><input type="date" name="calib_due"><input name="location" placeholder="설치 위치"><button>저장</button></form></div></div>`));
  }));
  app.post('/locations', P('master.manage'), wrap(async (req, res) => { await svc.createLocation(ctx(req), req.body); done(res, '추가했습니다.', '/master'); }));
  app.post('/scales', P('master.manage'), wrap(async (req, res) => { await svc.upsertScale(ctx(req), req.body); done(res, '저장했습니다.', '/master'); }));
  app.get('/settings', P('settings.manage'), wrap(async (req, res) => { const s = await svc.settings(db); res.send(pg(req, '설정', `<h1>설정</h1><div class="sub">판정 기준·기한·노출 범위는 〔예시〕 값입니다. 변경은 사유와 함께 감사 로그에 남습니다.</div><form class="f card" method="post" action="/settings">${V.csrf(req)}${Object.keys(svc.DEFAULT_SETTINGS).map((k) => `<label>${esc(svc.SETTING_LABEL[k])} <span class="muted mono small">${k}</span></label><input name="${k}" value="${esc(s[k])}">`).join('')}<label>변경 사유</label><input name="reason" required>${V.pw()}<button>저장</button></form>`)); }));
  app.post('/settings', P('settings.manage'), wrap(async (req, res) => { const { reauth } = require('../auth'); await reauth(req.user, req.body.password); const a = await svc.updateSettings(ctx(req), req.body); done(res, `변경 ${Object.keys(a).length}건`, '/settings'); }));
  // ── 사용자(시스템관리자)
  app.get('/users', P('user.manage'), wrap(async (req, res) => {
    const us = await db.all('SELECT id, username, display_name, roles, active, totp_enabled, last_login_at FROM users ORDER BY id');
    res.send(pg(req, '사용자', `<h1>사용자</h1><div class="card">${V.table(['아이디', '이름', '역할', 'MFA', '최근 로그인'], us.map((u) => [esc(u.username), esc(u.display_name), esc(rolesOf(u).map((r) => ROLES[r]).join(', ')), u.totp_enabled ? '등록' : '-', u.last_login_at ? kst(u.last_login_at) : '-']))}</div>
    <form class="f card" method="post" action="/users">${V.csrf(req)}<h2>추가·역할 변경</h2><div class="sub">매핑을 아는 역할(시스템관리자·지정 대행자·허가 명의자)은 원장 역할과 겸할 수 없고, 인원 상한이 있습니다.</div><input name="username" placeholder="아이디" required><input name="display_name" placeholder="표시 이름"><input type="password" name="temp_password" placeholder="임시 비밀번호(신규만, 12자+)">${Object.entries(ROLES).map(([k, v]) => `<label><input type="checkbox" name="roles" value="${k}"> ${v}</label>`).join('')}<h3>재인증</h3>${V.pw()}${totpIn}<button>저장</button></form>`));
  }));
  app.post('/users', P('user.manage'), wrap(async (req, res) => { await require('../auth').reauthStrong(req.user, req.body.password, req.body.code); await svc.saveUser(ctx(req), req.body); done(res, '저장했습니다.', '/users'); }));
  // ── 전광판 단말
  app.get('/devices', P('device.manage'), wrap(async (req, res) => {
    const ds = await db.all("SELECT * FROM devices WHERE kind='board' ORDER BY id");
    res.send(pg(req, '전광판 단말', `<h1>전광판 단말</h1><div class="sub">전광판은 사람 로그인이 없고 단말 토큰으로만 읽습니다(읽기 전용, 집계만).</div><div class="card">${V.table(['#', '이름', '허용 대역', '상태', '최근 접속', ''], ds.map((d) => [String(d.id), esc(d.name), esc(d.allow_cidrs || '(전체)'), d.active ? '사용' : '해지', d.last_seen ? kst(d.last_seen) : '-', d.active ? `<form method="post" action="/devices/${d.id}/revoke">${V.csrf(req)}<button class="o s">해지</button></form>` : '']))}</div>
    <form class="f card" method="post" action="/devices">${V.csrf(req)}<h2>단말 등록</h2><input name="name" placeholder="예: 3층 상황판" required><input name="allow_cidrs" placeholder="허용 대역(예: 192.168.10.0/24)">${V.pw()}${totpIn}<button>등록 — 연결 코드 1회 표시</button></form>`));
  }));
  app.post('/devices', P('device.manage'), wrap(async (req, res) => {
    await require('../auth').reauthStrong(req.user, req.body.password, req.body.code); const r = await svc.createBoardDevice(ctx(req), req.body);
    res.send(pg(req, '연결 코드', `<div class="card"><h1>전광판 연결 코드(이번 한 번만 표시)</h1><p>전광판 화면의 연결 입력란에 넣으세요. 이 화면을 닫으면 다시 볼 수 없습니다.</p><p class="mono" style="font-size:20px;word-break:break-all">${esc(r.token)}</p><a href="/devices">돌아가기</a></div>`));
  }));
  app.post('/devices/:id/revoke', P('device.manage'), wrap(async (req, res) => { await svc.revokeDevice(ctx(req), Number(req.params.id)); done(res, '해지했습니다.', '/devices'); }));
  // ── 감사 로그
  app.get('/audit', P('audit.view'), wrap(async (req, res) => {
    const rows = await db.all('SELECT seq, at, app, actor, action, entity, entity_id, hash FROM audit_log ORDER BY seq DESC LIMIT 200'); const v = await verifyChain(db);
    const an = await db.all('SELECT * FROM audit_anchors ORDER BY id DESC LIMIT 10');
    res.send(pg(req, '감사 로그', `<h1>감사 로그(추가 전용 · 해시 체인)</h1><div class="card">${v.ok ? V.badge(`체인 정상 · ${v.count}건`, 'ok') : V.badge(`체인 이상 — #${v.brokenAt} ${v.reason}`, 'err')} <form method="post" action="/audit/anchor" style="display:inline">${V.csrf(req)}<button class="o s">오늘 머리값 고정</button></form>${V.table(['일자', 'seq', '머리값'], an.map((a) => [esc(a.day), String(a.seq), `<span class="mono small">${esc(a.head.slice(0, 16))}…</span>`]))}</div>
    <div class="card">${V.table(['#', '시각', '앱', '사용자', '동작', '대상', '해시'], rows.map((r) => [String(r.seq), kst(r.at, true), esc(r.app), esc(r.actor), esc(r.action), esc(`${r.entity} ${r.entity_id || ''}`), `<span class="mono small">${esc(r.hash.slice(0, 12))}</span>`]))}</div>`));
  }));
  app.post('/audit/anchor', P('audit.view'), wrap(async (req, res) => { const r = await anchor(db, kstDate(), req.cfg.anchorFile || null); if (req.cfg.anchorFile && fs.existsSync(req.cfg.anchorFile)) { const list = fs.readFileSync(req.cfg.anchorFile, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l)); const c = await checkAnchors(db, list); if (!c.ok) { res.flash('err', `고정 파일과 불일치 ${c.mismatches.length}건`); return res.redirect(303, '/audit'); } } done(res, r.ok ? `고정: seq ${r.seq}` : '체인 이상으로 고정하지 않았습니다.', '/audit'); }));
  // ── 매핑 금고 안내 + 서명 메타 조회(내용 없음)
  app.get('/vault', wrap(async (req, res) => {
    if (!rolesOf(req.user).some((r) => ['sysadmin', 'mapping_deputy', 'permit_holder'].includes(r))) throw new AppError('권한이 없습니다.', 403);
    const m = await link.fetchMeta(req.cfg, req.user.username);
    await db.tx((t) => writeAudit(t, ctx(req), 'VAULT_META_QUERY', 'vault', null, null, { ok: !m.error }));
    res.send(pg(req, '매핑 금고', `<h1>매핑 금고(Vault)</h1><div class="sub">품명 매핑은 별도 프로세스·별도 DB·별도 로그인(비밀번호 + 인증 앱)에서만 다룹니다. 관리 앱은 아래 건수만 서명 요청으로 받아 옵니다.</div><div class="card">${m.error ? `<p class="lvl-warn">${esc(m.error)}</p>` : `매핑 기능 ${m.enabled ? '사용' : V.badge('꺼짐', 'warn')} · 매핑된 코드 ${m.mappedCount}개 · 승인 대기 ${m.pendingRequests}건 · 허가 정보 ${m.hasPermit ? '등록' : '미등록'} · 열람 기록 체인 ${m.logOk ? '정상' : V.badge('이상', 'err')}`}<p>Vault 주소는 사내망 담당자에게 받으세요(이 화면에 링크를 두지 않습니다).</p></div>`));
  }));
  app.get('/photos/:id', P('inventory.admin', 'anomaly.view'), wrap(async (req, res) => { const p = await db.get('SELECT * FROM photos WHERE id=$1', [Number(req.params.id)]); if (!p) throw new AppError('없음', 404); const buf = await core.storage.read(p.storage_key); if (!buf) throw new AppError('없음', 404); res.type(p.mime).send(buf); }));
  http.errors(app, (req, s, m) => V.page(req, { title: '오류', body: `<div class="card"><h1>${s}</h1><p>${esc(m)}</p><a href="/">처음으로</a></div>`, nav: req.user ? nav(req) : [] }));
  return app;
}
module.exports = { createAdminApp };
