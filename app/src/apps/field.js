'use strict';
// 현장 앱(태블릿): 입고·반출 계량·사용·반납·폐기 P1·입회. 매핑 저장소에 접근하는 코드가 이 앱에는 없습니다.
const http = require('../http'); const { wrap } = http; const V = require('../views'); const svc = require('../services');
const { can } = require('../perm'); const { kst, kstDate, addDays, AppError } = require('../util'); const { fmt } = require('../units');
const C = require('./common'); const J = require('../judge');
function createFieldApp(core) {
  const app = http.base(core, 'field'); const db = core.db; const esc = V.esc;
  app.use(http.sessionMw(app, db, db, { publicPaths: ['/login'] }));
  C.loginRoutes(app, { title: 'AEGIS v2 현장 앱' });
  app.use(C.requireFull);
  const P = (perm) => (req, res, next) => (can(req.user, perm, 'field') ? next() : next(new AppError('권한이 없습니다.', 403)));
  const nav = (req) => [['/', '오늘'], ['/inventory', '보관 재고'], can(req.user, 'receipt.create', 'field') && ['/receipts/new', '입고'], ['/checkouts', '반출·사용·반납'], can(req.user, 'disposal.create', 'field') && ['/disposals', '폐기'], can(req.user, 'witness.confirm', 'field') && ['/witness', '입회'], ['/alerts', '알림']].filter(Boolean);
  const pg = (req, title, body) => V.page(req, { title, body, nav: nav(req) });
  const ctx = C.ctxOf; const done = (res, msg, to) => { res.flash('ok', msg); res.redirect(303, to); };
  const J_HTML = (j, r) => (j ? `<span class="j-${esc(j)}">${esc(J.FIELD_LABEL[j])}</span> ${esc(r || '')}` : '');

  app.get('/', wrap(async (req, res) => {
    const u = req.user; const mine = await db.all("SELECT k.*, i.code FROM checkouts k JOIN item_codes i ON i.id=k.code_id WHERE k.requester_id=$1 AND k.status NOT IN ('returned','rejected','cancelled') ORDER BY k.id DESC", [u.id]);
    const al = (await svc.alerts(db)).filter((a) => ['반납 지연', '저울', '허가 게이트', '계량 보류', '용기 무게'].includes(a.kind));
    res.send(pg(req, '오늘', `<h1>${esc(u.display_name)} 님, 오늘 할 일</h1><div class="sub">${kstDate()} KST</div>
    <div class="grid g4 mb">${[can(u, 'checkout.request', 'field') && ['/checkouts/new', '반출 요청'], can(u, 'witness.confirm', 'field') && ['/witness', '입회 대기'], can(u, 'receipt.create', 'field') && ['/receipts/new', '입고 등록'], ['/inventory', '보관 재고']].filter(Boolean).map(([h, l]) => `<a class="btnbig" href="${h}">${l}</a>`).join('')}</div>
    <div class="card"><h2>내 반출 건</h2>${V.table(['번호', '코드', '단계', '반납 예정', ''], mine.map((k) => [esc(k.no), `<span class="mono">${esc(k.code)}</span>`, esc(svc.CO_STATUS[k.status]), esc(k.due_date), `<a href="/checkouts/${k.id}">열기</a>`]))}</div>
    <div class="card"><h2>현장 알림</h2>${al.map((a) => `<div class="lvl-${a.level}">● [${esc(a.kind)}] ${esc(a.text)}</div>`).join('') || '<p class="muted">없음</p>'}</div>`));
  }));
  app.get('/inventory', P('inventory.view'), wrap(async (req, res) => {
    const rows = await svc.inventory(db);
    res.send(pg(req, '보관 재고', `<h1>보관 재고(용기 단위)</h1><div class="sub">원장(입고 + 반출 − 반납 + 폐기 − 조정 ±) 합계. 반출 중인 양은 원장이 아니라 반출 건에서 따로 관리합니다.</div><div class="card">${V.table(['코드', '용기', '위치', '상태', '보관 순량', '용기 무게', ''], rows.map((c) => [`<span class="mono">${esc(c.code)}</span>${c.locked ? ' ' + V.badge('잠김', 'err') : ''}`, esc(c.cid), esc(c.location || '-'), esc(c.status), fmt(c.balance_ug), c.tare_ug === null ? V.badge('미확정', 'warn') : fmt(c.tare_ug), c.status === 'tare_pending' && can(req.user, 'receipt.create', 'field') ? `<a href="/containers/${c.id}/tare">용기 무게 확정</a>` : '']))}</div>`));
  }));
  // ── 입고
  app.get('/receipts/new', P('receipt.create'), wrap(async (req, res) => {
    const codes = await db.all("SELECT * FROM item_codes WHERE status='active' AND locked=0 ORDER BY code"); const locs = await db.all("SELECT * FROM locations WHERE active=1 AND kind='vault' AND in_permit_site=1 ORDER BY name");
    const lines = Array.from({ length: 5 }, (_, i) => `<tr><td>${i + 1}</td><td><input name="gross_${i + 1}" inputmode="decimal" ${i ? '' : 'required'}></td><td><input name="tare_${i + 1}" inputmode="decimal" placeholder="모르면 비움(미확정)"></td></tr>`).join('');
    res.send(pg(req, '입고 등록', `<h1>입고 등록</h1><form class="f card kpad" method="post" action="/receipts" enctype="multipart/form-data">${V.csrf(req)}
    <label>코드</label><select name="code_id" required>${codes.map((c) => `<option value="${c.id}">${esc(c.code)}</option>`).join('')}</select>
    <label>도착 일시(신고값)</label><input type="datetime-local" name="arrival_at" required><label>인수 일시(신고값)</label><input type="datetime-local" name="received_at" required>
    <p class="small muted">등록 일시는 서버 시각으로 자동 기록됩니다.</p>
    <label>인수 문서 번호(근거, 필수)</label><input name="doc_no" required><label>제공 신청서 접수번호</label><input name="supply_app_no"><label>출처 구분 코드</label><input name="source_ref" placeholder="예: SRC-01">
    <label>서류상 수량(신고 단위 그대로)</label><div class="flex"><input name="declared_value" placeholder="예: 100"><input name="declared_unit" placeholder="g / mg / mL / 개"></div>
    <label>봉인 번호</label><input name="seal_no"><label>봉인 상태</label><select name="seal_ok"><option value="1">정상</option><option value="0">훼손</option></select>
    <label>보관 금고(허가 소재지 안)</label><select name="location_id" required>${locs.map((l) => `<option value="${l.id}">${esc(l.name)}</option>`).join('')}</select>
    <label>저울</label><select name="scale_id" required>${await C.scaleOptions(db)}</select>${V.unitSel()}
    <label>용기 수</label><select name="lines">${[1, 2, 3, 4, 5].map((n) => `<option>${n}</option>`).join('')}</select>
    <table><tr><th>#</th><th>총중량</th><th>용기 무게(tare)</th></tr>${lines}</table>${V.photo()}<button>등록 → 입회 요청</button></form>`));
  }));
  app.post('/receipts', P('receipt.create'), ...C.upload(app, ['photo']), wrap(async (req, res) => { const id = await svc.createReceipt(ctx(req), req.body, req.files); done(res, '입고를 등록했습니다. 입회자 판독을 기다립니다.', `/receipts/${id}`); }));
  app.get('/receipts/:id', P('inventory.view'), wrap(async (req, res) => {
    const r = await db.get('SELECT r.*, i.code FROM receipts r JOIN item_codes i ON i.id=r.code_id WHERE r.id=$1', [Number(req.params.id)]); if (!r) throw new AppError('없음', 404);
    const cons = await db.all('SELECT * FROM containers WHERE lot_id=$1 ORDER BY id', [r.lot_id]); const fin = ['completed', 'blocked'].includes(r.status);
    const canW = r.status === 'await_witness' && can(req.user, 'witness.confirm', 'field') && Number(r.created_by) !== req.user.id;
    const canRe = r.status === 'reweigh' && Number(r.created_by) === req.user.id;
    const slotInputs = Array.from({ length: r.lines }, (_, i) => V.num(`gross_${i + 1}`, `${i + 1}번 용기(${cons[i] ? cons[i].cid : ''}) 총중량`)).join('');
    res.send(pg(req, r.no, `<h1>입고 ${esc(r.no)}</h1><div class="card">코드 <b class="mono">${esc(r.code)}</b> · 상태 <b>${esc(r.status)}</b>${r.attempt > 1 ? ' · 재계량(2회차)' : ''}<br>도착 ${kst(r.arrival_at)} (신고) · 인수 ${kst(r.received_at)} (신고) · 등록 ${kst(r.registered_at, true)} (서버)<br>문서 ${esc(r.doc_no)} · 봉인 ${esc(r.seal_no || '-')} ${r.seal_ok ? '정상' : V.badge('훼손', 'err')} · 서류 수량 ${esc(r.declared_value || '-')} ${esc(r.declared_unit || '')}</div>
    <div class="card"><h2>용기</h2>${V.table(['용기', '상태', '용기 무게'], cons.map((c) => [esc(c.cid), esc(c.status), c.tare_ug === null ? '미확정' : fmt(c.tare_ug)]))}</div>
    ${canW ? `<form class="f card kpad" method="post" action="/receipts/${r.id}/witness">${V.csrf(req)}<h2>입회 판독(블라인드)</h2><p class="muted">저울 표시창을 직접 보고 읽은 값을 넣으세요. 계량자 값은 보이지 않습니다.</p>${V.unitSel()}${slotInputs}${V.pw()}<button>판독 제출</button></form>` : ''}
    ${canRe ? `<form class="f card kpad" method="post" action="/receipts/${r.id}/reweigh" enctype="multipart/form-data">${V.csrf(req)}<h2>재계량(1회)</h2><p class="muted">입회 판독과 맞지 않았습니다. 다시 올려 계량하세요. 1차 값은 그대로 보존됩니다.</p>${V.unitSel()}${slotInputs}${V.photo()}<button>재계량 제출</button></form>` : ''}
    <div class="card"><h2>계량 기록</h2>${await C.readingsTable(db, 'receipt', r.id, fin)}</div>`));
  }));
  app.post('/receipts/:id/witness', P('witness.confirm'), wrap(async (req, res) => { const r = await svc.witnessReceipt(ctx(req), Number(req.params.id), req.body); done(res, r.result === 'match' ? '입회 확인 완료 — 원장에 반영했습니다.' : r.result === 'reweigh' ? '판독이 맞지 않습니다. 계량자가 1회 재계량합니다.' : '2회 불일치 — 이상 징후로 올리고 코드를 잠갔습니다.', `/receipts/${req.params.id}`); }));
  app.post('/receipts/:id/reweigh', P('receipt.create'), ...C.upload(app, ['photo']), wrap(async (req, res) => { await svc.reweighReceipt(ctx(req), Number(req.params.id), req.body, req.files); done(res, '재계량을 제출했습니다. 같은 입회자가 다시 판독합니다.', `/receipts/${req.params.id}`); }));
  // ── 용기 무게 확정
  app.get('/containers/:id/tare', P('receipt.create'), wrap(async (req, res) => {
    const c = await db.get('SELECT * FROM containers WHERE id=$1', [Number(req.params.id)]); if (!c) throw new AppError('없음', 404);
    const jobs = await db.all('SELECT * FROM tare_jobs WHERE container_id=$1 ORDER BY id DESC', [c.id]); const j = jobs[0];
    const canW = j && j.status === 'await_witness' && can(req.user, 'witness.confirm', 'field') && Number(j.created_by) !== req.user.id;
    res.send(pg(req, '용기 무게', `<h1>${esc(c.cid)} 용기 무게 확정</h1>
    ${c.status === 'tare_pending' && (!j || ['blocked', 'completed'].includes(j.status)) ? `<form class="f card kpad" method="post" action="/containers/${c.id}/tare" enctype="multipart/form-data">${V.csrf(req)}<label>저울</label><select name="scale_id">${await C.scaleOptions(db)}</select>${V.unitSel()}${V.num('tare', '용기·포장 무게')}${V.photo()}<button>계량 → 입회 요청</button></form>` : ''}
    ${j ? `<div class="card">작업 #${j.id} · ${esc(j.status)}${canW ? `<form class="f kpad" method="post" action="/tare/${j.id}/witness">${V.csrf(req)}<h2>입회 판독(블라인드)</h2>${V.unitSel()}${V.num('tare', '용기 무게 판독')}${V.pw()}<button>판독 제출</button></form>` : ''}
    ${j.status === 'reweigh' && Number(j.created_by) === req.user.id ? `<form class="f kpad" method="post" action="/tare/${j.id}/reweigh" enctype="multipart/form-data">${V.csrf(req)}<h2>재계량(1회)</h2>${V.unitSel()}${V.num('tare', '용기 무게')}${V.photo()}<button>재계량</button></form>` : ''}
    ${await C.readingsTable(db, 'tare', j.id, ['completed', 'blocked'].includes(j.status))}</div>` : ''}`));
  }));
  app.post('/containers/:id/tare', P('receipt.create'), ...C.upload(app, ['photo']), wrap(async (req, res) => { await svc.startTare(ctx(req), Number(req.params.id), req.body, req.files); done(res, '입회 판독을 기다립니다.', `/containers/${req.params.id}/tare`); }));
  app.post('/tare/:id/witness', P('witness.confirm'), wrap(async (req, res) => { const j = await db.get('SELECT container_id FROM tare_jobs WHERE id=$1', [Number(req.params.id)]); const r = await svc.witnessTare(ctx(req), Number(req.params.id), req.body); done(res, r.result === 'match' ? '용기 무게 확정 — 원장 반영' : r.result === 'reweigh' ? '불일치 — 1회 재계량' : '2회 불일치 — 이상 징후', `/containers/${j.container_id}/tare`); }));
  app.post('/tare/:id/reweigh', P('receipt.create'), ...C.upload(app, ['photo']), wrap(async (req, res) => { const j = await db.get('SELECT container_id FROM tare_jobs WHERE id=$1', [Number(req.params.id)]); await svc.reweighTare(ctx(req), Number(req.params.id), req.body, req.files); done(res, '재계량 제출', `/containers/${j.container_id}/tare`); }));
  // ── 반출·사용·반납
  app.get('/checkouts', P('inventory.view'), wrap(async (req, res) => {
    const all = can(req.user, 'receipt.create', 'field') || can(req.user, 'witness.confirm', 'field');
    const rows = await db.all(`SELECT k.*, i.code FROM checkouts k JOIN item_codes i ON i.id=k.code_id ${all ? '' : 'WHERE k.requester_id=$1'} ORDER BY k.id DESC LIMIT 100`, all ? [] : [req.user.id]);
    res.send(pg(req, '반출·사용·반납', `<h1>반출·사용·반납</h1>${can(req.user, 'checkout.request', 'field') ? '<a class="btn" href="/checkouts/new">반출 요청</a>' : ''}<div class="card">${V.table(['번호', '코드', '방식', '단계', '반납 예정', ''], rows.map((k) => [esc(k.no), `<span class="mono">${esc(k.code)}</span>`, k.mode === 'whole' ? '용기째' : '분주', esc(svc.CO_STATUS[k.status]), esc(k.due_date), `<a href="/checkouts/${k.id}">열기</a>`]))}</div>`));
  }));
  app.get('/checkouts/new', P('checkout.request'), wrap(async (req, res) => {
    const cons = (await svc.inventory(db)).filter((c) => c.status === 'stored' && !c.locked && c.balance_ug > 0); const labs = await db.all("SELECT * FROM locations WHERE active=1 AND kind='lab' AND in_permit_site=1 ORDER BY name");
    const s = await svc.settings(db);
    res.send(pg(req, '반출 요청', `<h1>반출 요청</h1>${s.permit_gate === '1' && s.permit_status !== 'confirmed' ? '<div class="flash err">허가 정보 확인 전이라 반출 요청이 잠겨 있습니다.</div>' : ''}<form class="f card kpad" method="post" action="/checkouts">${V.csrf(req)}
    <label>용기</label><select name="container_id" required>${cons.map((c) => `<option value="${c.id}">${esc(c.code)} · ${esc(c.cid)} · ${fmt(c.balance_ug)}</option>`).join('')}</select>
    <label>방식</label><select name="mode"><option value="aliquot">분주(하위 용기로 덜어 냄)</option><option value="whole">용기째</option></select>
    <label>요청량(분주일 때)</label><input name="requested" inputmode="decimal">${V.unitSel()}
    <label>목적</label><input name="purpose" required><label>실험 번호</label><input name="experiment_no">
    <label>사용 장소(허가 소재지 안 실험실)</label><select name="use_location_id" required>${labs.map((l) => `<option value="${l.id}">${esc(l.name)}</option>`).join('')}</select>
    <label>반납 예정일</label><input type="date" name="due_date" value="${addDays(kstDate(), Number(s.return_days))}" required><button>요청</button></form>`));
  }));
  app.post('/checkouts', P('checkout.request'), wrap(async (req, res) => { const id = await svc.requestCheckout(ctx(req), req.body); done(res, '반출을 요청했습니다. 관리 앱에서 승인합니다.', `/checkouts/${id}`); }));
  app.get('/checkouts/:id', P('inventory.view'), wrap(async (req, res) => {
    const k = await db.get('SELECT k.*, i.code FROM checkouts k JOIN item_codes i ON i.id=k.code_id WHERE k.id=$1', [Number(req.params.id)]); if (!k) throw new AppError('없음', 404);
    const u = req.user; const me = u.id; const isReq = Number(k.requester_id) === me; const sc = await C.scaleOptions(db);
    const uses = await db.all('SELECT * FROM usage_logs WHERE checkout_id=$1 ORDER BY id', [k.id]);
    const slots = svc.OUT_SLOTS[k.mode]; const LBL = { src_gross: '용기 총중량', src_before: '상위 용기 전 총중량', src_after: '상위 용기 후 총중량', ali_tare: '하위 용기 빈 무게', ali_gross: '하위 용기 총중량' };
    const outInputs = slots.map((sl) => V.num(sl, LBL[sl])).join('');
    const canPerform = (k.status === 'approved' && can(u, 'checkout.perform', 'field') && (isReq || can(u, 'receipt.create', 'field'))) || (k.status === 'out_reweigh' && Number(k.performer_id) === me);
    const wOk = (perfIds) => can(u, 'witness.confirm', 'field') && !perfIds.map(Number).includes(me);
    let forms = '';
    if (canPerform) forms += `<form class="f card kpad" method="post" action="/checkouts/${k.id}/out" enctype="multipart/form-data">${V.csrf(req)}<h2>반출 계량${k.status === 'out_reweigh' ? '(재계량 1회)' : ''}</h2>${k.status === 'approved' ? `<label>저울</label><select name="scale_id">${sc}</select>` : ''}${V.unitSel()}${outInputs}${V.photo()}<button>계량 제출 → 입회</button></form>`;
    if (k.status === 'out_await_witness' && wOk([k.requester_id, k.performer_id])) forms += `<form class="f card kpad" method="post" action="/checkouts/${k.id}/out-witness">${V.csrf(req)}<h2>반출 입회 판독(블라인드)</h2>${V.unitSel()}${outInputs}${V.pw()}<button>판독 제출</button></form>`;
    if (k.status === 'out' && isReq && can(u, 'usage.log', 'field') && !uses.some((x) => ['await_witness', 'reweigh'].includes(x.status))) forms += `<form class="f card kpad" method="post" action="/checkouts/${k.id}/usage" enctype="multipart/form-data">${V.csrf(req)}<h2>사용 기록(계량 + 입회)</h2><label>저울</label><select name="scale_id">${sc}</select>${V.unitSel()}${V.num('before', '사용 전 하위 용기 총중량')}${V.num('after', '사용 후 하위 용기 총중량')}<label>사용일</label><input type="date" name="used_on" value="${kstDate()}"><label>실험 번호</label><input name="experiment_no" value="${esc(k.experiment_no)}"><label>연구내용 요약(1~2문장, 품목명 쓰지 않음)</label><input name="research_summary" required><label>법정 장부 쪽·행 번호</label><input name="legal_row_no">${V.photo()}<button>계량 제출 → 입회</button></form>`;
    for (const x of uses) {
      if (x.status === 'await_witness' && wOk([x.by_user, k.requester_id])) forms += `<form class="f card kpad" method="post" action="/usage/${x.id}/witness">${V.csrf(req)}<h2>사용 #${x.id} 입회 판독(블라인드)</h2>${V.unitSel()}${V.num('before', '사용 전 총중량')}${V.num('after', '사용 후 총중량')}${V.pw()}<button>판독 제출</button></form>`;
      if (x.status === 'reweigh' && Number(x.by_user) === me) forms += `<form class="f card kpad" method="post" action="/usage/${x.id}/reweigh" enctype="multipart/form-data">${V.csrf(req)}<h2>사용 #${x.id} 재계량(1회)</h2>${V.unitSel()}${V.num('before', '사용 전 총중량')}${V.num('after', '사용 후 총중량')}${V.photo()}<button>재계량</button></form>`;
    }
    const canRet = (['out', 'return_hold'].includes(k.status) && (isReq || can(u, 'receipt.create', 'field'))) || (k.status === 'return_reweigh' && Number(k.return_submitter_id) === me);
    if (canRet) forms += `<form class="f card kpad" method="post" action="/checkouts/${k.id}/return" enctype="multipart/form-data">${V.csrf(req)}<h2>반납 계량${k.status === 'return_reweigh' ? '(재계량 1회)' : ''}</h2>${k.status !== 'return_reweigh' ? `<label>저울(쓸 수 있는 저울이 없으면 봉인 번호만 넣고 제출 → 계량 보류)</label><select name="scale_id"><option value="">저울 없음</option>${sc}</select><label>봉인 번호(계량 보류 시 필수)</label><input name="seal_no">` : ''}${V.unitSel()}<label>반납 총중량</label><input name="ret_gross" inputmode="decimal"><label>참고 메모</label><input name="reason">${V.photo()}<button>제출</button></form>`;
    if (k.status === 'return_await_witness' && wOk([k.requester_id, k.return_submitter_id])) forms += `<form class="f card kpad" method="post" action="/checkouts/${k.id}/return-witness">${V.csrf(req)}<h2>반납 입회 판독(블라인드)</h2><p class="muted">판정은 판독 제출 뒤에만 표시됩니다.</p>${V.unitSel()}${V.num('ret_gross', '반납 총중량 판독')}<label>봉인 상태</label><select name="seal_ok"><option value="1">정상</option><option value="0">훼손</option></select>${V.pw()}<button>판독 제출</button></form>`;
    const fin = ['returned', 'blocked'].includes(k.status);
    res.send(pg(req, k.no, `<h1>반출 ${esc(k.no)}</h1><div class="card">코드 <b class="mono">${esc(k.code)}</b> · ${k.mode === 'whole' ? '용기째' : '분주'} · 상태 <b>${esc(svc.CO_STATUS[k.status])}</b> · 반납 예정 ${esc(k.due_date)}<br>목적 ${esc(k.purpose)} · 실험 ${esc(k.experiment_no || '-')}
    ${['out', 'return_hold', 'return_await_witness', 'return_reweigh', 'returned', 'blocked'].includes(k.status) && k.out_ug !== null && (isReq || fin) ? `<br>반출량 ${fmt(k.out_ug)}` : ''}
    ${k.status === 'returned' ? `<br><b>판정: ${J_HTML(k.judgment, k.judgment_reason)}</b> · 실측 ${fmt(k.measured_ug)} / 예상 ${fmt(k.expected_ug)} (반출 ${fmt(k.out_ug)} − 사용 ${fmt(k.used_ug)}) · 차이 ${fmt(k.diff_ug)} · σ ${fmt(k.sigma_ug)}` : ''}</div>
    ${forms}<div class="card"><h2>사용 기록</h2>${V.table(['#', '사용일', '상태', '사용량(입회 계량)', '실험', '연구내용'], uses.map((x) => [String(x.id), esc(x.used_on), esc(x.status), x.status === 'confirmed' ? fmt(x.amount_ug) : '—', esc(x.experiment_no), esc(x.research_summary)]))}</div>
    <div class="card"><h2>계량 기록</h2>${await C.readingsTable(db, 'checkout', k.id, fin)}</div>`));
  }));
  app.post('/checkouts/:id/out', P('checkout.perform'), ...C.upload(app, ['photo']), wrap(async (req, res) => { await svc.submitOut(ctx(req), Number(req.params.id), req.body, req.files); done(res, '계량을 제출했습니다. 입회자 판독을 기다립니다.', `/checkouts/${req.params.id}`); }));
  app.post('/checkouts/:id/out-witness', P('witness.confirm'), wrap(async (req, res) => { const r = await svc.witnessOut(ctx(req), Number(req.params.id), req.body); done(res, { match: '반출 완료', reweigh: '불일치 — 계량자가 1회 재계량', fail: '2회 불일치 — 이상 징후·코드 잠금', stock_anomaly: '재고 대조 이상 — 코드 잠금', aliquot_anomaly: '분주 대조 이상 — 코드 잠금' }[r.result], `/checkouts/${req.params.id}`); }));
  app.post('/checkouts/:id/usage', P('usage.log'), ...C.upload(app, ['photo']), wrap(async (req, res) => { await svc.logUsage(ctx(req), Number(req.params.id), req.body, req.files); done(res, '사용 계량을 제출했습니다. 입회자 판독을 기다립니다.', `/checkouts/${req.params.id}`); }));
  app.post('/usage/:id/witness', P('witness.confirm'), wrap(async (req, res) => { const u = await db.get('SELECT checkout_id FROM usage_logs WHERE id=$1', [Number(req.params.id)]); const r = await svc.witnessUsage(ctx(req), Number(req.params.id), req.body); done(res, r.result === 'match' ? '사용량 확정' : r.result === 'reweigh' ? '불일치 — 1회 재계량' : '2회 불일치 — 이상 징후', `/checkouts/${u.checkout_id}`); }));
  app.post('/usage/:id/reweigh', P('usage.log'), ...C.upload(app, ['photo']), wrap(async (req, res) => { const u = await db.get('SELECT checkout_id FROM usage_logs WHERE id=$1', [Number(req.params.id)]); await svc.reweighUsage(ctx(req), Number(req.params.id), req.body, req.files); done(res, '재계량 제출', `/checkouts/${u.checkout_id}`); }));
  app.post('/checkouts/:id/return', P('return.submit'), ...C.upload(app, ['photo']), wrap(async (req, res) => { const r = await svc.submitReturn(ctx(req), Number(req.params.id), req.body, req.files); done(res, r && r.hold ? '계량 보류: 봉인·격리했습니다. 저울을 쓸 수 있게 되면 다시 계량하세요.' : '반납 계량을 제출했습니다. 입회자 판독 뒤 판정합니다.', `/checkouts/${req.params.id}`); }));
  app.post('/checkouts/:id/return-witness', P('witness.confirm'), wrap(async (req, res) => { const r = await svc.witnessReturn(ctx(req), Number(req.params.id), req.body); done(res, r.result === 'match' ? `판정: ${J.FIELD_LABEL[r.judgment.result]} — ${r.judgment.reason}` : r.result === 'reweigh' ? '같은 입회자로 1회 재계량합니다.' : '2회 불일치 — 이상 징후·코드 잠금', `/checkouts/${req.params.id}`); }));
  // ── 폐기 P1
  app.get('/disposals', P('disposal.create'), wrap(async (req, res) => {
    const rows = await db.all('SELECT d.*, c.cid FROM disposals d JOIN containers c ON c.id=d.container_id ORDER BY d.id DESC LIMIT 50');
    res.send(pg(req, '폐기', `<h1>폐기</h1><div class="sub">회사가 직접 폐기하거나 업체에 맡기지 않습니다. 격리·2인 계량 → 관청 신청 → 공무원 참관 → 결과 공문 순서입니다.</div><a class="btn" href="/disposals/new">폐기 사유 등록(P0)</a><div class="card">${V.table(['번호', '용기', '사유', '상태', ''], rows.map((d) => [esc(d.no), esc(d.cid), esc(svc.DISPOSAL_REASONS[d.reason_code]), esc(d.status), `<a href="/disposals/${d.id}">열기</a>`]))}</div>`));
  }));
  app.get('/disposals/new', P('disposal.create'), wrap(async (req, res) => {
    const cons = (await svc.inventory(db)).filter((c) => ['stored', 'quarantine'].includes(c.status)); const locs = await db.all("SELECT * FROM locations WHERE active=1 AND kind IN ('quarantine','vault') ORDER BY kind DESC, name");
    res.send(pg(req, '폐기 등록', `<h1>폐기 사유 등록 → 격리·2인 계량</h1><form class="f card kpad" method="post" action="/disposals" enctype="multipart/form-data">${V.csrf(req)}<label>용기</label><select name="container_id">${cons.map((c) => `<option value="${c.id}">${esc(c.code)} · ${esc(c.cid)}</option>`).join('')}</select>
    <label>사유</label><select name="reason_code">${Object.entries(svc.DISPOSAL_REASONS).map(([k, v]) => `<option value="${k}">${v}</option>`).join('')}</select><p class="small muted">변질·부패·파손은 사고 보고(5일) 흐름이 자동으로 시작됩니다.</p>
    <label>메모</label><input name="reason"><label>격리 칸</label><select name="quarantine_location_id">${locs.map((l) => `<option value="${l.id}">${esc(l.name)}</option>`).join('')}</select><label>봉인 번호</label><input name="seal_no" required>
    <label>저울</label><select name="scale_id">${await C.scaleOptions(db)}</select>${V.unitSel()}${V.num('gross', '용기 총중량')}${V.photo()}<button>계량 제출 → 입회</button></form>`));
  }));
  app.post('/disposals', P('disposal.create'), ...C.upload(app, ['photo']), wrap(async (req, res) => { const id = await svc.createDisposal(ctx(req), req.body, req.files); done(res, '등록했습니다. 입회자 판독을 기다립니다.', `/disposals/${id}`); }));
  app.get('/disposals/:id', P('inventory.view'), wrap(async (req, res) => {
    const d = await db.get('SELECT d.*, c.cid FROM disposals d JOIN containers c ON c.id=d.container_id WHERE d.id=$1', [Number(req.params.id)]); if (!d) throw new AppError('없음', 404);
    const canW = d.status === 'await_witness' && can(req.user, 'witness.confirm', 'field') && Number(d.created_by) !== req.user.id;
    res.send(pg(req, d.no, `<h1>폐기 ${esc(d.no)}</h1><div class="card">용기 ${esc(d.cid)} · 사유 ${esc(svc.DISPOSAL_REASONS[d.reason_code])} · 상태 <b>${esc(d.status)}</b> · 봉인 ${esc(d.seal_no)}</div>
    ${canW ? `<form class="f card kpad" method="post" action="/disposals/${d.id}/witness">${V.csrf(req)}<h2>입회 판독(블라인드)</h2>${V.unitSel()}${V.num('gross', '총중량 판독')}${V.pw()}<button>제출</button></form>` : ''}
    ${d.status === 'reweigh' && Number(d.created_by) === req.user.id ? `<form class="f card kpad" method="post" action="/disposals/${d.id}/reweigh" enctype="multipart/form-data">${V.csrf(req)}<h2>재계량(1회)</h2>${V.unitSel()}${V.num('gross', '총중량')}${V.photo()}<button>재계량</button></form>` : ''}
    <div class="card"><h2>계량 기록</h2>${await C.readingsTable(db, 'disposal', d.id, !['await_witness', 'reweigh'].includes(d.status))}</div>`));
  }));
  app.post('/disposals/:id/witness', P('witness.confirm'), wrap(async (req, res) => { const r = await svc.witnessDisposal(ctx(req), Number(req.params.id), req.body); done(res, r.result === 'match' ? 'P1 완료 — 격리. 관리 앱에서 관청 신청을 기록하세요.' : r.result === 'reweigh' ? '불일치 — 1회 재계량' : '2회 불일치 — 이상 징후', `/disposals/${req.params.id}`); }));
  app.post('/disposals/:id/reweigh', P('disposal.create'), ...C.upload(app, ['photo']), wrap(async (req, res) => { await svc.reweighDisposal(ctx(req), Number(req.params.id), req.body, req.files); done(res, '재계량 제출', `/disposals/${req.params.id}`); }));
  // ── 입회 대기 목록
  app.get('/witness', P('witness.confirm'), wrap(async (req, res) => {
    const me = req.user.id;
    const rows = [
      ...(await db.all("SELECT 'receipt' t, id, no, created_by p1, NULL p2, witness_id fw, attempt FROM receipts WHERE status='await_witness'")).map((r) => ({ ...r, link: `/receipts/${r.id}`, label: '입고' })),
      ...(await db.all("SELECT 'out' t, id, no, requester_id p1, performer_id p2, witness_id fw, step_attempt attempt FROM checkouts WHERE status='out_await_witness'")).map((r) => ({ ...r, link: `/checkouts/${r.id}`, label: '반출' })),
      ...(await db.all("SELECT 'ret' t, id, no, requester_id p1, return_submitter_id p2, return_witness_id fw, step_attempt attempt FROM checkouts WHERE status='return_await_witness'")).map((r) => ({ ...r, link: `/checkouts/${r.id}`, label: '반납' })),
      ...(await db.all("SELECT 'use' t, u.id, k.no, u.by_user p1, k.requester_id p2, u.witness_id fw, u.attempt FROM usage_logs u JOIN checkouts k ON k.id=u.checkout_id WHERE u.status='await_witness'")).map((r) => ({ ...r, link: `/checkouts/${r.no ? '' : ''}`, label: '사용' })),
      ...(await db.all("SELECT 'dsp' t, id, no, created_by p1, NULL p2, witness_id fw, attempt FROM disposals WHERE status='await_witness'")).map((r) => ({ ...r, link: `/disposals/${r.id}`, label: '폐기' })),
      ...(await db.all("SELECT 'tare' t, j.id, c.cid no, j.created_by p1, NULL p2, j.witness_id fw, j.attempt, c.id cidn FROM tare_jobs j JOIN containers c ON c.id=j.container_id WHERE j.status='await_witness'")).map((r) => ({ ...r, link: `/containers/${r.cidn}/tare`, label: '용기 무게' })),
    ];
    for (const r of rows) if (r.t === 'use') { const k = await db.get('SELECT checkout_id FROM usage_logs WHERE id=$1', [r.id]); r.link = `/checkouts/${k.checkout_id}`; }
    const mine = rows.filter((r) => Number(r.p1) !== me && Number(r.p2) !== me && (Number(r.attempt) < 2 || Number(r.fw) === me));
    res.send(pg(req, '입회', `<h1>입회 대기</h1><div class="sub">본인이 요청·계량한 건과, 다른 입회자가 맡은 재계량 건은 보이지 않습니다.</div><div class="card">${V.table(['구분', '번호', '회차', ''], mine.map((r) => [esc(r.label), esc(r.no), String(r.attempt), `<a href="${r.link}">판독하기</a>`]))}</div>`));
  }));
  app.get('/alerts', wrap(async (req, res) => { const al = await svc.alerts(db); res.send(pg(req, '알림', `<h1>알림</h1><div class="card">${al.map((a) => `<div class="lvl-${a.level}">● [${esc(a.kind)}] ${esc(a.text)}</div>`).join('') || '없음'}</div>`)); }));
  app.get('/photos/:id', wrap(async (req, res) => { const p = await db.get('SELECT * FROM photos WHERE id=$1', [Number(req.params.id)]); if (!p) throw new AppError('없음', 404); const buf = await core.storage.read(p.storage_key); if (!buf) throw new AppError('없음', 404); res.type(p.mime).send(buf); }));
  http.errors(app, (req, s, m) => V.page(req, { title: '오류', body: `<div class="card"><h1>${s}</h1><p>${esc(m)}</p><a href="/">처음으로</a></div>`, nav: req.user ? nav(req) : [] }));
  return app;
}
module.exports = { createFieldApp };
