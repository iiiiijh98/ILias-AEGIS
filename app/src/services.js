'use strict';
// AEGIS v2 업무 규칙(현장·관리 앱 공통). 원장 = 금고 안 보관 수량(µg). 보관 상태는 containers.status로 따로 관리.
// 모든 계량 단계: 계량자 입력·사진 → (값 가림) → 입회자 블라인드 판독 → 서버 비교 → 일치 시에만 판정·반영.
// 판독 불일치: 같은 입회자로 1회 재계량(두 값 모두 보존) → 2차도 불일치면 이상 징후 + 코드 잠금.
const auth = require('./auth');
const { writeAudit } = require('./audit');
const { can, rolesOf } = require('./perm');
const { AppError, nowIso, kstDate, addDays } = require('./util');
const { toUg, fmt } = require('./units');
const J = require('./judge');
const { makeCode, codeNumber, CATEGORIES, FORMS } = require('./codes');

const DEFAULT_SETTINGS = {
  z_warn: '3', z_anom: '4', z_up: '3', mdl_ug: '0', pct: '0', match_k: '2', stock_check_m: '4', // 판정 〔예시〕
  return_days: '7', lockout_threshold: '5', lockout_minutes: '15',
  incident_determine_hours: '24', incident_report_days: '5', incident_include_first_day: '1', incident_internal_target_day: '4', // 법무 3-B (기간 계산 [확인필요] → 보수적)
  disposal_apply_alert_days: '7', permit_gate: '1', permit_status: 'unconfirmed', // 허가 게이트(법무 4-1): 확인 전 반출·사용 잠금
  no_scale_policy: 'hold', // 저울 없음: 반출 차단, 반납은 봉인·격리 후 계량 보류
  mapping_max_knowers: '3', // 매핑을 아는 사람 수 상한(대표님 결정 대기, CTO 권고 3)
  board_show_amounts: '0', board_show_location_alerts: '1', // 전광판 노출 범위
};
const SETTING_LABEL = {
  z_warn: '경고 기준 z(누락)', z_anom: '이상 기준 z(누락)', z_up: '이상 기준 z(늘어남)', mdl_ug: '최소 검출 누락량(µg)', pct: '비례항(%) — 기본 0', match_k: '블라인드 일치 허용(k×s)', stock_check_m: '재고 대조 판독 수 m',
  return_days: '반납 기한 기본값(일)', lockout_threshold: '로그인 실패 잠금 횟수', lockout_minutes: '잠금 시간(분)',
  incident_determine_hours: '사고 1차 판정 기한(시간)', incident_report_days: '사고 보고 기한(일)', incident_include_first_day: '초일 포함(1=포함)', incident_internal_target_day: '사내 제출 목표(일차)',
  disposal_apply_alert_days: '폐기 신청 알림(일)', permit_gate: '허가 게이트(1=사용)', permit_status: '허가 상태(confirmed/unconfirmed)',
  no_scale_policy: '저울 없음 정책(hold/block)', mapping_max_knowers: '매핑을 아는 사람 수 상한', board_show_amounts: '전광판 무게 표시(1=표시)', board_show_location_alerts: '전광판 위치별 경보 표시(1=표시)',
};
const KNOWER_ROLES = ['sysadmin', 'mapping_deputy', 'permit_holder'];
const LEDGER_ROLES = ['manager', 'deputy', 'custodian', 'witness'];
const DISPOSAL_REASONS = { damaged: '변질·부패·파손', expired: '유효·사용기한 경과', storage: '보관 곤란' };
const CO_STATUS = {
  requested: '승인 대기', approved: '계량 대기', rejected: '반려', cancelled: '취소', out_await_witness: '반출 입회 대기', out_reweigh: '반출 재계량', out: '반출 중',
  return_hold: '계량 보류(봉인·격리)', return_await_witness: '반납 입회 대기', return_reweigh: '반납 재계량', returned: '반납 완료', blocked: '차단(이상 징후)',
};
const AN_TYPES = { WITNESS_MISMATCH: '입회 판독 불일치(2회)', RETURN_LOSS: '반납 누락', RETURN_INCREASE: '반납 무게 증가', RETURN_WARNING: '반납 감소(경고)', STOCK_MISMATCH: '재고 대조 차이', ALIQUOT_MISMATCH: '분주 대조 차이', SEAL_BROKEN: '봉인 훼손', RECEIPT_DOC: '입고 서류 차이', OVERDUE: '반납 지연', MANUAL: '수동 신고', INCONSISTENT: '기록 불일치', IMPORT_CHECK: '가져오기 확인 필요' };
const INC_STATUS = { awaiting_determination: '1차 판정 대기', report_pending: '보고 준비', reported: '보고 완료', not_reportable: '보고 대상 아님(계량 오류)' };

const need = (ctx, perm) => { if (!can(ctx.user, perm, ctx.app)) throw new AppError('권한이 없습니다.', 403); };
async function settings(t) { const rows = await t.all('SELECT key, value FROM settings'); const s = { ...DEFAULT_SETTINGS }; for (const r of rows) s[r.key] = r.value; return s; }
async function initSettings(db) { for (const [k, v] of Object.entries(DEFAULT_SETTINGS)) { const r = await db.get('SELECT key FROM settings WHERE key=$1', [k]); if (!r) await db.run('INSERT INTO settings (key, value) VALUES ($1,$2)', [k, v]); } }
async function nextNo(t, table, prefix) {
  const day = kstDate().replace(/-/g, ''); const like = `${prefix}-${day}-%`;
  const r = await t.get(`SELECT no FROM ${table} WHERE no LIKE $1 ORDER BY no DESC LIMIT 1`, [like]);
  const n = r ? Number(r.no.split('-').pop()) + 1 : 1; return `${prefix}-${day}-${String(n).padStart(3, '0')}`;
}
const txt = (v, max = 200) => String(v ?? '').trim().slice(0, max);
const reqTxt = (v, label, max = 200) => { const s = txt(v, max); if (!s) throw new AppError(`${label}을(를) 입력하세요.`); return s; };
function kstLocalToIso(v, label) { const s = String(v || '').trim(); if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(s)) throw new AppError(`${label}: 날짜·시각을 입력하세요.`); const d = new Date(`${s}:00+09:00`); if (isNaN(d)) throw new AppError(`${label} 형식 오류`); return d.toISOString(); }
const isDay = (s) => /^\d{4}-\d{2}-\d{2}$/.test(String(s || ''));
async function balanceOf(t, containerId) { const r = await t.get('SELECT COALESCE(SUM(delta_ug),0) AS s FROM ledger WHERE container_id=$1', [containerId]); return Number(r.s); }
async function reservedOf(t, containerId, exceptId = 0) { const r = await t.get("SELECT COALESCE(SUM(requested_ug),0) AS s FROM checkouts WHERE container_id=$1 AND id<>$2 AND status IN ('requested','approved','out_await_witness','out_reweigh')", [containerId, exceptId]); return Number(r.s); }
async function getCode(t, id) { const c = await t.get('SELECT * FROM item_codes WHERE id=$1', [id]); if (!c) throw new AppError('코드를 찾을 수 없습니다.', 404); return c; }
const usableCode = (c) => { if (c.status !== 'active') throw new AppError('사용 중지된 코드입니다.'); if (c.locked) throw new AppError(`${c.code}는 이상 징후로 잠긴 코드입니다. 관리책임자 2인 종결 전에는 진행할 수 없습니다.`, 409); };
async function usableScale(t, scaleId) {
  const s = scaleId ? await t.get('SELECT * FROM scales WHERE id=$1 AND active=1', [Number(scaleId)]) : null;
  if (!s) return { ok: false, why: '사용할 수 있는 저울을 선택하세요.' };
  if (!s.calib_due || s.calib_due < kstDate()) return { ok: false, why: `저울 ${s.scale_id} 교정 기한이 지났거나 없습니다.`, scale: s };
  if (!(Number(s.repeatability_ug) > 0)) return { ok: false, why: `저울 ${s.scale_id} 반복성(s)이 등록되지 않아 판정할 수 없습니다.`, scale: s };
  return { ok: true, scale: s };
}
async function needScale(t, id) { const r = await usableScale(t, id); if (!r.ok) throw new AppError(r.why, 409); return r.scale; }
async function permitGate(t) { const s = await settings(t); if (s.permit_gate === '1' && s.permit_status !== 'confirmed') throw new AppError('허가 정보 확인 전에는 반출·사용을 할 수 없습니다(허가 게이트).', 423); }
async function notifyLock(t, ctx, codeId) { await t.run('UPDATE item_codes SET locked=1, updated_at=$1 WHERE id=$2', [nowIso(), codeId]); await writeAudit(t, ctx, 'CODE_LOCK', 'item_code', codeId, null, { locked: true }); }

// ── 사고·외부 보고 트랙(이상 등급이면 자동 시작, 종결과 별개)
function incidentDues(awareIso, s) {
  const day = kstDate(awareIso); const days = Number(s.incident_report_days); const first = s.incident_include_first_day === '1';
  const endOf = (d) => new Date(`${d}T23:59:59+09:00`).toISOString();
  return {
    determine_due: new Date(Date.parse(awareIso) + Number(s.incident_determine_hours) * 3600000).toISOString(),
    report_due: endOf(addDays(day, first ? days - 1 : days)),
    internal_target: endOf(addDays(day, first ? Number(s.incident_internal_target_day) - 1 : Number(s.incident_internal_target_day))),
  };
}
async function createIncident(t, ctx, { anomaly_id = null, disposal_id = null, code_id = null, aware_at = null }) {
  const s = await settings(t); const now = nowIso(); const aware = aware_at && aware_at < now ? aware_at : now;
  const d = incidentDues(aware, s); const no = await nextNo(t, 'incidents', 'INC');
  const r = await t.get('INSERT INTO incidents (no, anomaly_id, disposal_id, code_id, aware_at, discovered_by, determine_due, report_due, internal_target, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING id',
    [no, anomaly_id, disposal_id, code_id, aware, ctx.user ? ctx.user.id : null, d.determine_due, d.report_due, d.internal_target, now]);
  await writeAudit(t, ctx, 'INCIDENT_OPEN', 'incident', r.id, null, { no, aware_at: aware, report_due: d.report_due });
  return r.id;
}
async function createAnomaly(t, ctx, a) {
  const no = await nextNo(t, 'anomalies', 'AN'); const at = nowIso();
  const r = await t.get('INSERT INTO anomalies (no, type, severity, code_id, ref_type, ref_id, diff_ug, description, locks_code, adjust_container_id, adjust_to_ug, created_by, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING id',
    [no, a.type, a.severity, a.code_id || null, a.ref_type || null, a.ref_id || null, a.diff_ug ?? null, a.description, a.locks ? 1 : 0, a.adjust_container_id || null, a.adjust_to_ug ?? null, ctx.user ? ctx.user.id : null, at]);
  await writeAudit(t, ctx, 'ANOMALY_OPEN', 'anomaly', r.id, null, { no, type: a.type, severity: a.severity, locks: !!a.locks });
  if (a.locks && a.code_id) await notifyLock(t, ctx, a.code_id);
  if (a.severity === 'anomaly') { const inc = await createIncident(t, ctx, { anomaly_id: r.id, code_id: a.code_id }); await t.run('UPDATE anomalies SET incident_id=$1 WHERE id=$2', [inc, r.id]); }
  return r.id;
}

// ── 판독 기록(추가 전용)
async function saveReadings(t, ctx, { refType, refId, purpose, role, attempt, scale, slots, containers = {}, method = 'manual' }) {
  const at = nowIso();
  for (const [slot, v] of Object.entries(slots)) {
    await t.run('INSERT INTO weighings (ref_type, ref_id, purpose, slot, role, attempt, container_id, scale_id, value_ug, resolution_ug, stable, entered, method, by_user, at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,1,$11,$12,$13,$14)',
      [refType, refId, purpose, slot, role, attempt, containers[slot] || null, scale ? scale.id : null, v.ug, scale ? scale.resolution_ug : null, v.entered, method, ctx.user.id, at]);
  }
}
async function readings(t, refType, refId, purpose, role, attempt) {
  const rows = await t.all('SELECT slot, value_ug FROM weighings WHERE ref_type=$1 AND ref_id=$2 AND purpose=$3 AND role=$4 AND attempt=$5', [refType, refId, purpose, role, attempt]);
  return Object.fromEntries(rows.map((r) => [r.slot, Number(r.value_ug)]));
}
function parseSlots(b, names, label = '계량값') {
  const unit = b.unit || 'g'; const o = {};
  for (const n of names) { const raw = b[n]; o[n] = { ug: toUg(raw, unit, `${label}(${n})`), entered: `${String(raw).trim()} ${unit}` }; }
  return o;
}
// 블라인드 비교 공통: 결과 'match' | 'reweigh' | 'fail'
async function blindCompare(t, ctx, { refType, refId, purpose, attempt, slots, scale, s }) {
  await saveReadings(t, ctx, { refType, refId, purpose, role: 'witness', attempt, scale, slots });
  const perf = await readings(t, refType, refId, purpose, 'performer', attempt);
  const bad = Object.keys(perf).filter((k) => !(k in slots) || !J.readingsMatch(perf[k], slots[k].ug, { dUg: scale.resolution_ug, sUg: scale.repeatability_ug, k: Number(s.match_k) }));
  if (!bad.length) return { result: 'match', perf };
  return { result: attempt >= 2 ? 'fail' : 'reweigh', bad };
}
const witnessGuard = (ent, ctx, performerIds, firstWitnessId) => {
  if (performerIds.filter(Boolean).map(Number).includes(ctx.user.id)) throw new AppError('계량자·요청자와 다른 사람이 입회해야 합니다.', 403);
  if (firstWitnessId && Number(firstWitnessId) !== ctx.user.id) throw new AppError('재계량은 1차 입회자가 다시 판독해야 합니다.', 403);
};
async function storePhotos(ctx, files, kinds) {
  const out = [];
  for (const k of kinds) { const f = files && files[k] && files[k][0]; if (!f) throw new AppError('저울 표시창 사진을 첨부하세요.'); out.push({ kind: k, ...(await ctx.storage.save(f.buffer)) }); }
  return out;
}
async function attachPhotos(t, ctx, photos, refType, refId) {
  for (const p of photos) await t.run('INSERT INTO photos (ref_type, ref_id, kind, storage_key, mime, size, sha256, uploaded_by, at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)', [refType, refId, p.kind, p.storage_key, p.mime, p.size, p.sha256, ctx.user.id, nowIso()]);
  return photos.map((p) => p.sha256.slice(0, 16));
}

// ══ 코드 (관리 앱, 2인 승인)
async function requestCode(ctx, b) {
  need(ctx, 'code.request');
  const category = String(b.category || ''); if (!CATEGORIES.includes(category)) throw new AppError('분류는 목록에서 고르세요.');
  const form = String(b.form || ''); if (!(form in FORMS)) throw new AppError('형태를 고르세요.');
  const return_days = b.return_days ? Math.max(1, Math.min(90, Number(b.return_days) || 7)) : null;
  const reason = reqTxt(b.reason, '요청 사유'); const count = Math.max(1, Math.min(20, Number(b.count) || 1));
  return ctx.db.tx(async (t) => {
    const r = await t.get("INSERT INTO approvals (type, payload, reason, requested_by, created_at) VALUES ('code_create',$1,$2,$3,$4) RETURNING id", [JSON.stringify({ category, form, return_days, count }), reason, ctx.user.id, nowIso()]);
    await writeAudit(t, ctx, 'CODE_REQUEST', 'approval', r.id, null, { category, form, count }); return r.id;
  });
}
async function decideApproval(ctx, id, approve, note, password) {
  need(ctx, 'code.approve'); await auth.reauth(ctx.user, password);
  return ctx.db.tx(async (t) => {
    const a = await t.get('SELECT * FROM approvals WHERE id=$1', [id]); if (!a) throw new AppError('요청을 찾을 수 없습니다.', 404);
    if (a.status !== 'pending') throw new AppError('이미 처리된 요청입니다.');
    if (Number(a.requested_by) === ctx.user.id) throw new AppError('본인 요청은 승인할 수 없습니다(2인 원칙).', 403);
    const at = nowIso(); const created = [];
    await t.run('UPDATE approvals SET status=$1, decided_by=$2, decision_note=$3, decided_at=$4 WHERE id=$5', [approve ? 'approved' : 'rejected', ctx.user.id, txt(note, 300), at, id]);
    if (approve && a.type === 'code_create') {
      const p = JSON.parse(a.payload); const rows = await t.all('SELECT code FROM item_codes');
      let max = rows.reduce((m, r) => Math.max(m, codeNumber(r.code)), 0);
      for (let i = 0; i < p.count; i++) { const code = makeCode(++max); await t.run('INSERT INTO item_codes (code, category, form, return_days, created_by, approved_by, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$7)', [code, p.category, p.form, p.return_days, a.requested_by, ctx.user.id, at]); created.push(code); }
    }
    await writeAudit(t, ctx, approve ? 'APPROVAL_APPROVE' : 'APPROVAL_REJECT', 'approval', id, { status: 'pending' }, { status: approve ? 'approved' : 'rejected', created });
    return created;
  });
}

// ══ 기준 정보
async function createLocation(ctx, b) {
  need(ctx, 'master.manage'); const name = reqTxt(b.name, '위치 이름', 60); const kind = ['vault', 'lab', 'quarantine'].includes(b.kind) ? b.kind : 'vault';
  const inSite = b.in_permit_site === '0' ? 0 : 1;
  return ctx.db.tx(async (t) => { const r = await t.get('INSERT INTO locations (name, kind, in_permit_site, created_at) VALUES ($1,$2,$3,$4) RETURNING id', [name, kind, inSite, nowIso()]); await writeAudit(t, ctx, 'LOCATION_CREATE', 'location', r.id, null, { name, kind, in_permit_site: inSite }); return r.id; });
}
async function upsertScale(ctx, b) {
  need(ctx, 'master.manage');
  const scale_id = reqTxt(b.scale_id, '저울 ID', 40); const resolution_ug = toUg(b.resolution, b.res_unit || 'mg', '분해능');
  if (!(resolution_ug > 0)) throw new AppError('분해능은 0보다 커야 합니다.');
  const rep = String(b.repeatability || '').trim() ? toUg(b.repeatability, b.res_unit || 'mg', '반복성') : null;
  const calib_due = isDay(b.calib_due) ? b.calib_due : null;
  return ctx.db.tx(async (t) => {
    const ex = await t.get('SELECT * FROM scales WHERE scale_id=$1', [scale_id]);
    if (ex) { await t.run('UPDATE scales SET model=$1, resolution_ug=$2, repeatability_ug=$3, location=$4, calib_due=$5 WHERE id=$6', [txt(b.model, 60), resolution_ug, rep, txt(b.location, 60), calib_due, ex.id]); await writeAudit(t, ctx, 'SCALE_UPDATE', 'scale', ex.id, { resolution_ug: ex.resolution_ug, repeatability_ug: ex.repeatability_ug, calib_due: ex.calib_due }, { resolution_ug, repeatability_ug: rep, calib_due }); return ex.id; }
    const r = await t.get('INSERT INTO scales (scale_id, model, resolution_ug, repeatability_ug, location, calib_due, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id', [scale_id, txt(b.model, 60), resolution_ug, rep, txt(b.location, 60), calib_due, nowIso()]);
    await writeAudit(t, ctx, 'SCALE_CREATE', 'scale', r.id, null, { scale_id, resolution_ug, repeatability_ug: rep, calib_due }); return r.id;
  });
}
async function updateSettings(ctx, b) {
  need(ctx, 'settings.manage'); const reason = reqTxt(b.reason, '변경 사유');
  return ctx.db.tx(async (t) => {
    const cur = await settings(t); const before = {}, after = {};
    for (const k of Object.keys(DEFAULT_SETTINGS)) {
      if (b[k] === undefined || String(b[k]) === cur[k]) continue;
      const v = String(b[k]).trim();
      if (['no_scale_policy'].includes(k) ? !['hold', 'block'].includes(v) : k === 'permit_status' ? !['confirmed', 'unconfirmed'].includes(v) : !/^\d+(\.\d+)?$/.test(v)) throw new AppError(`${SETTING_LABEL[k]}: 값 형식 오류`);
      before[k] = cur[k]; after[k] = v; await t.run('UPDATE settings SET value=$1 WHERE key=$2', [v, k]);
    }
    if (Object.keys(after).length) await writeAudit(t, ctx, 'SETTINGS_UPDATE', 'settings', null, before, { ...after, reason });
    return after;
  });
}
// 사용자(시스템관리자). 매핑을 아는 역할(KNOWER)과 원장 역할은 겸할 수 없고, 아는 사람 수에 상한.
async function saveUser(ctx, b) {
  need(ctx, 'user.manage');
  const roles = [].concat(b.roles || []).filter((r) => r && require('./perm').ROLES[r]);
  if (roles.some((r) => KNOWER_ROLES.includes(r)) && roles.some((r) => LEDGER_ROLES.includes(r))) throw new AppError('매핑을 아는 역할(시스템관리자·지정 대행자·허가 명의자)은 관리책임자·부책임자·보관담당·입회자를 겸할 수 없습니다.');
  return ctx.db.tx(async (t) => {
    const username = reqTxt(b.username, '아이디', 30).toLowerCase(); if (!/^[a-z0-9._-]{3,30}$/.test(username)) throw new AppError('아이디는 영문 소문자·숫자 3~30자');
    const ex = await t.get('SELECT * FROM users WHERE username=$1', [username]);
    if (roles.some((r) => KNOWER_ROLES.includes(r))) {
      const s = await settings(t); const all = await t.all("SELECT id, roles FROM users WHERE active=1");
      const n = all.filter((u) => u.id !== (ex && ex.id) && rolesOf(u).some((r) => KNOWER_ROLES.includes(r))).length + 1;
      if (n > Number(s.mapping_max_knowers)) throw new AppError(`매핑을 아는 사람 수 상한(${s.mapping_max_knowers}명)을 넘습니다.`);
    }
    if (ex) {
      await t.run('UPDATE users SET roles=$1, display_name=$2 WHERE id=$3', [roles.join(','), txt(b.display_name, 40) || ex.display_name, ex.id]);
      await writeAudit(t, ctx, 'USER_ROLES', 'user', ex.id, { roles: ex.roles }, { roles: roles.join(',') }); return ex.id;
    }
    auth.validatePassword(b.temp_password);
    const r = await t.get('INSERT INTO users (username, display_name, password_hash, roles, must_change_pw, created_at) VALUES ($1,$2,$3,$4,1,$5) RETURNING id', [username, reqTxt(b.display_name, '표시 이름', 40), await auth.hashPassword(b.temp_password, ctx.cfg.bcryptRounds), roles.join(','), nowIso()]);
    await writeAudit(t, ctx, 'USER_CREATE', 'user', r.id, null, { username, roles: roles.join(',') }); return r.id;
  });
}
async function createBoardDevice(ctx, b) {
  need(ctx, 'device.manage'); const name = reqTxt(b.name, '단말 이름', 40);
  const token = require('./util').randomToken(24);
  return ctx.db.tx(async (t) => {
    const r = await t.get("INSERT INTO devices (kind, name, token_hash, allow_cidrs, created_by, created_at) VALUES ('board',$1,$2,$3,$4,$5) RETURNING id", [name, require('./util').sha256(token), txt(b.allow_cidrs, 200), ctx.user.id, nowIso()]);
    await writeAudit(t, ctx, 'DEVICE_CREATE', 'device', r.id, null, { name, kind: 'board' }); return { id: r.id, token };
  });
}
async function revokeDevice(ctx, id) { need(ctx, 'device.manage'); return ctx.db.tx(async (t) => { await t.run('UPDATE devices SET active=0 WHERE id=$1', [id]); await t.run('DELETE FROM sessions WHERE device_id=$1', [id]); await writeAudit(t, ctx, 'DEVICE_REVOKE', 'device', id, null, { active: 0 }); }); }

// ══ 입고 (현장)
async function createReceipt(ctx, b, files) {
  need(ctx, 'receipt.create');
  const arrival_at = kstLocalToIso(b.arrival_at, '도착 일시'); const received_at = kstLocalToIso(b.received_at, '인수 일시'); const registered_at = nowIso();
  if (arrival_at > received_at) throw new AppError('인수 일시가 도착 일시보다 빠를 수 없습니다.');
  if (Date.parse(received_at) > Date.now() + 5 * 60000) throw new AppError('인수 일시가 현재 시각보다 늦을 수 없습니다.');
  const doc_no = reqTxt(b.doc_no, '인수 문서 번호(근거)', 80); const n = Math.max(1, Math.min(5, Number(b.lines) || 1));
  const grossNames = Array.from({ length: n }, (_, i) => `gross_${i + 1}`); const slots = parseSlots(b, grossNames, '총중량');
  const tares = grossNames.map((_, i) => (String(b[`tare_${i + 1}`] || '').trim() ? toUg(b[`tare_${i + 1}`], b.unit || 'g', `용기 무게 ${i + 1}`) : null));
  tares.forEach((tr, i) => { if (tr !== null && tr >= slots[grossNames[i]].ug) throw new AppError(`${i + 1}번 용기: 용기 무게가 총중량보다 크거나 같습니다.`); });
  const photos = await storePhotos(ctx, files, ['photo']);
  return ctx.db.tx(async (t) => {
    const code = await getCode(t, Number(b.code_id)); usableCode(code);
    const loc = await t.get("SELECT * FROM locations WHERE id=$1 AND active=1 AND kind='vault'", [Number(b.location_id)]); if (!loc) throw new AppError('보관 금고를 선택하세요.');
    if (!loc.in_permit_site) throw new AppError('허가 소재지 밖 위치에는 보관할 수 없습니다.');
    const scale = await needScale(t, b.scale_id);
    const no = await nextNo(t, 'receipts', 'IN'); const at = nowIso();
    const r = await t.get('INSERT INTO receipts (no, code_id, arrival_at, received_at, registered_at, source_ref, doc_no, supply_app_no, seal_no, seal_ok, declared_value, declared_unit, location_id, scale_id, lines, status, created_by) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17) RETURNING id',
      [no, code.id, arrival_at, received_at, registered_at, txt(b.source_ref, 60), doc_no, txt(b.supply_app_no, 60), txt(b.seal_no, 40), b.seal_ok === '0' ? 0 : 1, txt(b.declared_value, 30) || null, txt(b.declared_unit, 10) || null, loc.id, scale.id, n, 'await_witness', ctx.user.id]);
    const lot = await t.get('INSERT INTO lots (lot_no, code_id, receipt_id, created_at) VALUES ($1,$2,$3,$4) RETURNING id', [`L-${no.slice(3)}`, code.id, r.id, at]);
    await t.run('UPDATE receipts SET lot_id=$1 WHERE id=$2', [lot.id, r.id]);
    const cmap = {};
    for (let i = 0; i < n; i++) { const c = await t.get('INSERT INTO containers (cid, code_id, lot_id, tare_ug, location_id, status, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$7) RETURNING id', [`C-${no.slice(3)}-${i + 1}`, code.id, lot.id, tares[i], loc.id, 'pending', at]); cmap[grossNames[i]] = c.id; }
    await saveReadings(t, ctx, { refType: 'receipt', refId: r.id, purpose: 'receipt', role: 'performer', attempt: 1, scale, slots, containers: cmap });
    const ph = await attachPhotos(t, ctx, photos, 'receipt', r.id);
    await writeAudit(t, ctx, 'RECEIPT_CREATE', 'receipt', r.id, null, { no, code: code.code, lines: n, arrival_at, received_at, registered_at, doc_no, seal_ok: b.seal_ok !== '0', photos: ph }); // 계량값은 입회 전까지 감사 화면에도 노출하지 않도록 판독 테이블에만
    return r.id;
  });
}
async function reweighReceipt(ctx, id, b, files) {
  need(ctx, 'receipt.create'); const photos = await storePhotos(ctx, files, ['photo']);
  return ctx.db.tx(async (t) => {
    const r = await t.get('SELECT * FROM receipts WHERE id=$1', [id]); if (!r || r.status !== 'reweigh') throw new AppError('재계량 대기 상태가 아닙니다.');
    const scale = await needScale(t, r.scale_id); const names = Array.from({ length: r.lines }, (_, i) => `gross_${i + 1}`);
    const cons = await t.all('SELECT id FROM containers WHERE lot_id=$1 ORDER BY id', [r.lot_id]); const cmap = Object.fromEntries(names.map((n, i) => [n, cons[i] && cons[i].id]));
    await saveReadings(t, ctx, { refType: 'receipt', refId: id, purpose: 'receipt', role: 'performer', attempt: 2, scale, slots: parseSlots(b, names, '총중량'), containers: cmap });
    await t.run("UPDATE receipts SET status='await_witness' WHERE id=$1", [id]); await attachPhotos(t, ctx, photos, 'receipt', id);
    await writeAudit(t, ctx, 'RECEIPT_REWEIGH', 'receipt', id, null, { attempt: 2 });
  });
}
async function witnessReceipt(ctx, id, b) {
  need(ctx, 'witness.confirm'); await auth.reauth(ctx.user, b.password);
  return ctx.db.tx(async (t) => {
    const r = await t.get('SELECT * FROM receipts WHERE id=$1', [id]); if (!r || r.status !== 'await_witness') throw new AppError('입회 대기 상태가 아닙니다.');
    witnessGuard(r, ctx, [r.created_by], r.attempt > 1 ? r.witness_id : null);
    const s = await settings(t); const scale = await needScale(t, r.scale_id); const names = Array.from({ length: r.lines }, (_, i) => `gross_${i + 1}`);
    const cmp = await blindCompare(t, ctx, { refType: 'receipt', refId: id, purpose: 'receipt', attempt: r.attempt, slots: parseSlots(b, names, '입회 판독'), scale, s });
    const cons = await t.all('SELECT * FROM containers WHERE lot_id=$1 ORDER BY id', [r.lot_id]);
    if (cmp.result === 'reweigh') { await t.run("UPDATE receipts SET status='reweigh', attempt=2, witness_id=$1 WHERE id=$2", [ctx.user.id, id]); await writeAudit(t, ctx, 'RECEIPT_WITNESS_MISMATCH', 'receipt', id, null, { attempt: 1, next: 'reweigh' }); return { result: 'reweigh' }; }
    if (cmp.result === 'fail') {
      await t.run("UPDATE receipts SET status='blocked', blocked=1, witness_id=$1 WHERE id=$2", [ctx.user.id, id]);
      for (const c of cons) await t.run("UPDATE containers SET status='quarantine', updated_at=$1 WHERE id=$2", [nowIso(), c.id]);
      await createAnomaly(t, ctx, { type: 'WITNESS_MISMATCH', severity: 'anomaly', code_id: r.code_id, ref_type: 'receipt', ref_id: id, description: `${r.no}: 입고 입회 판독 2회 불일치`, locks: true });
      return { result: 'fail' };
    }
    const at = nowIso(); let total = 0; let allTare = true;
    for (let i = 0; i < cons.length; i++) {
      const c = cons[i]; const gross = cmp.perf[`gross_${i + 1}`];
      if (c.tare_ug === null || c.tare_ug === undefined) { allTare = false; await t.run("UPDATE containers SET status='tare_pending', updated_at=$1 WHERE id=$2", [at, c.id]); continue; }
      const net = gross - Number(c.tare_ug); total += net;
      await t.run('INSERT INTO ledger (container_id, code_id, type, delta_ug, ref_type, ref_id, note, by_user, at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)', [c.id, r.code_id, 'RECEIPT', net, 'receipt', id, r.no, ctx.user.id, at]);
      await t.run("UPDATE containers SET status=$1, updated_at=$2 WHERE id=$3", [r.seal_ok ? 'stored' : 'quarantine', at, c.id]);
    }
    await t.run("UPDATE receipts SET status='completed', witness_id=$1, completed_at=$2 WHERE id=$3", [ctx.user.id, at, id]);
    await writeAudit(t, ctx, 'RECEIPT_COMPLETE', 'receipt', id, { status: 'await_witness' }, { status: 'completed', containers: cons.length, tare_pending: !allTare });
    if (!r.seal_ok) await createAnomaly(t, ctx, { type: 'SEAL_BROKEN', severity: 'anomaly', code_id: r.code_id, ref_type: 'receipt', ref_id: id, description: `${r.no}: 입고 봉인 훼손`, locks: true });
    // 서류 수량 대조: 질량 단위이고 모든 용기 무게가 확정된 경우만. 그 밖은 '비교 불가'(관리책임자 확인)
    if (allTare && r.declared_value && ['g', 'mg', 'ug', 'µg'].includes(String(r.declared_unit || '').toLowerCase())) {
      const decl = toUg(r.declared_value, r.declared_unit, '서류 수량'); const sg = J.sigmaD({ m: 2 * cons.length, sUg: scale.repeatability_ug, dUg: scale.resolution_ug });
      const jd = J.judge({ measuredUg: total, expectedUg: decl, sigmaUg: sg, opts: s });
      if (jd.result !== 'normal') await createAnomaly(t, ctx, { type: 'RECEIPT_DOC', severity: 'warning', code_id: r.code_id, ref_type: 'receipt', ref_id: id, diff_ug: jd.diffUg, description: `${r.no}: 서류 수량 대비 실측 ${jd.reason}` });
    }
    return { result: 'match', total, allTare };
  });
}
// 용기 무게 확정(입고 때 미확정) — 계량 + 블라인드 입회 후 RECEIPT 원장 반영
async function startTare(ctx, containerId, b, files) {
  need(ctx, 'receipt.create'); const photos = await storePhotos(ctx, files, ['photo']);
  return ctx.db.tx(async (t) => {
    const c = await t.get('SELECT * FROM containers WHERE id=$1', [containerId]); if (!c || c.status !== 'tare_pending') throw new AppError('용기 무게 미확정 상태가 아닙니다.');
    const scale = await needScale(t, b.scale_id);
    const j = await t.get("INSERT INTO tare_jobs (container_id, status, scale_id, created_by, created_at) VALUES ($1,'await_witness',$2,$3,$4) RETURNING id", [c.id, scale.id, ctx.user.id, nowIso()]);
    await saveReadings(t, ctx, { refType: 'tare', refId: j.id, purpose: 'tare', role: 'performer', attempt: 1, scale, slots: parseSlots(b, ['tare'], '용기 무게'), containers: { tare: c.id } });
    await attachPhotos(t, ctx, photos, 'tare', j.id); await writeAudit(t, ctx, 'TARE_START', 'container', c.id, null, { job: j.id }); return j.id;
  });
}
async function reweighTare(ctx, jobId, b, files) {
  need(ctx, 'receipt.create'); const photos = await storePhotos(ctx, files, ['photo']);
  return ctx.db.tx(async (t) => {
    const j = await t.get('SELECT * FROM tare_jobs WHERE id=$1', [jobId]); if (!j || j.status !== 'reweigh') throw new AppError('재계량 대기 상태가 아닙니다.');
    const scale = await needScale(t, j.scale_id);
    await saveReadings(t, ctx, { refType: 'tare', refId: jobId, purpose: 'tare', role: 'performer', attempt: 2, scale, slots: parseSlots(b, ['tare'], '용기 무게') });
    await t.run("UPDATE tare_jobs SET status='await_witness' WHERE id=$1", [jobId]); await attachPhotos(t, ctx, photos, 'tare', jobId);
  });
}
async function witnessTare(ctx, jobId, b) {
  need(ctx, 'witness.confirm'); await auth.reauth(ctx.user, b.password);
  return ctx.db.tx(async (t) => {
    const j = await t.get('SELECT * FROM tare_jobs WHERE id=$1', [jobId]); if (!j || j.status !== 'await_witness') throw new AppError('입회 대기 상태가 아닙니다.');
    witnessGuard(j, ctx, [j.created_by], j.attempt > 1 ? j.witness_id : null);
    const s = await settings(t); const scale = await needScale(t, j.scale_id);
    const cmp = await blindCompare(t, ctx, { refType: 'tare', refId: jobId, purpose: 'tare', attempt: j.attempt, slots: parseSlots(b, ['tare'], '입회 판독'), scale, s });
    const c = await t.get('SELECT * FROM containers WHERE id=$1', [j.container_id]);
    if (cmp.result === 'reweigh') { await t.run("UPDATE tare_jobs SET status='reweigh', attempt=2, witness_id=$1 WHERE id=$2", [ctx.user.id, jobId]); return { result: 'reweigh' }; }
    if (cmp.result === 'fail') { await t.run("UPDATE tare_jobs SET status='blocked', witness_id=$1 WHERE id=$2", [ctx.user.id, jobId]); await createAnomaly(t, ctx, { type: 'WITNESS_MISMATCH', severity: 'anomaly', code_id: c.code_id, ref_type: 'container', ref_id: c.id, description: `${c.cid}: 용기 무게 입회 판독 2회 불일치`, locks: true }); return { result: 'fail' }; }
    const tare = cmp.perf.tare; const g = await t.get("SELECT value_ug FROM weighings WHERE ref_type='receipt' AND container_id=$1 AND role='performer' ORDER BY attempt DESC, id DESC LIMIT 1", [c.id]);
    const net = Number(g.value_ug) - tare; if (!(net > 0)) throw new AppError('용기 무게가 입고 총중량보다 크거나 같습니다.');
    const at = nowIso();
    await t.run("UPDATE containers SET tare_ug=$1, status='stored', updated_at=$2 WHERE id=$3", [tare, at, c.id]);
    await t.run("UPDATE tare_jobs SET status='completed', witness_id=$1, completed_at=$2 WHERE id=$3", [ctx.user.id, at, jobId]);
    await t.run('INSERT INTO ledger (container_id, code_id, type, delta_ug, ref_type, ref_id, note, by_user, at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)', [c.id, c.code_id, 'RECEIPT', net, 'tare', jobId, `${c.cid} 용기 무게 확정`, ctx.user.id, at]);
    await writeAudit(t, ctx, 'TARE_COMPLETE', 'container', c.id, { status: 'tare_pending' }, { status: 'stored', ledger: 'RECEIPT' }); return { result: 'match', net };
  });
}

// 가져온 입고: 도착·인수 일시를 관리자가 나중에 입력(비어 있을 때 1회만)
async function setReceiptTimes(ctx, id, b) {
  need(ctx, 'master.manage');
  const arrival_at = kstLocalToIso(b.arrival_at, '도착 일시'); const received_at = kstLocalToIso(b.received_at, '인수 일시');
  if (arrival_at > received_at) throw new AppError('인수 일시가 도착 일시보다 빠를 수 없습니다.');
  return ctx.db.tx(async (t) => {
    const r = await t.get('SELECT * FROM receipts WHERE id=$1', [id]); if (!r) throw new AppError('입고 건을 찾을 수 없습니다.', 404);
    if (r.arrival_at) throw new AppError('이미 일시가 입력된 건입니다.');
    await t.run("UPDATE receipts SET arrival_at=$1, received_at=$2, arrival_src='admin_entry', received_src='admin_entry' WHERE id=$3", [arrival_at, received_at, id]);
    await writeAudit(t, ctx, 'RECEIPT_TIMES_SET', 'receipt', id, { arrival_at: '' }, { arrival_at, received_at });
  });
}
// ══ 반출
async function requestCheckout(ctx, b) {
  need(ctx, 'checkout.request');
  const mode = b.mode === 'whole' ? 'whole' : 'aliquot';
  const purpose = reqTxt(b.purpose, '목적', 200); const due = String(b.due_date || ''); if (!isDay(due) || due < kstDate()) throw new AppError('반납 예정일을 오늘 이후로 입력하세요.');
  return ctx.db.tx(async (t) => {
    await permitGate(t);
    const c = await t.get('SELECT * FROM containers WHERE id=$1', [Number(b.container_id)]); if (!c || c.status !== 'stored') throw new AppError('보관 중인 용기를 선택하세요.');
    const code = await getCode(t, c.code_id); usableCode(code);
    const loc = await t.get("SELECT * FROM locations WHERE id=$1 AND active=1 AND kind='lab'", [Number(b.use_location_id)]); if (!loc || !loc.in_permit_site) throw new AppError('사용 장소는 허가 소재지 안 실험실 목록에서 고르세요.');
    const bal = await balanceOf(t, c.id); const avail = bal - (await reservedOf(t, c.id));
    const req = mode === 'whole' ? bal : toUg(b.requested, b.unit || 'g', '요청량');
    if (!(req > 0) || req > avail) throw new AppError(`요청량이 가용 재고(${fmt(avail)})를 넘습니다.`);
    const no = await nextNo(t, 'checkouts', 'CO'); const at = nowIso();
    const r = await t.get('INSERT INTO checkouts (no, code_id, container_id, mode, requester_id, requested_ug, purpose, experiment_no, due_date, use_location_id, status, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$12) RETURNING id',
      [no, code.id, c.id, mode, ctx.user.id, req, purpose, txt(b.experiment_no, 40), due, loc.id, 'requested', at]);
    await writeAudit(t, ctx, 'CHECKOUT_REQUEST', 'checkout', r.id, null, { no, code: code.code, container: c.cid, mode, requested_ug: req, due }); return r.id;
  });
}
async function decideCheckout(ctx, id, approve, note, password) {
  need(ctx, 'checkout.approve'); await auth.reauth(ctx.user, password);
  return ctx.db.tx(async (t) => {
    const k = await t.get('SELECT * FROM checkouts WHERE id=$1', [id]); if (!k || k.status !== 'requested') throw new AppError('승인 대기 상태가 아닙니다.');
    if (Number(k.requester_id) === ctx.user.id) throw new AppError('본인 요청은 승인할 수 없습니다.', 403);
    if (approve) { const code = await getCode(t, k.code_id); usableCode(code); await permitGate(t); }
    else if (!txt(note)) throw new AppError('반려 사유를 입력하세요.');
    await t.run('UPDATE checkouts SET status=$1, approver_id=$2, approved_at=$3, decision_note=$4, updated_at=$3 WHERE id=$5', [approve ? 'approved' : 'rejected', ctx.user.id, nowIso(), txt(note, 300), id]);
    await writeAudit(t, ctx, approve ? 'CHECKOUT_APPROVE' : 'CHECKOUT_REJECT', 'checkout', id, { status: 'requested' }, { status: approve ? 'approved' : 'rejected' });
  });
}
const OUT_SLOTS = { whole: ['src_gross'], aliquot: ['src_before', 'src_after', 'ali_tare', 'ali_gross'] };
async function submitOut(ctx, id, b, files) {
  need(ctx, 'checkout.perform'); const photos = await storePhotos(ctx, files, ['photo']);
  return ctx.db.tx(async (t) => {
    const k = await t.get('SELECT * FROM checkouts WHERE id=$1', [id]); if (!k || !['approved', 'out_reweigh'].includes(k.status)) throw new AppError('반출 계량 단계가 아닙니다.');
    if (k.status === 'out_reweigh' && Number(k.performer_id) !== ctx.user.id) throw new AppError('재계량은 1차 계량자가 합니다.', 403);
    await permitGate(t); const code = await getCode(t, k.code_id); usableCode(code);
    const scale = await needScale(t, k.status === 'out_reweigh' ? k.scale_id : b.scale_id); // 저울 없으면 반출 차단
    const slots = parseSlots(b, OUT_SLOTS[k.mode]);
    if (k.mode === 'aliquot' && !(slots.src_before.ug > slots.src_after.ug && slots.ali_gross.ug > slots.ali_tare.ug)) throw new AppError('분주 계량값을 확인하세요(전 > 후, 하위 용기 총중량 > 용기 무게).');
    const attempt = k.status === 'out_reweigh' ? 2 : 1;
    await saveReadings(t, ctx, { refType: 'checkout', refId: id, purpose: 'out', role: 'performer', attempt, scale, slots });
    await t.run("UPDATE checkouts SET status='out_await_witness', performer_id=$1, scale_id=$2, updated_at=$3 WHERE id=$4", [ctx.user.id, scale.id, nowIso(), id]);
    const ph = await attachPhotos(t, ctx, photos, 'checkout', id);
    await writeAudit(t, ctx, 'CHECKOUT_WEIGH', 'checkout', id, null, { attempt, photos: ph });
  });
}
async function witnessOut(ctx, id, b) {
  need(ctx, 'witness.confirm'); await auth.reauth(ctx.user, b.password);
  return ctx.db.tx(async (t) => {
    const k = await t.get('SELECT * FROM checkouts WHERE id=$1', [id]); if (!k || k.status !== 'out_await_witness') throw new AppError('반출 입회 대기 상태가 아닙니다.');
    witnessGuard(k, ctx, [k.requester_id, k.performer_id], k.step_attempt > 1 ? k.witness_id : null);
    const s = await settings(t); const scale = await needScale(t, k.scale_id);
    const cmp = await blindCompare(t, ctx, { refType: 'checkout', refId: id, purpose: 'out', attempt: k.step_attempt, slots: parseSlots(b, OUT_SLOTS[k.mode], '입회 판독'), scale, s });
    const at = nowIso();
    if (cmp.result === 'reweigh') { await t.run("UPDATE checkouts SET status='out_reweigh', step_attempt=2, witness_id=$1, updated_at=$2 WHERE id=$3", [ctx.user.id, at, id]); await writeAudit(t, ctx, 'CHECKOUT_WITNESS_MISMATCH', 'checkout', id, null, { attempt: 1 }); return { result: 'reweigh' }; }
    if (cmp.result === 'fail') { await t.run("UPDATE checkouts SET status='blocked', blocked=1, witness_id=$1, updated_at=$2 WHERE id=$3", [ctx.user.id, at, id]); await createAnomaly(t, ctx, { type: 'WITNESS_MISMATCH', severity: 'anomaly', code_id: k.code_id, ref_type: 'checkout', ref_id: id, description: `${k.no}: 반출 입회 판독 2회 불일치`, locks: true }); return { result: 'fail' }; }
    const p = cmp.perf; const src = await t.get('SELECT * FROM containers WHERE id=$1', [k.container_id]); const book = await balanceOf(t, src.id);
    // 1) 재고 대조: 반출 전 실측 순량 vs 원장
    const srcNet = (k.mode === 'whole' ? p.src_gross : p.src_before) - Number(src.tare_ug);
    const sgStock = J.sigmaD({ m: Number(s.stock_check_m), sUg: scale.repeatability_ug, dUg: scale.resolution_ug });
    const js = J.judge({ measuredUg: srcNet, expectedUg: book, sigmaUg: sgStock, opts: s });
    if (js.result === 'anomaly') {
      await t.run("UPDATE checkouts SET status='blocked', blocked=1, witness_id=$1, updated_at=$2 WHERE id=$3", [ctx.user.id, at, id]);
      await t.run("UPDATE containers SET status='quarantine', updated_at=$1 WHERE id=$2", [at, src.id]);
      await createAnomaly(t, ctx, { type: 'STOCK_MISMATCH', severity: 'anomaly', code_id: k.code_id, ref_type: 'checkout', ref_id: id, diff_ug: js.diffUg, description: `${src.cid}: 반출 전 실측 순량이 원장과 다름(${js.reason})`, locks: true, adjust_container_id: src.id, adjust_to_ug: srcNet });
      return { result: 'stock_anomaly', judgment: js };
    }
    let outUg, deduct, aliquotId = null;
    if (k.mode === 'whole') { outUg = srcNet; deduct = book; }
    else {
      const dec = p.src_before - p.src_after; const aliNet = p.ali_gross - p.ali_tare;
      const ja = J.judge({ measuredUg: aliNet, expectedUg: dec, sigmaUg: J.sigmaD({ m: 4, sUg: scale.repeatability_ug, dUg: scale.resolution_ug }), opts: s });
      if (ja.result === 'anomaly') {
        await t.run("UPDATE checkouts SET status='blocked', blocked=1, witness_id=$1, updated_at=$2 WHERE id=$3", [ctx.user.id, at, id]);
        await createAnomaly(t, ctx, { type: 'ALIQUOT_MISMATCH', severity: 'anomaly', code_id: k.code_id, ref_type: 'checkout', ref_id: id, diff_ug: ja.diffUg, description: `${k.no}: 상위 용기 감소량과 하위 용기 순량 차이(${ja.reason})`, locks: true });
        return { result: 'aliquot_anomaly', judgment: ja };
      }
      outUg = aliNet; deduct = dec;
      const n = Number((await t.get('SELECT COUNT(*) AS n FROM containers WHERE parent_id=$1', [src.id])).n) + 1;
      const ali = await t.get('INSERT INTO containers (cid, code_id, lot_id, parent_id, tare_ug, location_id, status, holder_id, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$9) RETURNING id', [`${src.cid}-A${n}`, src.code_id, src.lot_id, src.id, p.ali_tare, src.location_id, 'out', k.requester_id, at]);
      aliquotId = ali.id;
    }
    await t.run('INSERT INTO ledger (container_id, code_id, type, delta_ug, ref_type, ref_id, note, by_user, at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)', [src.id, k.code_id, 'OUT', -deduct, 'checkout', id, k.no, ctx.user.id, at]);
    if (k.mode === 'whole') await t.run("UPDATE containers SET status='out', holder_id=$1, updated_at=$2 WHERE id=$3", [k.requester_id, at, src.id]);
    await t.run("UPDATE checkouts SET status='out', out_ug=$1, aliquot_id=$2, witness_id=$3, out_at=$4, step_attempt=1, updated_at=$4 WHERE id=$5", [outUg, aliquotId, ctx.user.id, at, id]);
    await writeAudit(t, ctx, 'CHECKOUT_COMPLETE', 'checkout', id, { status: 'out_await_witness' }, { status: 'out', out_ug: outUg, ledger_out_ug: -deduct });
    return { result: 'match', outUg };
  });
}
// ══ 사용(계량 + 입회). 원장에 넣지 않음.
async function logUsage(ctx, checkoutId, b, files) {
  need(ctx, 'usage.log'); const photos = await storePhotos(ctx, files, ['photo']);
  const used_on = String(b.used_on || kstDate()); if (!isDay(used_on) || used_on > kstDate()) throw new AppError('사용일을 확인하세요.');
  const summary = reqTxt(b.research_summary, '연구내용 요약', 300);
  return ctx.db.tx(async (t) => {
    await permitGate(t);
    const k = await t.get('SELECT * FROM checkouts WHERE id=$1', [checkoutId]); if (!k || k.status !== 'out') throw new AppError('반출 중인 건이 아닙니다.');
    if (Number(k.requester_id) !== ctx.user.id) throw new AppError('본인 반출 건만 사용 기록을 남길 수 있습니다.', 403);
    const pend = await t.get("SELECT id FROM usage_logs WHERE checkout_id=$1 AND status IN ('await_witness','reweigh')", [checkoutId]); if (pend) throw new AppError('입회 대기 중인 사용 기록이 있습니다.');
    const scale = await needScale(t, b.scale_id); const slots = parseSlots(b, ['before', 'after'], '사용 전·후 총중량');
    if (!(slots.before.ug > slots.after.ug)) throw new AppError('사용 전 총중량이 사용 후보다 커야 합니다.');
    const r = await t.get("INSERT INTO usage_logs (checkout_id, status, scale_id, used_on, experiment_no, research_summary, legal_row_no, by_user, at) VALUES ($1,'await_witness',$2,$3,$4,$5,$6,$7,$8) RETURNING id",
      [checkoutId, scale.id, used_on, txt(b.experiment_no, 40) || k.experiment_no, summary, txt(b.legal_row_no, 40), ctx.user.id, nowIso()]);
    await saveReadings(t, ctx, { refType: 'usage', refId: r.id, purpose: 'usage', role: 'performer', attempt: 1, scale, slots });
    await attachPhotos(t, ctx, photos, 'usage', r.id); await writeAudit(t, ctx, 'USAGE_WEIGH', 'usage', r.id, null, { checkout: k.no, used_on }); return r.id;
  });
}
async function reweighUsage(ctx, id, b, files) {
  need(ctx, 'usage.log'); const photos = await storePhotos(ctx, files, ['photo']);
  return ctx.db.tx(async (t) => {
    const u = await t.get('SELECT * FROM usage_logs WHERE id=$1', [id]); if (!u || u.status !== 'reweigh' || Number(u.by_user) !== ctx.user.id) throw new AppError('재계량 대기 상태가 아닙니다.');
    const scale = await needScale(t, u.scale_id);
    await saveReadings(t, ctx, { refType: 'usage', refId: id, purpose: 'usage', role: 'performer', attempt: 2, scale, slots: parseSlots(b, ['before', 'after'], '사용 전·후 총중량') });
    await t.run("UPDATE usage_logs SET status='await_witness' WHERE id=$1", [id]); await attachPhotos(t, ctx, photos, 'usage', id);
  });
}
async function witnessUsage(ctx, id, b) {
  need(ctx, 'witness.confirm'); await auth.reauth(ctx.user, b.password);
  return ctx.db.tx(async (t) => {
    const u = await t.get('SELECT * FROM usage_logs WHERE id=$1', [id]); if (!u || u.status !== 'await_witness') throw new AppError('입회 대기 상태가 아닙니다.');
    const k = await t.get('SELECT * FROM checkouts WHERE id=$1', [u.checkout_id]);
    witnessGuard(u, ctx, [u.by_user, k.requester_id], u.attempt > 1 ? u.witness_id : null);
    const s = await settings(t); const scale = await needScale(t, u.scale_id);
    const cmp = await blindCompare(t, ctx, { refType: 'usage', refId: id, purpose: 'usage', attempt: u.attempt, slots: parseSlots(b, ['before', 'after'], '입회 판독'), scale, s });
    if (cmp.result === 'reweigh') { await t.run("UPDATE usage_logs SET status='reweigh', attempt=2, witness_id=$1 WHERE id=$2", [ctx.user.id, id]); return { result: 'reweigh' }; }
    if (cmp.result === 'fail') { await t.run("UPDATE usage_logs SET status='blocked', witness_id=$1 WHERE id=$2", [ctx.user.id, id]); await createAnomaly(t, ctx, { type: 'WITNESS_MISMATCH', severity: 'anomaly', code_id: k.code_id, ref_type: 'checkout', ref_id: k.id, description: `${k.no}: 사용 입회 판독 2회 불일치`, locks: true }); return { result: 'fail' }; }
    const amount = cmp.perf.before - cmp.perf.after;
    await t.run("UPDATE usage_logs SET status='confirmed', amount_ug=$1, witness_id=$2, confirmed_at=$3 WHERE id=$4", [amount, ctx.user.id, nowIso(), id]);
    await writeAudit(t, ctx, 'USAGE_CONFIRM', 'usage', id, null, { checkout: k.no, amount_ug: amount }); return { result: 'match', amount };
  });
}
// ══ 반납: 실측 → (값 가림) → 블라인드 입회 → 판정
const returnContainer = async (t, k) => t.get('SELECT * FROM containers WHERE id=$1', [k.mode === 'whole' ? k.container_id : k.aliquot_id]);
async function submitReturn(ctx, id, b, files) {
  need(ctx, 'return.submit'); const photos = await storePhotos(ctx, files, ['photo']);
  return ctx.db.tx(async (t) => {
    const k = await t.get('SELECT * FROM checkouts WHERE id=$1', [id]); if (!k || !['out', 'return_hold', 'return_reweigh'].includes(k.status)) throw new AppError('반납할 수 있는 상태가 아닙니다.');
    if (k.status !== 'return_reweigh' && Number(k.requester_id) !== ctx.user.id && !can(ctx.user, 'receipt.create', 'field')) throw new AppError('요청자 또는 보관담당만 반납을 등록할 수 있습니다.', 403);
    if (k.status === 'return_reweigh' && Number(k.return_submitter_id) !== ctx.user.id) throw new AppError('재계량은 1차 계량자가 합니다.', 403);
    const pend = await t.get("SELECT id FROM usage_logs WHERE checkout_id=$1 AND status IN ('await_witness','reweigh')", [id]); if (pend) throw new AppError('입회 대기 중인 사용 기록을 먼저 끝내세요.');
    const s = await settings(t); const c = await returnContainer(t, k); const at = nowIso();
    const sc = await usableScale(t, k.status === 'return_reweigh' ? k.return_scale_id : b.scale_id);
    if (!sc.ok) {
      if (s.no_scale_policy !== 'hold' || k.status !== 'out') throw new AppError(sc.why, 409);
      const seal = reqTxt(b.seal_no, '봉인 번호', 40); // 계량 보류: 봉인·격리, 추정값 입력 금지
      await t.run("UPDATE checkouts SET status='return_hold', return_seal_no=$1, return_submitter_id=$2, updated_at=$3 WHERE id=$4", [seal, ctx.user.id, at, id]);
      await t.run("UPDATE containers SET status='weigh_hold', holder_id=NULL, updated_at=$1 WHERE id=$2", [at, c.id]);
      await attachPhotos(t, ctx, photos, 'checkout', id); await writeAudit(t, ctx, 'RETURN_HOLD', 'checkout', id, { status: k.status }, { status: 'return_hold', seal_no: seal, why: sc.why });
      return { hold: true };
    }
    const attempt = k.status === 'return_reweigh' ? 2 : 1;
    await saveReadings(t, ctx, { refType: 'checkout', refId: id, purpose: 'return', role: 'performer', attempt, scale: sc.scale, slots: parseSlots(b, ['ret_gross'], '반납 총중량'), containers: { ret_gross: c.id } });
    await t.run("UPDATE checkouts SET status='return_await_witness', step_attempt=$1, return_submitter_id=$2, return_scale_id=$3, return_reason=$4, updated_at=$5 WHERE id=$6", [attempt, ctx.user.id, sc.scale.id, txt(b.reason, 300) || null, at, id]);
    await t.run("UPDATE containers SET status='quarantine', holder_id=NULL, updated_at=$1 WHERE id=$2", [at, c.id]);
    const ph = await attachPhotos(t, ctx, photos, 'checkout', id); await writeAudit(t, ctx, 'RETURN_WEIGH', 'checkout', id, { status: k.status }, { status: 'return_await_witness', attempt, photos: ph });
  });
}
async function witnessReturn(ctx, id, b) {
  need(ctx, 'witness.confirm'); await auth.reauth(ctx.user, b.password);
  const seal_ok = b.seal_ok !== '0';
  return ctx.db.tx(async (t) => {
    const k = await t.get('SELECT * FROM checkouts WHERE id=$1', [id]); if (!k || k.status !== 'return_await_witness') throw new AppError('반납 입회 대기 상태가 아닙니다.');
    witnessGuard(k, ctx, [k.requester_id, k.return_submitter_id], k.step_attempt > 1 ? k.return_witness_id : null);
    const s = await settings(t); const scale = await needScale(t, k.return_scale_id); const at = nowIso();
    const cmp = await blindCompare(t, ctx, { refType: 'checkout', refId: id, purpose: 'return', attempt: k.step_attempt, slots: parseSlots(b, ['ret_gross'], '입회 판독'), scale, s });
    if (cmp.result === 'reweigh') { await t.run("UPDATE checkouts SET status='return_reweigh', return_witness_id=$1, updated_at=$2 WHERE id=$3", [ctx.user.id, at, id]); await writeAudit(t, ctx, 'RETURN_WITNESS_MISMATCH', 'checkout', id, null, { attempt: 1 }); return { result: 'reweigh' }; }
    if (cmp.result === 'fail') { await t.run("UPDATE checkouts SET status='blocked', blocked=1, return_witness_id=$1, updated_at=$2 WHERE id=$3", [ctx.user.id, at, id]); await createAnomaly(t, ctx, { type: 'WITNESS_MISMATCH', severity: 'anomaly', code_id: k.code_id, ref_type: 'checkout', ref_id: id, description: `${k.no}: 반납 입회 판독 2회 불일치`, locks: true }); return { result: 'fail' }; }
    // 판정(입회 일치 뒤에만 계산·표시)
    const c = await returnContainer(t, k); const measured = cmp.perf.ret_gross - Number(c.tare_ug);
    const uses = await t.all("SELECT amount_ug FROM usage_logs WHERE checkout_id=$1 AND status='confirmed'", [id]);
    const used = uses.reduce((a, u) => a + Number(u.amount_ug), 0); const expected = J.expectedReturn({ outUg: k.out_ug, usedUg: used });
    const outScale = await t.get('SELECT * FROM scales WHERE id=$1', [k.scale_id]);
    const m = 2 + 2 * uses.length + 2; const sAll = Math.max(Number(scale.repeatability_ug), Number(outScale ? outScale.repeatability_ug : 0)); // 다른 저울이면 큰 s로 보수 계산
    const sg = J.sigmaD({ m, sUg: sAll, dUg: Math.max(Number(scale.resolution_ug), Number(outScale ? outScale.resolution_ug : 0)) });
    const jd = J.judge({ measuredUg: measured, expectedUg: expected, sigmaUg: sg, baseUg: k.out_ug, opts: s });
    if (!seal_ok) { jd.result = 'anomaly'; jd.kind = 'seal'; jd.reason = '봉인 훼손'; jd.immediateLock = true; }
    // 누락 측 이상: 1차면 같은 입회자로 1회 재계량
    if (jd.result === 'anomaly' && jd.kind === 'loss' && k.step_attempt < 2) {
      await t.run("UPDATE checkouts SET status='return_reweigh', return_witness_id=$1, updated_at=$2 WHERE id=$3", [ctx.user.id, at, id]);
      await writeAudit(t, ctx, 'RETURN_RECHECK', 'checkout', id, null, { attempt: 1, reason: 'loss_recheck' }); return { result: 'reweigh', judgment: jd };
    }
    await t.run('INSERT INTO ledger (container_id, code_id, type, delta_ug, ref_type, ref_id, note, by_user, at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)', [c.id, k.code_id, 'RETURN', measured, 'checkout', id, k.no, ctx.user.id, at]);
    await t.run("UPDATE checkouts SET status='returned', return_witness_id=$1, measured_ug=$2, expected_ug=$3, used_ug=$4, diff_ug=$5, sigma_ug=$6, judgment=$7, judgment_reason=$8, returned_at=$9, updated_at=$9 WHERE id=$10",
      [ctx.user.id, measured, expected, used, jd.diffUg, jd.sigmaUg, jd.result, jd.reason, at, id]);
    await t.run('UPDATE containers SET status=$1, updated_at=$2 WHERE id=$3', [jd.result === 'anomaly' ? 'quarantine' : 'stored', at, c.id]);
    await writeAudit(t, ctx, 'RETURN_COMPLETE', 'checkout', id, { status: 'return_await_witness' }, { status: 'returned', judgment: jd.result, measured_ug: measured, expected_ug: expected, diff_ug: jd.diffUg, sigma_ug: jd.sigmaUg });
    if (jd.result === 'anomaly') await createAnomaly(t, ctx, { type: jd.kind === 'increase' ? 'RETURN_INCREASE' : jd.kind === 'seal' ? 'SEAL_BROKEN' : jd.kind === 'inconsistent' ? 'INCONSISTENT' : 'RETURN_LOSS', severity: 'anomaly', code_id: k.code_id, ref_type: 'checkout', ref_id: id, diff_ug: jd.diffUg, description: `${k.no}: 반납 판정 이상 — ${jd.reason}`, locks: true });
    else if (jd.result === 'warning') await createAnomaly(t, ctx, { type: 'RETURN_WARNING', severity: 'warning', code_id: k.code_id, ref_type: 'checkout', ref_id: id, diff_ug: jd.diffUg, description: `${k.no}: 반납 판정 경고 — ${jd.reason}. 요청자 사유 확인 필요` });
    return { result: 'match', judgment: jd };
  });
}

// ══ 폐기(법무 3-A) — P1 현장 2인 계량·격리, P2~P5 관리 앱 기록
async function createDisposal(ctx, b, files) {
  need(ctx, 'disposal.create'); const photos = await storePhotos(ctx, files, ['photo']);
  const reason_code = String(b.reason_code || ''); if (!DISPOSAL_REASONS[reason_code]) throw new AppError('폐기 사유는 세 가지 중에서 고르세요.');
  return ctx.db.tx(async (t) => {
    const c = await t.get('SELECT * FROM containers WHERE id=$1', [Number(b.container_id)]); if (!c || !['stored', 'quarantine'].includes(c.status)) throw new AppError('보관·격리 중인 용기를 선택하세요.');
    const open = await t.get("SELECT id FROM disposals WHERE container_id=$1 AND status NOT IN ('completed','cancelled')", [c.id]); if (open) throw new AppError('이미 폐기 진행 중인 용기입니다.');
    const q = await t.get("SELECT * FROM locations WHERE id=$1 AND active=1 AND kind IN ('quarantine','vault')", [Number(b.quarantine_location_id)]); if (!q) throw new AppError('격리 칸을 선택하세요.');
    const scale = await needScale(t, b.scale_id); const no = await nextNo(t, 'disposals', 'DSP'); const at = nowIso();
    const r = await t.get("INSERT INTO disposals (no, container_id, code_id, reason_code, reason, status, created_by, scale_id, quarantine_location_id, seal_no, created_at) VALUES ($1,$2,$3,$4,$5,'await_witness',$6,$7,$8,$9,$10) RETURNING id",
      [no, c.id, c.code_id, reason_code, txt(b.reason, 300), ctx.user.id, scale.id, q.id, reqTxt(b.seal_no, '봉인 번호', 40), at]);
    await saveReadings(t, ctx, { refType: 'disposal', refId: r.id, purpose: 'disposal', role: 'performer', attempt: 1, scale, slots: parseSlots(b, ['gross'], '총중량'), containers: { gross: c.id } });
    await attachPhotos(t, ctx, photos, 'disposal', r.id); await writeAudit(t, ctx, 'DISPOSAL_P0', 'disposal', r.id, null, { no, container: c.cid, reason_code });
    if (reason_code === 'damaged') { const inc = await createIncident(t, ctx, { disposal_id: r.id, code_id: c.code_id }); await t.run('UPDATE disposals SET incident_id=$1 WHERE id=$2', [inc, r.id]); } // 변질·부패·파손 = 사고 보고 대상
    return r.id;
  });
}
async function reweighDisposal(ctx, id, b, files) {
  need(ctx, 'disposal.create'); const photos = await storePhotos(ctx, files, ['photo']);
  return ctx.db.tx(async (t) => {
    const d = await t.get('SELECT * FROM disposals WHERE id=$1', [id]); if (!d || d.status !== 'reweigh') throw new AppError('재계량 대기 상태가 아닙니다.');
    const scale = await needScale(t, d.scale_id);
    await saveReadings(t, ctx, { refType: 'disposal', refId: id, purpose: 'disposal', role: 'performer', attempt: 2, scale, slots: parseSlots(b, ['gross'], '총중량') });
    await t.run("UPDATE disposals SET status='await_witness' WHERE id=$1", [id]); await attachPhotos(t, ctx, photos, 'disposal', id);
  });
}
async function witnessDisposal(ctx, id, b) {
  need(ctx, 'witness.confirm'); await auth.reauth(ctx.user, b.password);
  return ctx.db.tx(async (t) => {
    const d = await t.get('SELECT * FROM disposals WHERE id=$1', [id]); if (!d || d.status !== 'await_witness') throw new AppError('입회 대기 상태가 아닙니다.');
    witnessGuard(d, ctx, [d.created_by], d.attempt > 1 ? d.witness_id : null);
    const s = await settings(t); const scale = await needScale(t, d.scale_id); const at = nowIso();
    const cmp = await blindCompare(t, ctx, { refType: 'disposal', refId: id, purpose: 'disposal', attempt: d.attempt, slots: parseSlots(b, ['gross'], '입회 판독'), scale, s });
    if (cmp.result === 'reweigh') { await t.run("UPDATE disposals SET status='reweigh', attempt=2, witness_id=$1 WHERE id=$2", [ctx.user.id, id]); return { result: 'reweigh' }; }
    if (cmp.result === 'fail') { await t.run("UPDATE disposals SET status='blocked', witness_id=$1 WHERE id=$2", [ctx.user.id, id]); await createAnomaly(t, ctx, { type: 'WITNESS_MISMATCH', severity: 'anomaly', code_id: d.code_id, ref_type: 'disposal', ref_id: id, description: `${d.no}: 폐기 계량 입회 판독 2회 불일치`, locks: true }); return { result: 'fail' }; }
    const c = await t.get('SELECT * FROM containers WHERE id=$1', [d.container_id]); const net = cmp.perf.gross - Number(c.tare_ug); const book = await balanceOf(t, c.id);
    await t.run("UPDATE disposals SET status='pending_application', amount_ug=$1, witness_id=$2, weighed_at=$3 WHERE id=$4", [net, ctx.user.id, at, id]);
    await t.run("UPDATE containers SET status='quarantine', location_id=$1, updated_at=$2 WHERE id=$3", [d.quarantine_location_id, at, c.id]); // P1: 재고에서 빼지 않음, 반출 잠금(격리)
    await writeAudit(t, ctx, 'DISPOSAL_P1', 'disposal', id, { status: 'await_witness' }, { status: 'pending_application', amount_ug: net });
    const js = J.judge({ measuredUg: net, expectedUg: book, sigmaUg: J.sigmaD({ m: Number(s.stock_check_m), sUg: scale.repeatability_ug, dUg: scale.resolution_ug }), opts: s });
    if (js.result === 'anomaly') await createAnomaly(t, ctx, { type: 'STOCK_MISMATCH', severity: 'anomaly', code_id: d.code_id, ref_type: 'disposal', ref_id: id, diff_ug: js.diffUg, description: `${c.cid}: 폐기 대기 계량이 원장과 다름(${js.reason})`, locks: true, adjust_container_id: c.id, adjust_to_ug: net });
    return { result: 'match' };
  });
}
async function disposalStep(ctx, id, step, b) {
  need(ctx, 'disposal.manage'); await auth.reauth(ctx.user, b.password);
  return ctx.db.tx(async (t) => {
    const d = await t.get('SELECT * FROM disposals WHERE id=$1', [id]); if (!d) throw new AppError('폐기 건을 찾을 수 없습니다.', 404); const at = nowIso();
    if (step === 'apply') {
      if (d.status !== 'pending_application') throw new AppError('신청 준비 단계가 아닙니다.');
      if (!isDay(b.applied_on)) throw new AppError('제출일을 입력하세요.');
      await t.run("UPDATE disposals SET status='applied', applicant=$1, authority=$2, applied_on=$3, application_no=$4, application_doc_sha=$5, applied_by=$6 WHERE id=$7", [reqTxt(b.applicant, '신청인(허가 명의자)', 40), reqTxt(b.authority, '제출 기관(허가관청)', 60), b.applied_on, reqTxt(b.application_no, '접수번호', 60), txt(b.doc_sha, 64) || null, ctx.user.id, id]);
    } else if (step === 'observe') {
      if (d.status !== 'applied') throw new AppError('관청 신청 뒤에 참관 기록을 남깁니다.');
      if (!isDay(b.observed_on)) throw new AppError('참관 일자를 입력하세요.');
      const w = await t.all('SELECT id, username FROM users WHERE username IN ($1,$2) AND active=1', [String(b.witness1 || '').toLowerCase(), String(b.witness2 || '').toLowerCase()]);
      if (w.length !== 2) throw new AppError('사내 입회자 2명(서로 다른 계정)을 입력하세요.');
      if (w.some((x) => x.id === ctx.user.id || x.id === Number(d.applied_by))) throw new AppError('기록자·신청 기록자와 다른 사람이 입회해야 합니다.');
      const c = await t.get('SELECT * FROM containers WHERE id=$1', [d.container_id]);
      const handover = toUg(b.handover_gross, b.unit || 'g', '인계 총중량') - Number(c.tare_ug);
      await t.run("UPDATE disposals SET status='observed', observed_on=$1, official_affiliation=$2, handover_ug=$3, observe_witness1_id=$4, observe_witness2_id=$5, observed_by=$6 WHERE id=$7", [b.observed_on, reqTxt(b.official_affiliation, '참관 공무원 소속', 60), handover, w[0].id, w[1].id, ctx.user.id, id]);
    } else if (step === 'result') {
      if (d.status !== 'observed') throw new AppError('참관 기록 뒤에 결과 공문을 기록합니다.');
      if (!isDay(b.result_on)) throw new AppError('결과 공문 시행일을 입력하세요.');
      const bal = await balanceOf(t, d.container_id);
      await t.run("UPDATE disposals SET status='completed', result_doc_no=$1, result_on=$2, result_doc_sha=$3, result_by=$4, completed_at=$5, legal_row_no=$6 WHERE id=$7", [reqTxt(b.result_doc_no, '결과 공문 번호', 60), b.result_on, txt(b.doc_sha, 64) || null, ctx.user.id, at, txt(b.legal_row_no, 40), id]);
      if (d.stock_deduct) await t.run('INSERT INTO ledger (container_id, code_id, type, delta_ug, ref_type, ref_id, note, by_user, at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)', [d.container_id, d.code_id, 'DISPOSE', -bal, 'disposal', id, d.no, ctx.user.id, at]);
      await t.run("UPDATE containers SET status='disposed', updated_at=$1 WHERE id=$2", [at, d.container_id]);
    } else throw new AppError('잘못된 단계');
    await writeAudit(t, ctx, `DISPOSAL_${step.toUpperCase()}`, 'disposal', id, { status: d.status }, { step });
  });
}

// ══ 이상 징후: 2인 종결(1차 확인 → 다른 사람 최종). 종결 시 원장 조정·잠금 해제. 사고 보고 트랙과는 별개.
async function resolveAnomaly(ctx, id, b) {
  need(ctx, 'anomaly.manage'); await auth.reauth(ctx.user, b.password); const note = reqTxt(b.note, '조사·조치 내용', 1000);
  return ctx.db.tx(async (t) => {
    const a = await t.get('SELECT * FROM anomalies WHERE id=$1', [id]); if (!a || a.status === 'resolved') throw new AppError('처리할 수 없는 상태입니다.');
    const at = nowIso();
    await t.run('INSERT INTO anomaly_actions (anomaly_id, user_id, action, note, at) VALUES ($1,$2,$3,$4,$5)', [id, ctx.user.id, a.resolve_first_by ? 'final' : 'first', note, at]);
    const twoPerson = a.severity === 'anomaly' || a.locks_code;
    if (twoPerson && !a.resolve_first_by) {
      await t.run("UPDATE anomalies SET status='investigating', resolve_first_by=$1, resolve_first_at=$2, resolve_first_note=$3 WHERE id=$4", [ctx.user.id, at, note, id]);
      await writeAudit(t, ctx, 'ANOMALY_FIRST_SIGN', 'anomaly', id, { status: a.status }, { status: 'investigating' }); return { stage: 'first' };
    }
    if (twoPerson && Number(a.resolve_first_by) === ctx.user.id) throw new AppError('1차 확인자와 다른 관리책임자가 최종 종결해야 합니다(2인).', 403);
    if (a.adjust_container_id) {
      const bal = await balanceOf(t, a.adjust_container_id); const delta = Number(a.adjust_to_ug) - bal;
      if (delta) await t.run('INSERT INTO ledger (container_id, code_id, type, delta_ug, ref_type, ref_id, note, by_user, at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)', [a.adjust_container_id, a.code_id, 'ADJUST', delta, 'anomaly', id, `${a.no} 2인 종결`, ctx.user.id, at]);
    }
    await t.run("UPDATE anomalies SET status='resolved', resolved_by=$1, resolved_at=$2, resolution=$3 WHERE id=$4", [ctx.user.id, at, note, id]);
    // 관련 격리 용기 복귀
    if (a.ref_type === 'checkout') { const k = await t.get('SELECT * FROM checkouts WHERE id=$1', [a.ref_id]); if (k) { const cid = a.adjust_container_id || (k.mode === 'whole' ? k.container_id : k.aliquot_id); if (cid) await t.run("UPDATE containers SET status='stored', updated_at=$1 WHERE id=$2 AND status='quarantine'", [at, cid]); } }
    if (a.adjust_container_id) await t.run("UPDATE containers SET status='stored', updated_at=$1 WHERE id=$2 AND status='quarantine'", [at, a.adjust_container_id]);
    if (a.code_id) { const other = await t.get("SELECT id FROM anomalies WHERE code_id=$1 AND locks_code=1 AND status<>'resolved'", [a.code_id]); if (!other) { await t.run('UPDATE item_codes SET locked=0, updated_at=$1 WHERE id=$2', [at, a.code_id]); await writeAudit(t, ctx, 'CODE_UNLOCK', 'item_code', a.code_id, { locked: true }, { locked: false }); } }
    await writeAudit(t, ctx, 'ANOMALY_RESOLVE', 'anomaly', id, { status: a.status }, { status: 'resolved', adjusted: !!a.adjust_container_id });
    return { stage: 'final' };
  });
}
async function reportAnomaly(ctx, b) {
  if (!can(ctx.user, 'inventory.view', ctx.app) && !can(ctx.user, 'anomaly.manage', ctx.app)) throw new AppError('권한이 없습니다.', 403); const desc = reqTxt(b.description, '내용', 500);
  return ctx.db.tx(async (t) => createAnomaly(t, ctx, { type: 'MANUAL', severity: b.severity === 'anomaly' ? 'anomaly' : 'warning', code_id: b.code_id ? Number(b.code_id) : null, description: desc, locks: b.severity === 'anomaly' && !!b.code_id }));
}
// ══ 사고 보고 트랙
async function incidentStep(ctx, id, step, b) {
  need(ctx, 'incident.manage'); await auth.reauth(ctx.user, b.password);
  return ctx.db.tx(async (t) => {
    const i = await t.get('SELECT * FROM incidents WHERE id=$1', [id]); if (!i) throw new AppError('사고 건을 찾을 수 없습니다.', 404); const at = nowIso();
    if (step === 'determine') {
      if (i.status !== 'awaiting_determination') throw new AppError('이미 판정했습니다.');
      const d = String(b.determination || ''); if (!['weigh_error', 'reportable', 'unknown'].includes(d)) throw new AppError('판정을 고르세요.');
      const st = d === 'weigh_error' ? 'not_reportable' : 'report_pending'; // 원인 불명 = 보고 대상(보수적)
      await t.run('UPDATE incidents SET determination=$1, determination_note=$2, determined_by=$3, determined_at=$4, status=$5 WHERE id=$6', [d, reqTxt(b.note, '판정 근거', 500), ctx.user.id, at, st, id]);
    } else if (step === 'evidence') {
      await t.run('UPDATE incidents SET evidence_kind=$1, evidence_no=$2 WHERE id=$3', [reqTxt(b.evidence_kind, '증명서류 종류', 40), reqTxt(b.evidence_no, '접수·발급 번호', 60), id]);
    } else if (step === 'report') {
      if (i.status !== 'report_pending') throw new AppError('보고 준비 상태가 아닙니다.');
      const rep = kstLocalToIso(b.reported_at, '제출 일시');
      await t.run("UPDATE incidents SET status='reported', report_authority=$1, reported_at=$2, report_receipt_no=$3, report_doc_sha=$4, reported_by=$5, legal_row_no=$6 WHERE id=$7", [reqTxt(b.report_authority, '제출 기관(허가관청)', 60), rep, reqTxt(b.report_receipt_no, '접수번호', 60), txt(b.doc_sha, 64) || null, ctx.user.id, txt(b.legal_row_no, 40), id]);
    } else throw new AppError('잘못된 단계');
    await writeAudit(t, ctx, `INCIDENT_${step.toUpperCase()}`, 'incident', id, { status: i.status }, { step });
  });
}
async function openIncidentManual(ctx, b) {
  need(ctx, 'incident.manage'); const discovered = b.discovered_at ? kstLocalToIso(b.discovered_at, '발견 일시') : null;
  return ctx.db.tx(async (t) => createIncident(t, ctx, { code_id: b.code_id ? Number(b.code_id) : null, aware_at: discovered }));
}
// 카운트다운: 인지일 = D+1(초일 포함 설정 시)
function incidentClock(i, nowMs = Date.now()) {
  const dayIdx = Math.floor((Date.parse(`${kstDate(new Date(nowMs).toISOString())}T00:00:00+09:00`) - Date.parse(`${kstDate(i.aware_at)}T00:00:00+09:00`)) / 86400000) + 1;
  const left = Date.parse(i.report_due) - nowMs; const detLeft = Date.parse(i.determine_due) - nowMs;
  const open = i.status === 'awaiting_determination' || i.status === 'report_pending';
  let level = 'info';
  if (open && left < 0) level = 'overdue'; else if (open && dayIdx >= 4) level = 'err'; else if (open && dayIdx >= 3) level = 'warn';
  return { dayIdx, hoursLeft: Math.floor(left / 3600000), determineOverdue: i.status === 'awaiting_determination' && detLeft < 0, level, open };
}

// ══ 반납 지연 점검 + 알림 목록
async function sweep(db) {
  const today = kstDate();
  const rows = await db.all("SELECT * FROM checkouts c WHERE c.status='out' AND c.due_date < $1 AND NOT EXISTS (SELECT 1 FROM anomalies a WHERE a.type='OVERDUE' AND a.ref_type='checkout' AND a.ref_id=c.id)", [today]);
  for (const k of rows) await db.tx((t) => createAnomaly(t, { app: 'system' }, { type: 'OVERDUE', severity: 'warning', code_id: k.code_id, ref_type: 'checkout', ref_id: k.id, description: `${k.no}: 반납 기한 ${k.due_date} 경과` }));
}
async function alerts(db, { forBoard = false } = {}) {
  await sweep(db); const today = kstDate(); const s = await settings(db); const out = [];
  const an = await db.all("SELECT a.*, i.code FROM anomalies a LEFT JOIN item_codes i ON i.id=a.code_id WHERE a.status<>'resolved' ORDER BY a.id DESC");
  for (const a of an) out.push({ level: a.severity === 'anomaly' ? 'err' : 'warn', kind: a.type === 'OVERDUE' ? '반납 지연' : '이상 징후', text: `${a.no} ${AN_TYPES[a.type] || a.type}${a.code ? ' · ' + a.code : ''}${a.locks_code ? ' · 코드 잠김' : ''}${a.resolve_first_by ? ' · 1차 확인됨(최종 대기)' : ''}`, link: `/anomalies/${a.id}` });
  for (const i of await db.all("SELECT * FROM incidents WHERE status IN ('awaiting_determination','report_pending') ORDER BY id")) {
    const c = incidentClock(i); out.push({ level: c.level === 'overdue' ? 'err' : c.level, kind: '사고 보고', text: `${i.no} ${INC_STATUS[i.status]} · D+${c.dayIdx} · 보고 기한까지 ${c.hoursLeft}시간${c.determineOverdue ? ' · 1차 판정 기한 경과' : ''}`, link: `/incidents/${i.id}` });
  }
  for (const sc of await db.all('SELECT * FROM scales WHERE active=1')) {
    if (!sc.calib_due || sc.calib_due < today) out.push({ level: 'err', kind: '저울', text: `${sc.scale_id} 교정 기한 경과·미등록 — 사용 차단`, link: '/scales' });
    else if (sc.calib_due <= addDays(today, 7)) out.push({ level: 'warn', kind: '저울', text: `${sc.scale_id} 교정 기한 ${sc.calib_due}`, link: '/scales' });
    if (!(Number(sc.repeatability_ug) > 0)) out.push({ level: 'err', kind: '저울', text: `${sc.scale_id} 반복성(s) 미등록 — 판정 불가`, link: '/scales' });
  }
  const dlim = addDays(today, -Number(s.disposal_apply_alert_days));
  for (const d of await db.all("SELECT * FROM disposals WHERE status='pending_application'")) if (kstDate(d.weighed_at) <= dlim) out.push({ level: 'warn', kind: '폐기 신청', text: `${d.no} 관청 신청 대기 ${s.disposal_apply_alert_days}일 경과`, link: `/disposals/${d.id}` });
  const n = (q) => db.get(q).then((r) => Number(r.n));
  const hold = await n("SELECT COUNT(*) AS n FROM checkouts WHERE status='return_hold'"); if (hold) out.push({ level: 'warn', kind: '계량 보류', text: `계량 보류(봉인·격리) ${hold}건 — 재계량 필요`, link: '/checkouts' });
  const wp = await n("SELECT COUNT(*) AS n FROM containers WHERE status='weigh_pending'"); if (wp) out.push({ level: 'warn', kind: '무게 미확정', text: `무게 미확정(개수만·묶음 확인 필요) ${wp}개 — 원장 미반영`, link: '/inventory' });
  const na = await n("SELECT COUNT(*) AS n FROM receipts WHERE status IN ('imported','imported_check') AND arrival_at=''"); if (na) out.push({ level: 'warn', kind: '가져오기', text: `가져온 입고 ${na}건 도착·인수 일시 미입력`, link: '/receipts' });
  const tp = await n("SELECT COUNT(*) AS n FROM containers WHERE status='tare_pending'"); if (tp) out.push({ level: 'warn', kind: '용기 무게', text: `용기 무게 미확정 ${tp}개 — 원장 미반영`, link: '/inventory' });
  if (s.permit_gate === '1' && s.permit_status !== 'confirmed') out.push({ level: 'warn', kind: '허가 게이트', text: '허가 정보 미확인 — 반출·사용 잠금 중', link: '/settings' });
  return out;
}
// 보관 재고(용기 단위)
async function inventory(db, { codeId } = {}) {
  return db.all(`SELECT c.*, i.code, i.locked, l.name AS location, (SELECT COALESCE(SUM(delta_ug),0) FROM ledger g WHERE g.container_id=c.id) AS balance_ug
    FROM containers c JOIN item_codes i ON i.id=c.code_id LEFT JOIN locations l ON l.id=c.location_id ${codeId ? 'WHERE c.code_id=$1' : ''} ORDER BY i.code, c.cid`, codeId ? [codeId] : []);
}
// 전광판: 허용 목록 집계만(이름·코드·건번호·매핑 관련 이벤트 없음)
async function boardData(db) {
  await sweep(db); const s = await settings(db); const today = kstDate(); const dayStart = new Date(`${today}T00:00:00+09:00`).toISOString();
  const n = (q, p = []) => db.get(q, p).then((r) => Number(r.n));
  const k = {
    containers: await n("SELECT COUNT(*) AS n FROM containers WHERE status IN ('stored','quarantine','weigh_hold','tare_pending','weigh_pending')"),
    todayOut: await n("SELECT COUNT(*) AS n FROM checkouts WHERE out_at >= $1", [dayStart]),
    outstanding: await n("SELECT COUNT(*) AS n FROM checkouts WHERE status IN ('out','return_hold','return_await_witness','return_reweigh')"),
    openAnomalies: await n("SELECT COUNT(*) AS n FROM anomalies WHERE status<>'resolved' AND severity='anomaly'"),
    lockedCodes: await n('SELECT COUNT(*) AS n FROM item_codes WHERE locked=1'),
    pendingWitness: await n("SELECT (SELECT COUNT(*) FROM receipts WHERE status='await_witness') + (SELECT COUNT(*) FROM checkouts WHERE status IN ('out_await_witness','return_await_witness')) + (SELECT COUNT(*) FROM usage_logs WHERE status='await_witness') + (SELECT COUNT(*) FROM disposals WHERE status='await_witness') + (SELECT COUNT(*) FROM tare_jobs WHERE status='await_witness') AS n"),
    incidentsOpen: await n("SELECT COUNT(*) AS n FROM incidents WHERE status IN ('awaiting_determination','report_pending')"),
  };
  const locs = await db.all("SELECT l.id, l.name, (SELECT COUNT(*) FROM containers c WHERE c.location_id=l.id AND c.status IN ('stored','quarantine','weigh_hold','tare_pending','weigh_pending')) AS cnt, (SELECT COUNT(*) FROM containers c WHERE c.location_id=l.id AND c.status IN ('quarantine','weigh_hold')) AS q FROM locations l WHERE l.active=1 AND l.kind<>'lab' ORDER BY l.name");
  const stages = await db.all("SELECT status, COUNT(*) AS n FROM checkouts WHERE status NOT IN ('returned','rejected','cancelled') GROUP BY status");
  const days = Array.from({ length: 7 }, (_, i) => addDays(today, i - 6));
  const series = { out: [], ret: [], amountOut: [] };
  for (const d of days) { const a = new Date(`${d}T00:00:00+09:00`).toISOString(); const b = new Date(`${addDays(d, 1)}T00:00:00+09:00`).toISOString();
    series.out.push(await n('SELECT COUNT(*) AS n FROM checkouts WHERE out_at >= $1 AND out_at < $2', [a, b])); series.ret.push(await n('SELECT COUNT(*) AS n FROM checkouts WHERE returned_at >= $1 AND returned_at < $2', [a, b]));
    if (s.board_show_amounts === '1') series.amountOut.push(Number((await db.get("SELECT COALESCE(-SUM(delta_ug),0) AS n FROM ledger WHERE type='OUT' AND at >= $1 AND at < $2", [a, b])).n) / 1e6); }
  const CAT = { RECEIPT: '입고', CHECKOUT: '반출', RETURN: '반납', USAGE: '사용', DISPOSAL: '폐기', ANOMALY: '이상 징후', INCIDENT: '사고 보고', CODE: '코드', TARE: '용기 무게', LOGIN: '접속' };
  const stream = (await db.all('SELECT at, action FROM audit_log ORDER BY seq DESC LIMIT 12')).map((a) => ({ at: a.at, cat: CAT[a.action.split('_')[0]] || '기타' }));
  return { k, locs: s.board_show_location_alerts === '1' ? locs : locs.map((l) => ({ ...l, q: null })), stages, days, series, showAmounts: s.board_show_amounts === '1', stream };
}
module.exports = {
  DEFAULT_SETTINGS, SETTING_LABEL, DISPOSAL_REASONS, CO_STATUS, AN_TYPES, INC_STATUS, KNOWER_ROLES, LEDGER_ROLES, OUT_SLOTS,
  settings, initSettings, nextNo, balanceOf, usableScale, incidentDues, incidentClock, createAnomaly, createIncident,
  requestCode, decideApproval, createLocation, upsertScale, updateSettings, saveUser, createBoardDevice, revokeDevice,
  setReceiptTimes, createReceipt, reweighReceipt, witnessReceipt, startTare, reweighTare, witnessTare,
  requestCheckout, decideCheckout, submitOut, witnessOut, logUsage, reweighUsage, witnessUsage, submitReturn, witnessReturn,
  createDisposal, reweighDisposal, witnessDisposal, disposalStep, resolveAnomaly, reportAnomaly, incidentStep, openIncidentManual,
  sweep, alerts, inventory, boardData,
};
