'use strict';
// 코드↔실물 매핑 저장소(Code Vault)
// - 업무 DB와 다른 DB(별도 SQLite 파일 또는 별도 Postgres)에 저장. 현장 앱·전광판은 이 모듈을 아예 받지 않습니다.
// - 내용은 AES-256-GCM으로 암호화(키는 환경변수, DB에 없음). AAD = 코드|버전 → 다른 코드로 옮겨 붙이면 복호화 실패.
// - 열람: 시스템관리자만(또는 지정 대행자 2인 비상 승인). 매번 비밀번호 재인증 + 사유 + 열람 기록.
// - 등록·변경: 시스템관리자 요청 → 매핑 지정 대행자(요청자와 다른 사람) 승인 = 2인.
const crypto = require('crypto');
const { createDb } = require('./db');
const { sqliteTriggers, pgTriggers } = require('./schema');
const { AppError, nowIso, sha256, canonical } = require('./util');
const VAULT_TABLES = `
CREATE TABLE IF NOT EXISTS mappings (
  id {{ID}}, code TEXT NOT NULL, version INTEGER NOT NULL, key_id TEXT NOT NULL, iv TEXT NOT NULL, ct TEXT NOT NULL, tag TEXT NOT NULL,
  requested_by INTEGER NOT NULL, approved_by INTEGER NOT NULL, request_id INTEGER NOT NULL, created_at TEXT NOT NULL, UNIQUE(code, version));
CREATE TABLE IF NOT EXISTS mapping_requests (
  id {{ID}}, code TEXT NOT NULL, version INTEGER NOT NULL, key_id TEXT NOT NULL, iv TEXT NOT NULL, ct TEXT NOT NULL, tag TEXT NOT NULL,
  reason TEXT NOT NULL, requested_by INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'pending', decided_by INTEGER, decision_note TEXT,
  created_at TEXT NOT NULL, decided_at TEXT);
CREATE TABLE IF NOT EXISTS mapping_access_log (
  id {{ID}}, at TEXT NOT NULL, user_id INTEGER, username TEXT NOT NULL, kind TEXT NOT NULL, code TEXT, reason TEXT NOT NULL, ip TEXT, prev_hash TEXT NOT NULL, hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions (
  id_hash TEXT PRIMARY KEY, app TEXT NOT NULL, user_id INTEGER, device_id INTEGER, csrf TEXT NOT NULL, stage TEXT NOT NULL DEFAULT 'full',
  created_at TEXT NOT NULL, last_seen TEXT NOT NULL, ip TEXT);
CREATE TABLE IF NOT EXISTS permit_info (
  id {{ID}}, code TEXT NOT NULL DEFAULT 'PERMIT', version INTEGER NOT NULL, key_id TEXT NOT NULL, iv TEXT NOT NULL, ct TEXT NOT NULL, tag TEXT NOT NULL,
  set_by INTEGER NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS ledger_unlocks (
  id {{ID}}, requested_by INTEGER NOT NULL, reason TEXT NOT NULL, inspector TEXT NOT NULL DEFAULT '', scope TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'pending', approved_by INTEGER, expires_at TEXT, created_at TEXT NOT NULL, decided_at TEXT, outputs INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS emergency_grants (
  id {{ID}}, requested_by INTEGER NOT NULL, reason TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', approved_by INTEGER,
  expires_at TEXT, created_at TEXT NOT NULL, decided_at TEXT);
`;
const V_APPEND = ['mappings', 'mapping_access_log', 'permit_info'];
const VAULT_SCHEMA = { SCHEMA_TABLES: VAULT_TABLES, SQLITE_TRIGGERS: sqliteTriggers(V_APPEND), PG_TRIGGERS: pgTriggers(V_APPEND, 'aegis2_vault_append_only'), LOCK: 7342200 };
// 실물 정의 항목(필드 목록은 법무·CTO 확정 전 임시) — 화면 라벨만 있고, 값은 모두 암호문으로만 저장
// 법무 의견(6-6) 최소 필드. 값은 모두 암호문으로만 저장.
const FIELDS = [['def_name', '품명(법정 장부 기재명)'], ['legal_class', '법정 분류'], ['extra_approval_no', '추가 승인 번호(해당 시)'], ['supply_doc_no', '제공 문서 번호'], ['permit_ref', '허가 근거'], ['chem_law', '화학물질 법령 해당 여부'], ['def_note', '비고'], ['case_no', '사건번호'], ['evidence_no', '증거번호'], ['listed_qty', '서류상 수량'], ['received_raw', '인수 수량(손글씨 원문)']];
// 법정 장부 머리 항목(허가번호·명의자 성명·생년월일·업소명·소재지) — 개인정보 포함, 암호화 저장
const PERMIT_FIELDS = [['permit_no', '허가번호'], ['holder_name', '성명(허가 명의자)'], ['holder_birth', '생년월일'], ['business_name', '업소명'], ['address', '소재지']];
const LEDGER_UNLOCK_MINUTES = 60; // 〔예시〕 점검 대장 출력 2인 해제 유효 시간
const EMERGENCY_MINUTES = 30; // 〔예시〕

function loadKey(b64) {
  if (!b64) return null;
  const k = Buffer.from(String(b64), 'base64');
  if (k.length !== 32) throw new Error('AEGIS2_MAPPING_KEY는 base64로 인코딩한 32바이트여야 합니다.');
  return k;
}
function encrypt(key, keyId, code, version, obj) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key, iv); c.setAAD(Buffer.from(`${code}|${version}`));
  const ct = Buffer.concat([c.update(JSON.stringify(obj), 'utf8'), c.final()]);
  return { key_id: keyId, iv: iv.toString('base64'), ct: ct.toString('base64'), tag: c.getAuthTag().toString('base64') };
}
function decrypt(key, row) {
  const d = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(row.iv, 'base64')); d.setAAD(Buffer.from(`${row.code}|${row.version}`));
  d.setAuthTag(Buffer.from(row.tag, 'base64'));
  return JSON.parse(Buffer.concat([d.update(Buffer.from(row.ct, 'base64')), d.final()]).toString('utf8'));
}

const { rolesOf } = require('./perm');
const KNOWERS = ['sysadmin', 'mapping_deputy', 'permit_holder'];
const role = (ctx, list) => { if (!ctx || ctx.app !== 'vault' || !rolesOf(ctx.user).some((r) => list.includes(r))) throw new AppError('매핑 금고 권한이 없습니다.', 403); };
function createVault(cfg, over = {}) {
  // 매핑은 국외 클라우드에 두지 않습니다(법무 7-2): Vercel 등 클라우드 런타임에서는 매핑 기능을 끕니다.
  const onCloud = !!(process.env.VERCEL || process.env.AWS_LAMBDA_FUNCTION_NAME) && !over.allowCloud;
  const key = onCloud ? null : loadKey(cfg.mappingKey);
  const db = over.db || createDb({ url: cfg.vaultDatabaseUrl, sqlitePath: cfg.vaultSqlitePath }, VAULT_SCHEMA);
  const enabled = !!key;
  const needKey = () => { if (!key) throw new AppError(onCloud ? '클라우드 실행 환경에서는 매핑 기능을 쓰지 않습니다(사내 서버 전용).' : '매핑 암호 키(AEGIS2_MAPPING_KEY)가 설정되지 않아 매핑 기능이 꺼져 있습니다.', 503); };
  // Vault 열람 기록: 업무 감사 로그와 별도의 해시 체인
  const log = async (t, ctx, kind, code, reason) => {
    const last = await t.get('SELECT hash FROM mapping_access_log ORDER BY id DESC LIMIT 1'); const prev = last ? last.hash : '0'.repeat(64);
    const r = { at: nowIso(), user_id: ctx.user ? ctx.user.id : null, username: ctx.user ? ctx.user.username : (ctx.actorName || 'system'), kind, code: code || null, reason: String(reason || ''), ip: ctx.ip || null };
    const hash = sha256(prev + '|' + canonical(r));
    await t.run('INSERT INTO mapping_access_log (at, user_id, username, kind, code, reason, ip, prev_hash, hash) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)', [r.at, r.user_id, r.username, kind, r.code, r.reason, r.ip, prev, hash]);
  };
  async function verifyLog() {
    const rows = await db.all('SELECT * FROM mapping_access_log ORDER BY id'); let prev = '0'.repeat(64);
    for (const x of rows) { const r = { at: x.at, user_id: x.user_id ?? null, username: x.username, kind: x.kind, code: x.code ?? null, reason: x.reason, ip: x.ip ?? null };
      if (x.prev_hash !== prev || sha256(prev + '|' + canonical(r)) !== x.hash) return { ok: false, brokenAt: x.id, count: rows.length }; prev = x.hash; }
    return { ok: true, count: rows.length, head: prev };
  }
  const latest = (t, code) => t.get('SELECT * FROM mappings WHERE code=$1 ORDER BY version DESC LIMIT 1', [code]);
  function clean(fields) {
    const o = {}; let any = false;
    for (const [k] of FIELDS) { const v = String(fields[k] ?? '').trim().slice(0, 300); o[k] = v; if (v) any = true; }
    if (!any) throw new AppError('매핑 항목을 하나 이상 입력하세요.');
    return o;
  }
  async function activeGrant(t, userId) {
    return t.get("SELECT * FROM emergency_grants WHERE requested_by=$1 AND status='approved' AND expires_at > $2 ORDER BY id DESC LIMIT 1", [userId, nowIso()]);
  }
  return {
    db, enabled, onCloud, FIELDS, PERMIT_FIELDS, verifyLog, log: (ctx, kind, code, reason) => db.tx((t) => log(t, ctx, kind, code, reason)), migrate: () => db.migrate(), close: () => db.close(),
    // 매핑 등록·변경 요청(시스템관리자). 평문은 요청 단계부터 암호화해 둡니다.
    async request(ctx, code, fields, reason) {
      role(ctx, ['sysadmin']); needKey();
      return db.tx(async (t) => {
        const last = await latest(t, code);
        const pend = await t.get("SELECT id FROM mapping_requests WHERE code=$1 AND status='pending'", [code]);
        if (pend) throw new AppError('이 코드에 이미 승인 대기 중인 매핑 요청이 있습니다.');
        const version = last ? Number(last.version) + 1 : 1;
        const enc = encrypt(key, cfg.mappingKeyId, code, version, clean(fields));
        const r = await t.get('INSERT INTO mapping_requests (code, version, key_id, iv, ct, tag, reason, requested_by, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id',
          [code, version, enc.key_id, enc.iv, enc.ct, enc.tag, reason, ctx.user.id, nowIso()]);
        await log(t, ctx, 'request', code, reason);
        return { id: r.id, version };
      });
    },
    async pending() { return db.all("SELECT id, code, version, reason, requested_by, created_at FROM mapping_requests WHERE status='pending' ORDER BY id"); },
    // 승인자(대행자)가 승인 전에 내용 확인 — 이것도 열람 기록
    async viewRequest(ctx, id, reason) {
      role(ctx, ['mapping_deputy']); needKey();
      return db.tx(async (t) => {
        const r = await t.get('SELECT * FROM mapping_requests WHERE id=$1', [id]); if (!r) throw new AppError('요청을 찾을 수 없습니다.', 404);
        await log(t, ctx, 'review_view', r.code, reason);
        return { ...r, fields: decrypt(key, r) };
      });
    },
    async decide(ctx, id, approve, note) {
      role(ctx, ['mapping_deputy']); needKey();
      return db.tx(async (t) => {
        const r = await t.get('SELECT * FROM mapping_requests WHERE id=$1', [id]); if (!r) throw new AppError('요청을 찾을 수 없습니다.', 404);
        if (r.status !== 'pending') throw new AppError('이미 처리된 요청입니다.');
        if (Number(r.requested_by) === ctx.user.id) throw new AppError('본인이 요청한 매핑은 승인할 수 없습니다(2인 원칙).', 403);
        const at = nowIso();
        await t.run('UPDATE mapping_requests SET status=$1, decided_by=$2, decision_note=$3, decided_at=$4 WHERE id=$5', [approve ? 'approved' : 'rejected', ctx.user.id, note || '', at, id]);
        if (approve) {
          decrypt(key, r); // 무결성 확인
          await t.run('INSERT INTO mappings (code, version, key_id, iv, ct, tag, requested_by, approved_by, request_id, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)',
            [r.code, r.version, r.key_id, r.iv, r.ct, r.tag, r.requested_by, ctx.user.id, r.id, at]);
        }
        await log(t, ctx, approve ? 'approve' : 'reject', r.code, note || '-');
        return { code: r.code, version: r.version, approved: approve };
      });
    },
    // 열람: 시스템관리자 또는 유효한 비상 승인 보유 대행자. 사유 필수.
    async view(ctx, code, reason, { emergency = false } = {}) {
      role(ctx, emergency ? ['mapping_deputy'] : ['sysadmin']); needKey();
      return db.tx(async (t) => {
        if (emergency) { const g = await activeGrant(t, ctx.user.id); if (!g) throw new AppError('유효한 비상 열람 승인이 없습니다.', 403); }
        const row = await latest(t, code);
        await log(t, ctx, emergency ? 'emergency_view' : 'view', code, reason);
        if (!row) return null;
        return { code, version: row.version, created_at: row.created_at, requested_by: row.requested_by, approved_by: row.approved_by, fields: decrypt(key, row) };
      });
    },
    async mappedCodes() { return (await db.all('SELECT code, MAX(version) AS version FROM mappings GROUP BY code')).reduce((m, r) => { m[r.code] = Number(r.version); return m; }, {}); },
    async accessLog(limit = 100) { return db.all('SELECT * FROM mapping_access_log ORDER BY id DESC LIMIT $1', [limit]); },
    // 비상 열람: 대행자 A 요청 → 대행자 B 승인 → A가 30분간 열람 가능
    async requestEmergency(ctx, reason) {
      role(ctx, ['mapping_deputy']);
      return db.tx(async (t) => {
        const r = await t.get('INSERT INTO emergency_grants (requested_by, reason, created_at) VALUES ($1,$2,$3) RETURNING id', [ctx.user.id, reason, nowIso()]);
        await log(t, ctx, 'emergency_request', null, reason); return r.id;
      });
    },
    async decideEmergency(ctx, id, approve) {
      role(ctx, ['mapping_deputy']);
      return db.tx(async (t) => {
        const g = await t.get('SELECT * FROM emergency_grants WHERE id=$1', [id]); if (!g) throw new AppError('요청을 찾을 수 없습니다.', 404);
        if (g.status !== 'pending') throw new AppError('이미 처리된 요청입니다.');
        if (Number(g.requested_by) === ctx.user.id) throw new AppError('본인 비상 요청은 승인할 수 없습니다(2인 원칙).', 403);
        const at = nowIso(); const exp = new Date(Date.now() + EMERGENCY_MINUTES * 60000).toISOString();
        await t.run('UPDATE emergency_grants SET status=$1, approved_by=$2, decided_at=$3, expires_at=$4 WHERE id=$5', [approve ? 'approved' : 'rejected', ctx.user.id, at, approve ? exp : null, id]);
        await log(t, ctx, approve ? 'emergency_approve' : 'emergency_reject', null, `grant #${id}`);
        return { approved: approve, expires_at: approve ? exp : null, requested_by: g.requested_by };
      });
    },
    // 허가 정보(시스템관리자 등록, 버전 이력 보존)
    async setPermit(ctx, fields, reason) {
      role(ctx, ['sysadmin']); needKey();
      return db.tx(async (t) => {
        const last = await t.get('SELECT version FROM permit_info ORDER BY version DESC LIMIT 1');
        const version = last ? Number(last.version) + 1 : 1; const o = {};
        for (const [k] of PERMIT_FIELDS) o[k] = String(fields[k] ?? '').trim().slice(0, 200);
        const enc = encrypt(key, cfg.mappingKeyId, 'PERMIT', version, o);
        await t.run('INSERT INTO permit_info (code, version, key_id, iv, ct, tag, set_by, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)', ['PERMIT', version, enc.key_id, enc.iv, enc.ct, enc.tag, ctx.user.id, nowIso()]);
        await log(t, ctx, 'permit_set', null, reason); return version;
      });
    },
    async hasPermit() { return !!(await db.get('SELECT id FROM permit_info LIMIT 1')); },
    // 점검 대장 출력: SA·지정 대행자·허가 명의자 중 1인 요청 → 다른 1인 승인(2인 해제) → 요청자가 60분간 출력
    async requestLedgerUnlock(ctx, reason, inspector, scope) {
      role(ctx, KNOWERS);
      return db.tx(async (t) => {
        const r = await t.get('INSERT INTO ledger_unlocks (requested_by, reason, inspector, scope, created_at) VALUES ($1,$2,$3,$4,$5) RETURNING id', [ctx.user.id, reason, inspector || '', scope || '', nowIso()]);
        await log(t, ctx, 'ledger_unlock_request', null, reason); return r.id;
      });
    },
    async decideLedgerUnlock(ctx, id, approve) {
      role(ctx, KNOWERS);
      return db.tx(async (t) => {
        const g = await t.get('SELECT * FROM ledger_unlocks WHERE id=$1', [id]); if (!g) throw new AppError('요청을 찾을 수 없습니다.', 404);
        if (g.status !== 'pending') throw new AppError('이미 처리된 요청입니다.');
        if (Number(g.requested_by) === ctx.user.id) throw new AppError('본인 요청은 승인할 수 없습니다(2인 해제).', 403);
        const exp = new Date(Date.now() + LEDGER_UNLOCK_MINUTES * 60000).toISOString();
        await t.run('UPDATE ledger_unlocks SET status=$1, approved_by=$2, decided_at=$3, expires_at=$4 WHERE id=$5', [approve ? 'approved' : 'rejected', ctx.user.id, nowIso(), approve ? exp : null, id]);
        await log(t, ctx, approve ? 'ledger_unlock_approve' : 'ledger_unlock_reject', null, `unlock #${id}`);
        return { approved: approve, expires_at: approve ? exp : null };
      });
    },
    async ledgerUnlocks() { return db.all('SELECT * FROM ledger_unlocks ORDER BY id DESC LIMIT 50'); },
    async activeLedgerUnlock(userId) { return db.get("SELECT * FROM ledger_unlocks WHERE requested_by=$1 AND status='approved' AND expires_at > $2 ORDER BY id DESC LIMIT 1", [userId, nowIso()]); },
    // 해제된 사용자만: 코드 목록의 품명 + 허가 정보 복호화(출력 1회 = 열람 기록 1건)
    async ledgerData(ctx, codes, outputNo) {
      role(ctx, KNOWERS); needKey();
      return db.tx(async (t) => {
        const u = await t.get("SELECT * FROM ledger_unlocks WHERE requested_by=$1 AND status='approved' AND expires_at > $2 ORDER BY id DESC LIMIT 1", [ctx.user.id, nowIso()]);
        if (!u) throw new AppError('점검 대장 출력은 2인 해제가 필요합니다.', 403);
        await t.run('UPDATE ledger_unlocks SET outputs=outputs+1 WHERE id=$1', [u.id]);
        const names = {};
        for (const c of codes) { const row = await latest(t, c); names[c] = row ? decrypt(key, row).def_name || '' : ''; }
        const p = await t.get('SELECT * FROM permit_info ORDER BY version DESC LIMIT 1');
        await log(t, ctx, 'ledger_output', null, `출력 ${outputNo} · 코드 ${codes.length}개 · unlock #${u.id}`);
        return { names, permit: p ? decrypt(key, p) : null, unlockId: u.id };
      });
    },
    async grants() { return db.all('SELECT * FROM emergency_grants ORDER BY id DESC LIMIT 50'); },
    activeGrant: (userId) => activeGrant(db, userId),
  };
}
module.exports = { createVault, encrypt, decrypt, loadKey, FIELDS, PERMIT_FIELDS, VAULT_SCHEMA };
