'use strict';
// AEGIS v2 업무 DB. 품목은 코드로만 식별합니다(품목명·성분명 필드 없음). 무게는 모두 µg 정수(_ug).
// 코드↔실물 매핑은 이 DB에 두지 않습니다(별도 매핑 저장소: src/vault.js).
const SCHEMA_TABLES = `
CREATE TABLE IF NOT EXISTS users (
  id {{ID}}, username TEXT NOT NULL UNIQUE, display_name TEXT NOT NULL, password_hash TEXT NOT NULL,
  roles TEXT NOT NULL DEFAULT '', active INTEGER NOT NULL DEFAULT 1, must_change_pw INTEGER NOT NULL DEFAULT 0,
  totp_secret TEXT, totp_enabled INTEGER NOT NULL DEFAULT 0, failed_count INTEGER NOT NULL DEFAULT 0,
  locked_until TEXT, last_login_at TEXT, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions (
  id_hash TEXT PRIMARY KEY, app TEXT NOT NULL, user_id INTEGER, device_id INTEGER, csrf TEXT NOT NULL, stage TEXT NOT NULL DEFAULT 'full',
  created_at TEXT NOT NULL, last_seen TEXT NOT NULL, ip TEXT);
CREATE TABLE IF NOT EXISTS devices (
  id {{ID}}, kind TEXT NOT NULL, name TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, allow_cidrs TEXT NOT NULL DEFAULT '', active INTEGER NOT NULL DEFAULT 1,
  created_by INTEGER NOT NULL, created_at TEXT NOT NULL, last_seen TEXT);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS locations (
  id {{ID}}, name TEXT NOT NULL UNIQUE, kind TEXT NOT NULL DEFAULT 'vault', in_permit_site INTEGER NOT NULL DEFAULT 1, active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS scales (
  id {{ID}}, scale_id TEXT NOT NULL UNIQUE, model TEXT NOT NULL DEFAULT '', resolution_ug {{BIG}} NOT NULL, repeatability_ug {{BIG}},
  location TEXT NOT NULL DEFAULT '', adapter TEXT NOT NULL DEFAULT 'manual', calib_due TEXT, active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS item_codes (
  id {{ID}}, code TEXT NOT NULL UNIQUE, category TEXT NOT NULL DEFAULT 'CAT-A', form TEXT NOT NULL DEFAULT 'solid', return_days INTEGER,
  status TEXT NOT NULL DEFAULT 'active', locked INTEGER NOT NULL DEFAULT 0, created_by INTEGER, approved_by INTEGER, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS approvals (
  id {{ID}}, type TEXT NOT NULL, target_id INTEGER, payload TEXT NOT NULL, reason TEXT NOT NULL,
  requested_by INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'pending', decided_by INTEGER, decision_note TEXT, created_at TEXT NOT NULL, decided_at TEXT);
CREATE TABLE IF NOT EXISTS lots (
  id {{ID}}, lot_no TEXT NOT NULL UNIQUE, code_id INTEGER NOT NULL REFERENCES item_codes(id), receipt_id INTEGER, created_at TEXT NOT NULL);
-- 보관 상태(status)는 수량과 분리: pending(입회 전) / tare_pending(용기 무게 미확정) / stored / out(반출 중) / quarantine(격리) / weigh_hold(계량 보류) / disposed / empty
CREATE TABLE IF NOT EXISTS containers (
  id {{ID}}, cid TEXT NOT NULL UNIQUE, code_id INTEGER NOT NULL REFERENCES item_codes(id), lot_id INTEGER REFERENCES lots(id),
  parent_id INTEGER, tare_ug {{BIG}}, location_id INTEGER REFERENCES locations(id),
  status TEXT NOT NULL DEFAULT 'pending', holder_id INTEGER, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS receipts (
  id {{ID}}, no TEXT NOT NULL UNIQUE, code_id INTEGER NOT NULL REFERENCES item_codes(id), lot_id INTEGER,
  arrival_at TEXT NOT NULL, arrival_src TEXT NOT NULL DEFAULT 'declared', received_at TEXT NOT NULL, received_src TEXT NOT NULL DEFAULT 'declared', registered_at TEXT NOT NULL,
  source_ref TEXT NOT NULL DEFAULT '', doc_no TEXT NOT NULL, supply_app_no TEXT NOT NULL DEFAULT '', seal_no TEXT NOT NULL DEFAULT '', seal_ok INTEGER NOT NULL DEFAULT 1,
  declared_value TEXT, declared_unit TEXT, location_id INTEGER, scale_id INTEGER, lines INTEGER NOT NULL,
  status TEXT NOT NULL, attempt INTEGER NOT NULL DEFAULT 1, created_by INTEGER NOT NULL, witness_id INTEGER, completed_at TEXT, blocked INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS weighings (
  id {{ID}}, ref_type TEXT NOT NULL, ref_id INTEGER NOT NULL, purpose TEXT NOT NULL, slot TEXT NOT NULL, role TEXT NOT NULL, attempt INTEGER NOT NULL DEFAULT 1,
  container_id INTEGER, scale_id INTEGER REFERENCES scales(id), value_ug {{BIG}} NOT NULL, resolution_ug {{BIG}}, stable INTEGER NOT NULL DEFAULT 1,
  entered TEXT NOT NULL, method TEXT NOT NULL DEFAULT 'manual', raw TEXT, device_sig TEXT, device_at TEXT, by_user INTEGER NOT NULL, at TEXT NOT NULL);
-- 반출: mode = whole(용기째) | aliquot(분주). step = 계량·입회 진행 상태
CREATE TABLE IF NOT EXISTS checkouts (
  id {{ID}}, no TEXT NOT NULL UNIQUE, code_id INTEGER NOT NULL REFERENCES item_codes(id), container_id INTEGER NOT NULL REFERENCES containers(id),
  mode TEXT NOT NULL DEFAULT 'aliquot', aliquot_id INTEGER, requester_id INTEGER NOT NULL, requested_ug {{BIG}} NOT NULL, purpose TEXT NOT NULL,
  experiment_no TEXT NOT NULL DEFAULT '', due_date TEXT NOT NULL, use_location_id INTEGER, status TEXT NOT NULL, step_attempt INTEGER NOT NULL DEFAULT 1,
  approver_id INTEGER, approved_at TEXT, decision_note TEXT, performer_id INTEGER, scale_id INTEGER, out_ug {{BIG}}, witness_id INTEGER, out_at TEXT,
  blocked INTEGER NOT NULL DEFAULT 0, return_submitter_id INTEGER, return_scale_id INTEGER, return_seal_no TEXT, return_witness_id INTEGER,
  measured_ug {{BIG}}, expected_ug {{BIG}}, used_ug {{BIG}}, diff_ug {{BIG}}, sigma_ug {{BIG}}, judgment TEXT, judgment_reason TEXT, return_reason TEXT, returned_at TEXT,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
-- 사용: 원장에 넣지 않음(이중 차감 방지). 입회 계량한 양만 판정에 씀.
CREATE TABLE IF NOT EXISTS usage_logs (
  id {{ID}}, checkout_id INTEGER NOT NULL REFERENCES checkouts(id), amount_ug {{BIG}}, status TEXT NOT NULL, attempt INTEGER NOT NULL DEFAULT 1,
  scale_id INTEGER, used_on TEXT NOT NULL, experiment_no TEXT NOT NULL DEFAULT '', research_summary TEXT NOT NULL DEFAULT '',
  legal_row_no TEXT NOT NULL DEFAULT '', by_user INTEGER NOT NULL, witness_id INTEGER, at TEXT NOT NULL, confirmed_at TEXT);
-- 폐기(법무 3-A): 회사 직접·위탁 폐기 없음. P1 격리·2인 계량 → P2 관청 신청 → P3 공무원 참관 → P5 결과 공문 수령 시 원장 차감.
CREATE TABLE IF NOT EXISTS disposals (
  id {{ID}}, no TEXT NOT NULL UNIQUE, container_id INTEGER NOT NULL REFERENCES containers(id), code_id INTEGER NOT NULL,
  amount_ug {{BIG}}, reason_code TEXT NOT NULL, reason TEXT NOT NULL DEFAULT '', stock_deduct INTEGER NOT NULL DEFAULT 1, status TEXT NOT NULL, attempt INTEGER NOT NULL DEFAULT 1,
  created_by INTEGER NOT NULL, witness_id INTEGER, scale_id INTEGER, quarantine_location_id INTEGER, seal_no TEXT NOT NULL DEFAULT '', weighed_at TEXT,
  applicant TEXT, authority TEXT, applied_on TEXT, application_no TEXT, application_doc_sha TEXT, applied_by INTEGER,
  observed_on TEXT, official_affiliation TEXT, handover_ug {{BIG}}, observe_witness1_id INTEGER, observe_witness2_id INTEGER, observed_by INTEGER,
  result_doc_no TEXT, result_on TEXT, result_doc_sha TEXT, result_by INTEGER, completed_at TEXT, incident_id INTEGER, legal_row_no TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL);
-- 원장 = 보관 수량(금고 안). 종류: RECEIPT(+), OUT(−), RETURN(+실측), DISPOSE(−), ADJUST(±, 2인 종결)
CREATE TABLE IF NOT EXISTS tare_jobs (
  id {{ID}}, container_id INTEGER NOT NULL REFERENCES containers(id), status TEXT NOT NULL, attempt INTEGER NOT NULL DEFAULT 1, scale_id INTEGER,
  created_by INTEGER NOT NULL, witness_id INTEGER, created_at TEXT NOT NULL, completed_at TEXT);
CREATE TABLE IF NOT EXISTS ledger (
  id {{ID}}, container_id INTEGER NOT NULL REFERENCES containers(id), code_id INTEGER NOT NULL, type TEXT NOT NULL,
  delta_ug {{BIG}} NOT NULL, ref_type TEXT NOT NULL, ref_id INTEGER, note TEXT, by_user INTEGER NOT NULL, at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS photos (
  id {{ID}}, ref_type TEXT NOT NULL, ref_id INTEGER NOT NULL, kind TEXT NOT NULL, storage_key TEXT NOT NULL,
  mime TEXT NOT NULL, size INTEGER NOT NULL, sha256 TEXT NOT NULL, uploaded_by INTEGER NOT NULL, at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS anomalies (
  id {{ID}}, no TEXT NOT NULL UNIQUE, type TEXT NOT NULL, severity TEXT NOT NULL, code_id INTEGER, ref_type TEXT, ref_id INTEGER,
  diff_ug {{BIG}}, description TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open', locks_code INTEGER NOT NULL DEFAULT 0,
  adjust_container_id INTEGER, adjust_to_ug {{BIG}}, incident_id INTEGER,
  created_by INTEGER, created_at TEXT NOT NULL, resolve_first_by INTEGER, resolve_first_at TEXT, resolve_first_note TEXT,
  resolved_by INTEGER, resolved_at TEXT, resolution TEXT);
CREATE TABLE IF NOT EXISTS anomaly_actions (
  id {{ID}}, anomaly_id INTEGER NOT NULL REFERENCES anomalies(id), user_id INTEGER NOT NULL, action TEXT NOT NULL, note TEXT NOT NULL, at TEXT NOT NULL);
-- 사고·외부 보고 트랙(법무 3-B): 이상 징후 종결과 별개. aware_at·기한은 수정 불가(트리거).
CREATE TABLE IF NOT EXISTS incidents (
  id {{ID}}, no TEXT NOT NULL UNIQUE, anomaly_id INTEGER, disposal_id INTEGER, code_id INTEGER, aware_at TEXT NOT NULL, discovered_by INTEGER,
  determine_due TEXT NOT NULL, report_due TEXT NOT NULL, internal_target TEXT NOT NULL, determination TEXT, determination_note TEXT, determined_by INTEGER, determined_at TEXT,
  evidence_kind TEXT, evidence_no TEXT, report_authority TEXT, reported_at TEXT, report_receipt_no TEXT, report_doc_sha TEXT, reported_by INTEGER,
  status TEXT NOT NULL DEFAULT 'awaiting_determination', legal_row_no TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit_anchors (
  id {{ID}}, day TEXT NOT NULL, seq INTEGER NOT NULL, head TEXT NOT NULL, count INTEGER NOT NULL, at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit_log (
  seq INTEGER PRIMARY KEY, fmt_version INTEGER NOT NULL DEFAULT 2, at TEXT NOT NULL, app TEXT NOT NULL, actor_id INTEGER, actor TEXT NOT NULL, action TEXT NOT NULL,
  entity TEXT NOT NULL, entity_id TEXT, before_json TEXT, after_json TEXT, ip TEXT, prev_hash TEXT NOT NULL, hash TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_ledger_container ON ledger(container_id);
CREATE INDEX IF NOT EXISTS ix_checkouts_status ON checkouts(status);
CREATE INDEX IF NOT EXISTS ix_audit_at ON audit_log(at);
CREATE INDEX IF NOT EXISTS ix_photos_ref ON photos(ref_type, ref_id);
CREATE INDEX IF NOT EXISTS ix_weigh_ref ON weighings(ref_type, ref_id);
`;
// 추가 전용(수정·삭제 DB 차단)
const APPEND_ONLY = ['audit_log', 'ledger', 'photos', 'anomaly_actions', 'weighings', 'audit_anchors'];
const sqliteTriggers = (tables) => tables.map((t) => `
CREATE TRIGGER IF NOT EXISTS ${t}_no_update BEFORE UPDATE ON ${t} BEGIN SELECT RAISE(ABORT, 'append-only'); END;
CREATE TRIGGER IF NOT EXISTS ${t}_no_delete BEFORE DELETE ON ${t} BEGIN SELECT RAISE(ABORT, 'append-only'); END;`).join('\n');
const pgTriggers = (tables, fn) => `
CREATE OR REPLACE FUNCTION ${fn}() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'append-only'; END; $$ LANGUAGE plpgsql;
` + tables.map((t) => `
DROP TRIGGER IF EXISTS ${t}_append_only ON ${t};
CREATE TRIGGER ${t}_append_only BEFORE UPDATE OR DELETE ON ${t} FOR EACH ROW EXECUTE FUNCTION ${fn}();`).join('\n');
const AWARE_GUARD_SQLITE = `
CREATE TRIGGER IF NOT EXISTS incidents_aware_fixed BEFORE UPDATE OF aware_at, report_due, determine_due ON incidents BEGIN SELECT RAISE(ABORT, 'aware_at fixed'); END;
CREATE TRIGGER IF NOT EXISTS incidents_no_delete BEFORE DELETE ON incidents BEGIN SELECT RAISE(ABORT, 'append-only'); END;
CREATE TRIGGER IF NOT EXISTS usage_confirmed_fixed BEFORE UPDATE ON usage_logs WHEN OLD.status NOT IN ('await_witness','reweigh') BEGIN SELECT RAISE(ABORT, 'usage confirmed: append-only'); END;
CREATE TRIGGER IF NOT EXISTS usage_no_delete BEFORE DELETE ON usage_logs BEGIN SELECT RAISE(ABORT, 'append-only'); END;`;
const AWARE_GUARD_PG = `
CREATE OR REPLACE FUNCTION aegis2_incident_guard() RETURNS trigger AS $$ BEGIN
  IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'append-only'; END IF;
  IF NEW.aware_at <> OLD.aware_at OR NEW.report_due <> OLD.report_due OR NEW.determine_due <> OLD.determine_due THEN RAISE EXCEPTION 'aware_at fixed'; END IF;
  RETURN NEW; END; $$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS incidents_guard ON incidents;
CREATE TRIGGER incidents_guard BEFORE UPDATE OR DELETE ON incidents FOR EACH ROW EXECUTE FUNCTION aegis2_incident_guard();
-- 사용 기록: 입회 확정(confirmed·blocked) 뒤에는 수정 불가, 삭제 불가
CREATE OR REPLACE FUNCTION aegis2_usage_guard() RETURNS trigger AS $$ BEGIN
  IF TG_OP = 'DELETE' OR OLD.status NOT IN ('await_witness','reweigh') THEN RAISE EXCEPTION 'append-only'; END IF; RETURN NEW; END; $$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS usage_guard ON usage_logs;
CREATE TRIGGER usage_guard BEFORE UPDATE OR DELETE ON usage_logs FOR EACH ROW EXECUTE FUNCTION aegis2_usage_guard();`;
const MAIN = { SCHEMA_TABLES, SQLITE_TRIGGERS: sqliteTriggers(APPEND_ONLY) + AWARE_GUARD_SQLITE, PG_TRIGGERS: pgTriggers(APPEND_ONLY, 'aegis2_append_only') + AWARE_GUARD_PG, LOCK: 7342100 };
module.exports = { MAIN, APPEND_ONLY, sqliteTriggers, pgTriggers };
