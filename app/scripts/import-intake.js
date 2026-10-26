'use strict';
// 가져오기_실데이터.bat → 입고 CSV(row_no, case_no, evidence_no, item_desc, listed_qty, received, received_qty_handwritten, note) 가져오기
// 규칙: received=Y 행만. 품명·사건번호·증거번호·서류 수량·손글씨 원문·비고는 매핑 금고(암호화)에만 저장.
//       업무 DB(원장 쪽)에는 코드·분류·총중량(용기 무게 미확정) 또는 개수(무게 미확정)만. 도착·인수 일시는 비워 둠(관리자 입력).
// 화면·로그에는 건수와 코드 범위만 출력합니다(품명 출력 없음).
const fs = require('fs'); const path = require('path'); const crypto = require('crypto');
const COLS = ['row_no', 'case_no', 'evidence_no', 'item_desc', 'listed_qty', 'received', 'received_qty_handwritten', 'note'];
function decode(buf) {
  if (buf[0] === 0xef && buf[1] === 0xbb && buf[2] === 0xbf) return buf.slice(3).toString('utf8');
  try { return new TextDecoder('utf-8', { fatal: true }).decode(buf); } catch (_) { return new TextDecoder('euc-kr').decode(buf); } // 엑셀 저장(CP949) 대비
}
function parseCsv(text) {
  const rows = []; let row = [], f = '', q = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) { if (c === '"') { if (text[i + 1] === '"') { f += '"'; i++; } else q = false; } else f += c; continue; }
    if (c === '"') q = true; else if (c === ',') { row.push(f); f = ''; } else if (c === '\n' || c === '\r') { if (c === '\r' && text[i + 1] === '\n') i++; row.push(f); rows.push(row); row = []; f = ''; } else f += c;
  }
  if (f !== '' || row.length) { row.push(f); rows.push(row); }
  return rows.filter((r) => r.some((x) => String(x).trim() !== ''));
}
function readCsv(buf) {
  const rows = parseCsv(decode(buf)); if (!rows.length) throw new Error('빈 파일입니다.');
  const head = rows[0].map((h) => h.trim().toLowerCase()); const miss = COLS.filter((c) => !head.includes(c));
  if (miss.length) throw new Error(`필수 열이 없습니다: ${miss.join(', ')}`);
  const idx = Object.fromEntries(COLS.map((c) => [c, head.indexOf(c)]));
  const bad = rows.slice(1).filter((r) => r.length !== head.length).length; if (bad) throw new Error(`열 개수가 맞지 않는 행이 ${bad}개 있습니다.`);
  return rows.slice(1).map((r) => Object.fromEntries(COLS.map((c) => [c, String(r[idx[c]] ?? '').trim()])));
}
const WEIGHT = /^(\d+(?:\.\d+)?)\s*(g|mg|kg)$/i; const COUNT = /^(\d+)\s*([가-힣A-Za-z]{1,3})$/;
function classify(r, rules) {
  const n = Number(r.row_no); const ov = rules.overrides && rules.overrides[String(n)];
  const group = (rules.groups || []).find((g) => g.rows.includes(n));
  if (group) return { kind: 'group', group };
  const hw = (ov ? `${ov.value} ${ov.unit}` : r.received_qty_handwritten).replace(/\s+/g, ' ').trim();
  const w = WEIGHT.exec(hw);
  if (w) { const unit = w[2].toLowerCase(); const { toUg } = require('../src/units'); const ug = unit === 'kg' ? toUg(w[1], 'g') * 1000 : toUg(w[1], unit); return { kind: 'weight', ug, entered: `${w[1]} ${unit}`, override: !!ov, packaging: (rules.packagingIncludedRows || []).includes(n) }; }
  if (!hw) { const c = COUNT.exec(r.listed_qty.replace(/\s+/g, '')); if (c && !/^(g|mg|kg)$/i.test(c[2])) return { kind: 'count', count: c[1], unit: c[2] }; return { kind: 'none' }; }
  const c = COUNT.exec(hw.replace(/\s+/g, '')); if (c && !/^(g|mg|kg)$/i.test(c[2])) return { kind: 'count', count: c[1], unit: c[2] };
  return { kind: 'other' };
}
function plan(rows, rules) {
  const dup = rows.length - new Set(rows.map((r) => r.row_no)).size; if (dup) throw new Error(`row_no 중복 ${dup}건`);
  const Y = rows.filter((r) => r.received.toUpperCase() === 'Y');
  const items = Y.map((r) => ({ r, c: classify(r, rules) }));
  const cnt = (k) => items.filter((x) => x.c.kind === k).length;
  return { total: rows.length, yes: Y.length, skipped: rows.length - Y.length, items, summary: { weight: cnt('weight'), count: cnt('count'), group: cnt('group'), none: cnt('none'), other: cnt('other'), override: items.filter((x) => x.c.override).length, packaging: items.filter((x) => x.c.packaging).length } };
}
// 실제 가져오기. ctxUser = 재인증된 시스템관리자. vault = createVault()
async function importIntake({ db, vault, user, buf, rules, category, ip = '127.0.0.1' }) {
  const svc = require('../src/services'); const { writeAudit } = require('../src/audit'); const { makeCode, codeNumber } = require('../src/codes'); const { nowIso } = require('../src/util');
  if (!vault.enabled) throw new Error('매핑 금고가 꺼져 있어 가져올 수 없습니다(키 확인).');
  const sha = crypto.createHash('sha256').update(buf).digest('hex'); const key = `import:${sha.slice(0, 16)}`;
  if (await db.get('SELECT key FROM settings WHERE key=$1', [key])) throw new Error('이미 가져온 파일입니다(같은 내용).');
  const P = plan(readCsv(buf), rules); const batch = `CSV-${sha.slice(0, 8)}`; const cat = String(category || rules.category || '마약').slice(0, 20);
  const ctx = { user, app: 'import', ip }; const vctx = { user, app: 'vault', ip }; const codes = []; const checkCodes = { group: new Map(), other: [] };
  await db.tx(async (t) => {
    let loc = await t.get("SELECT * FROM locations WHERE active=1 AND kind='vault' AND in_permit_site=1 ORDER BY id LIMIT 1");
    if (!loc) { const at = nowIso(); loc = await t.get("INSERT INTO locations (name, kind, in_permit_site, created_at) VALUES ('보관 금고(가져오기 기본)','vault',1,$1) RETURNING *", [at]); }
    let max = (await t.all('SELECT code FROM item_codes')).reduce((m, r) => Math.max(m, codeNumber(r.code)), 0);
    for (const { r, c } of P.items) {
      const at = nowIso(); const code = makeCode(++max); codes.push(code);
      const ic = await t.get("INSERT INTO item_codes (code, category, form, created_by, created_at, updated_at) VALUES ($1,$2,'unknown',$3,$4,$4) RETURNING id", [code, cat, user.id, at]);
      const no = await svc.nextNo(t, 'receipts', 'IN'); const check = ['group', 'other', 'none'].includes(c.kind);
      const src = `CSV행 ${r.row_no}${c.packaging ? ' · 총중량(포장 포함)' : ''}${c.override ? ' · 무게 대표 확인' : ''}`;
      const rc = await t.get("INSERT INTO receipts (no, code_id, arrival_at, arrival_src, received_at, received_src, registered_at, source_ref, doc_no, declared_value, declared_unit, location_id, lines, status, created_by) VALUES ($1,$2,'','missing','','missing',$3,$4,$5,$6,$7,$8,1,$9,$10) RETURNING id",
        [no, ic.id, at, src, `IMPORT-${batch}`, c.kind === 'count' ? c.count : null, c.kind === 'count' ? c.unit : null, loc.id, check ? 'imported_check' : 'imported', user.id]);
      const lot = await t.get('INSERT INTO lots (lot_no, code_id, receipt_id, created_at) VALUES ($1,$2,$3,$4) RETURNING id', [`L-${no.slice(3)}`, ic.id, rc.id, at]);
      await t.run('UPDATE receipts SET lot_id=$1 WHERE id=$2', [lot.id, rc.id]);
      const ct = await t.get('INSERT INTO containers (cid, code_id, lot_id, tare_ug, location_id, status, created_at, updated_at) VALUES ($1,$2,$3,NULL,$4,$5,$6,$6) RETURNING id', [`C-${no.slice(3)}-1`, ic.id, lot.id, loc.id, c.kind === 'weight' ? 'tare_pending' : 'weigh_pending', at]);
      if (c.kind === 'weight') await t.run("INSERT INTO weighings (ref_type, ref_id, purpose, slot, role, attempt, container_id, scale_id, value_ug, resolution_ug, stable, entered, method, by_user, at) VALUES ('receipt',$1,'receipt','gross_1','performer',1,$2,NULL,$3,NULL,0,$4,'import_handwritten',$5,$6)", [rc.id, ct.id, c.ug, `${c.entered} (손글씨)`, user.id, at]);
      if (c.kind === 'group') { const k = c.group.rows.join(','); if (!checkCodes.group.has(k)) checkCodes.group.set(k, { g: c.group, codes: [] }); checkCodes.group.get(k).codes.push(code); }
      if (c.kind === 'other' || c.kind === 'none') checkCodes.other.push(code);
      await writeAudit(t, ctx, 'IMPORT_ROW', 'receipt', rc.id, null, { code, row_no: r.row_no, kind: c.kind, batch });
      // 매핑(암호화, 2인 승인 대기): 식별 정보는 여기에만
      await vault.request(vctx, code, { def_name: r.item_desc, case_no: r.case_no, evidence_no: r.evidence_no, listed_qty: r.listed_qty, received_raw: r.received_qty_handwritten, def_note: r.note || '-' }, `CSV 가져오기 ${batch}`);
    }
    for (const { g, codes: cs } of checkCodes.group.values()) await svc.createAnomaly(t, ctx, { type: 'IMPORT_CHECK', severity: 'warning', description: `CSV행 ${g.rows[0]}–${g.rows[g.rows.length - 1]} 묶음(${cs[0]}~${cs[cs.length - 1]}): 손글씨 ${g.handwrittenTotal} — ${g.note}. 무게 미확정으로 등록(배분하지 않음)` });
    if (checkCodes.other.length) await svc.createAnomaly(t, ctx, { type: 'IMPORT_CHECK', severity: 'warning', description: `무게·개수를 해석하지 못한 행 ${checkCodes.other.length}건(${checkCodes.other.join(', ')}) — 원문은 매핑 금고에서 확인` });
    await t.run('INSERT INTO settings (key, value) VALUES ($1,$2)', [key, JSON.stringify({ batch, at: nowIso(), rows: P.items.length })]);
    await writeAudit(t, ctx, 'IMPORT_BATCH', 'import', batch, null, { file_sha256: sha, total: P.total, imported: P.items.length, skipped: P.skipped, ...P.summary, codes: codes.length ? `${codes[0]}~${codes[codes.length - 1]}` : '' });
  });
  return { batch, ...P, codes, items: undefined };
}
// ── 콘솔(Windows) 입력
function ask(q) { return new Promise((r) => { const rl = require('readline').createInterface({ input: process.stdin, output: process.stdout }); rl.question(q, (a) => { rl.close(); r(a.trim()); }); }); }
function askHidden(q) {
  return new Promise((resolve) => {
    process.stdout.write(q); const s = process.stdin; let v = '';
    if (!s.isTTY) return ask('').then(resolve);
    s.setRawMode(true); s.resume(); s.setEncoding('utf8');
    const on = (ch) => { for (const c of ch) { if (c === '\r' || c === '\n') { s.setRawMode(false); s.pause(); s.removeListener('data', on); process.stdout.write('\n'); return resolve(v); } if (c === '\u0003') process.exit(1); if (c === '\b' || c === '\u007f') v = v.slice(0, -1); else v += c; } };
    s.on('data', on);
  });
}
async function cli() {
  const E = process.env.AEGIS2_EDITION === 'server' ? require('./server-env') : require('./offline-env'); E.applyEnv({ create: false }); // 서버판: aegisctl import 로 실행
  const rules = JSON.parse(fs.readFileSync(path.join(__dirname, 'import-rules.json'), 'utf8'));
  let file = process.argv[2] || await ask('가져올 CSV 파일 경로(파일을 이 창에 끌어다 놓아도 됩니다): ');
  file = file.replace(/^"(.*)"$/, '$1'); if (!fs.existsSync(file)) throw new Error('파일을 찾을 수 없습니다.');
  const buf = fs.readFileSync(file); const P = plan(readCsv(buf), rules); const s = P.summary;
  console.log(`\n[미리보기] 전체 ${P.total}행 · 가져올 행(received=Y) ${P.yes} · 제외 ${P.skipped}`);
  console.log(`  총중량(용기 무게 미확정) ${s.weight}건 (포장 포함 표시 ${s.packaging}, 대표 확인 무게 ${s.override}) · 개수만(무게 미확정) ${s.count}건 · 묶음 확인 필요 ${s.group}건 · 수량 없음 ${s.none}건 · 해석 불가 ${s.other}건`);
  console.log('  품명·사건번호 등은 매핑 금고에 암호화되어 들어가고, 지정 대행자의 승인(2인) 뒤 확정됩니다.\n');
  if ((await ask('가져올까요? (Y 입력 후 Enter): ')).toUpperCase() !== 'Y') { console.log('취소했습니다.'); return; }
  const { createCore } = require('../src/server'); const { createVault } = require('../src/vault'); const auth = require('../src/auth'); const { rolesOf } = require('../src/perm');
  const core = await createCore(); const vault = createVault(core.cfg); await vault.migrate();
  const username = (await ask('시스템관리자 아이디: ')).toLowerCase(); const pw = await askHidden('비밀번호: '); const code = await ask('인증 앱 6자리: ');
  const u = await core.db.get('SELECT * FROM users WHERE username=$1 AND active=1', [username]);
  if (!u || !rolesOf(u).includes('sysadmin')) throw new Error('시스템관리자 계정이 아닙니다.');
  await auth.reauthStrong(u, pw, code);
  const r = await importIntake({ db: core.db, vault, user: u, buf, rules, category: rules.category });
  console.log(`\n완료: 묶음 ${r.batch} · ${r.codes.length}건 등록 · 코드 ${r.codes[0] || '-'} ~ ${r.codes[r.codes.length - 1] || '-'}`);
  console.log('다음: ① 매핑 금고(3204)에서 지정 대행자가 "승인 대기 → 묶음 전체 승인" ② 관리 앱 "가져온 입고"에서 도착·인수 일시 입력 ③ 현장 앱 "보관 재고"에서 용기 무게 확정(입회 계량)');
  await core.db.close(); await vault.close();
}
if (require.main === module) cli().catch((e) => { console.error('가져오기 실패:', e.message); process.exitCode = 1; });
module.exports = { readCsv, plan, classify, importIntake, decode };
