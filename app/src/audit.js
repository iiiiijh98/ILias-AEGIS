'use strict';
// 감사 로그: 추가 전용 + SHA-256 해시 체인. hash = sha256(prev_hash | canonical(record)). 매핑 내용은 절대 기록하지 않습니다.
const { sha256, canonical, nowIso } = require('./util');
const GENESIS = '0'.repeat(64);
function recordString(r) {
  return canonical({ v: Number(r.fmt_version || 2), seq: Number(r.seq), at: r.at, app: r.app, actor_id: r.actor_id ?? null, actor: r.actor, action: r.action, entity: r.entity, entity_id: r.entity_id ?? null, before: r.before_json ?? null, after: r.after_json ?? null, ip: r.ip ?? null });
}
async function writeAudit(t, ctx, action, entity, entityId, before, after) {
  await t.lockAudit();
  const last = await t.get('SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1');
  const actor = ctx && ctx.user;
  const r = {
    fmt_version: 2, seq: last ? Number(last.seq) + 1 : 1, at: nowIso(), app: (ctx && ctx.app) || 'system', actor_id: actor ? actor.id : null, actor: actor ? actor.username : ((ctx && ctx.actorName) || 'system'),
    action, entity, entity_id: entityId === undefined || entityId === null ? null : String(entityId),
    before_json: before === undefined || before === null ? null : JSON.stringify(before),
    after_json: after === undefined || after === null ? null : JSON.stringify(after), ip: (ctx && ctx.ip) || null,
  };
  r.prev_hash = last ? last.hash : GENESIS;
  r.hash = sha256(r.prev_hash + '|' + recordString(r));
  await t.run('INSERT INTO audit_log (fmt_version, seq, at, app, actor_id, actor, action, entity, entity_id, before_json, after_json, ip, prev_hash, hash) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)',
    [r.fmt_version, r.seq, r.at, r.app, r.actor_id, r.actor, r.action, r.entity, r.entity_id, r.before_json, r.after_json, r.ip, r.prev_hash, r.hash]);
  return r;
}
async function verifyChain(db) {
  const rows = await db.all('SELECT * FROM audit_log ORDER BY seq ASC');
  let prev = GENESIS, expectSeq = 1;
  for (const r of rows) {
    if (Number(r.seq) !== expectSeq) return { ok: false, count: rows.length, brokenAt: r.seq, reason: `순번 누락(기대 ${expectSeq})` };
    if (r.prev_hash !== prev) return { ok: false, count: rows.length, brokenAt: r.seq, reason: '이전 해시 불일치' };
    if (sha256(prev + '|' + recordString(r)) !== r.hash) return { ok: false, count: rows.length, brokenAt: r.seq, reason: '해시 불일치(기록 변조 의심)' };
    prev = r.hash; expectSeq++;
  }
  return { ok: true, count: rows.length, head: prev };
}
// 체인 머리값 고정: 매일 {day, seq, head, count}를 DB 안 고정 테이블 + (설정 시) 별도 위치 파일에 추가 기록
async function anchor(db, day, file) {
  const v = await verifyChain(db); if (!v.ok) return { ok: false, verify: v };
  const last = await db.get('SELECT seq FROM audit_log ORDER BY seq DESC LIMIT 1'); const seq = last ? Number(last.seq) : 0;
  const ex = await db.get('SELECT id FROM audit_anchors WHERE day=$1 AND seq=$2', [day, seq]);
  if (!ex) await db.run('INSERT INTO audit_anchors (day, seq, head, count, at) VALUES ($1,$2,$3,$4,$5)', [day, seq, v.head, v.count, nowIso()]);
  if (file && !ex) { const fs = require('fs'); fs.mkdirSync(require('path').dirname(file), { recursive: true }); fs.appendFileSync(file, JSON.stringify({ day, seq, head: v.head, count: v.count }) + '\n'); }
  return { ok: true, day, seq, head: v.head };
}
// 고정값과 현재 체인 대조(DB 관리자가 체인 전체를 재계산해도 고정 파일과 달라지면 탐지)
async function checkAnchors(db, anchorsFromFile) {
  const rows = await db.all('SELECT seq, hash FROM audit_log ORDER BY seq'); const bySeq = new Map(rows.map((r) => [Number(r.seq), r.hash]));
  const bad = (anchorsFromFile || []).filter((a) => a.seq > 0 && bySeq.get(Number(a.seq)) !== a.head);
  return { ok: bad.length === 0, mismatches: bad };
}
module.exports = { writeAudit, verifyChain, anchor, checkAnchors, GENESIS, recordString };
