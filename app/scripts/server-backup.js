'use strict';
// 서버판 백업·복원. 백업 = 업무 DB + 매핑 금고 DB(암호화된 상태 그대로) + 사진. 암호 키(keys)는 넣지 않습니다(별도 보관).
const fs = require('fs'); const path = require('path'); const crypto = require('crypto');
const E = require('./server-env');
const PREFIX = 'aegis-backup-';
const stamp = (d = new Date()) => { const k = new Date(d.getTime() + 9 * 3600e3).toISOString(); return k.slice(0, 10).replace(/-/g, '') + '-' + k.slice(11, 19).replace(/:/g, ''); }; // 한국 시간
const sha = (f) => crypto.createHash('sha256').update(fs.readFileSync(f)).digest('hex');
function walk(dir, base = dir, out = []) { if (!fs.existsSync(dir)) return out; for (const e of fs.readdirSync(dir, { withFileTypes: true })) { const p = path.join(dir, e.name); if (e.isDirectory()) walk(p, base, out); else if (e.isFile()) out.push(path.relative(base, p)); } return out; }
const inside = (child, parent) => { const r = path.relative(path.resolve(parent), path.resolve(child)); return r === '' || (!r.startsWith('..') && !path.isAbsolute(r)); };
function sqliteSnapshot(src, dest) {
  let db; try { const { DatabaseSync } = require('node:sqlite'); db = new DatabaseSync(src, { readOnly: true }); }
  catch (e) { if (e.code !== 'ERR_UNKNOWN_BUILTIN_MODULE' && e.code !== 'MODULE_NOT_FOUND') throw e; const BS = require('better-sqlite3'); db = new BS(src, { readonly: true }); } // 개발용(Node 20)
  try { db.exec('PRAGMA busy_timeout = 10000'); db.exec(`VACUUM INTO '${dest.replace(/'/g, "''")}'`); } finally { db.close(); }
}
function listBackups(dir = E.DIRS.backup) {
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir).filter((n) => n.startsWith(PREFIX) && fs.existsSync(path.join(dir, n, 'manifest.json'))).sort();
}
function runBackup({ dir = E.DIRS.backup, keep = Number(process.env.AEGIS_BACKUP_KEEP || 30), reason = 'manual' } = {}) {
  if (inside(dir, E.DIRS.keys) || inside(E.DIRS.keys, dir)) throw new Error('백업 폴더와 키 폴더가 겹칩니다. 키는 백업과 다른 곳에 두세요.');
  if (inside(dir, E.DIRS.data)) throw new Error('백업 폴더가 데이터 폴더 안에 있습니다. 다른 디스크/폴더를 지정하세요.');
  fs.mkdirSync(dir, { recursive: true, mode: 0o750 });
  const name = PREFIX + stamp(); const tmp = path.join(dir, '.partial-' + name); const final = path.join(dir, name);
  fs.rmSync(tmp, { recursive: true, force: true }); fs.mkdirSync(path.join(tmp, 'vault'), { recursive: true, mode: 0o750 });
  const main = path.join(E.DIRS.data, 'aegis2.db'); const vault = path.join(E.DIRS.data, 'vault', 'mapping.db');
  if (!fs.existsSync(main)) throw new Error('업무 DB가 없습니다(아직 한 번도 시작하지 않음).');
  sqliteSnapshot(main, path.join(tmp, 'aegis2.db'));
  if (fs.existsSync(vault)) sqliteSnapshot(vault, path.join(tmp, 'vault', 'mapping.db'));
  // 사진은 DB 스냅샷 뒤에 복사(스냅샷이 가리키는 사진은 모두 포함됨). 사진은 덮어쓰지 않는 파일이라 실행 중 복사해도 됩니다.
  const pdir = path.join(E.DIRS.data, 'photos'); for (const rel of walk(pdir)) { const d = path.join(tmp, 'photos', rel); fs.mkdirSync(path.dirname(d), { recursive: true }); fs.copyFileSync(path.join(pdir, rel), d); }
  const files = walk(tmp).sort().map((rel) => ({ path: rel.split(path.sep).join('/'), size: fs.statSync(path.join(tmp, rel)).size, sha256: sha(path.join(tmp, rel)) }));
  const manifest = { kind: 'aegis-v2-server-backup', version: 1, created_at: new Date().toISOString(), reason, keys_included: false, files };
  fs.writeFileSync(path.join(tmp, 'manifest.json'), JSON.stringify(manifest, null, 2), { mode: 0o640 });
  fs.renameSync(tmp, final);
  const all = listBackups(dir); const removed = [];
  if (keep > 0) for (const n of all.slice(0, Math.max(0, all.length - keep))) { fs.rmSync(path.join(dir, n), { recursive: true, force: true }); removed.push(n); }
  return { path: final, files: files.length, bytes: files.reduce((a, f) => a + f.size, 0), removed };
}
function verifyBackup(src) {
  const m = JSON.parse(fs.readFileSync(path.join(src, 'manifest.json'), 'utf8'));
  if (m.kind !== 'aegis-v2-server-backup') throw new Error('AEGIS v2 서버판 백업이 아닙니다.');
  for (const f of m.files) { const p = path.join(src, ...f.path.split('/')); if (!fs.existsSync(p) || sha(p) !== f.sha256) throw new Error('백업 파일이 손상되었거나 빠졌습니다: ' + f.path); }
  return m;
}
// 복원: 서비스를 멈춘 상태에서만. 현재 데이터(DB·WAL·사진)는 data/.before-restore-<시각>/ 로 옮겨 둡니다(삭제하지 않음).
// (도커에서는 data 폴더 자체가 마운트 지점이라 폴더 이름을 바꾸지 않고 안쪽 항목만 옮깁니다.)
function restore(src) {
  src = path.resolve(src); const m = verifyBackup(src);
  const data = E.DIRS.data; fs.mkdirSync(data, { recursive: true });
  const keepDir = path.join(data, '.before-restore-' + stamp()); let moved = 0;
  for (const n of fs.readdirSync(data)) {
    if (n === 'run' || n.startsWith('.before-restore-')) continue;
    if (!moved++) fs.mkdirSync(keepDir, { mode: 0o750 });
    fs.renameSync(path.join(data, n), path.join(keepDir, n));
  }
  fs.mkdirSync(path.join(data, 'vault'), { recursive: true, mode: 0o750 });
  for (const f of m.files) { const d = path.join(data, ...f.path.split('/')); fs.mkdirSync(path.dirname(d), { recursive: true }); fs.copyFileSync(path.join(src, ...f.path.split('/')), d); }
  try { fs.unlinkSync(path.join(data, 'run', 'last_backup_day')); } catch (_) {}
  return { restored: m.files.length, previous: moved ? keepDir : null, created_at: m.created_at };
}
// 키 백업: 백업 폴더·데이터 폴더와 다른 곳(USB, 금고 PC 등)에만. 같은 곳에 두면 백업 하나로 매핑이 풀립니다.
function backupKeys(dest, { force = false } = {}) {
  if (!dest) throw new Error('키를 복사할 폴더를 지정하세요(예: USB 경로).');
  dest = path.resolve(dest);
  if (!force && (inside(dest, E.DIRS.backup) || inside(dest, E.DIRS.data) || inside(dest, E.DIRS.keys))) throw new Error('키 백업 위치가 자료 백업/데이터/키 폴더와 겹칩니다. 다른 매체를 지정하세요.');
  const out = path.join(dest, 'aegis-keys-' + stamp()); fs.mkdirSync(out, { recursive: true, mode: 0o700 });
  const copied = [];
  for (const n of ['secrets.json', 'audit_anchors.jsonl']) { const s = path.join(E.DIRS.keys, n); if (fs.existsSync(s)) { fs.copyFileSync(s, path.join(out, n)); fs.chmodSync(path.join(out, n), 0o600); copied.push(n); } }
  if (!copied.includes('secrets.json')) throw new Error('키 파일이 없습니다.');
  return { path: out, copied };
}
module.exports = { runBackup, verifyBackup, restore, backupKeys, listBackups, stamp, inside };
