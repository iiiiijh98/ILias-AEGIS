'use strict';
// 저장소 어댑터: 같은 SQL($1,$2… 자리표시자)을 SQLite(로컬·테스트)와 Postgres(운영)에서 실행합니다.
// v2: 스키마를 인자로 받아 업무 DB와 매핑 저장소(별도 DB)에 같은 어댑터를 씁니다.

function toSqlite(sql, params, nz = norm) {
  const out = [];
  const s = sql.replace(/\$(\d+)/g, (_, n) => { out.push(nz(params[Number(n) - 1])); return '?'; });
  return [s, out];
}
function norm(v) { if (v === undefined) return null; if (typeof v === 'boolean') return v ? 1 : 0; return v; }
// node:sqlite: 정수는 BigInt로 묶어 INTEGER로 정확히 저장(숫자를 REAL로 묶는 경우 대비)
function normNode(v) { v = norm(v); return typeof v === 'number' && Number.isSafeInteger(v) ? BigInt(v) : v; }

// node:sqlite(Node 22.13+/24 내장) 드라이버 — 네이티브 모듈 없이 동작(오프라인 설치판 기본)
function nodeSqliteAdapter(file, S) {
  const { DatabaseSync } = require('node:sqlite');
  const fs = require('fs'); const path = require('path');
  if (file !== ':memory:') fs.mkdirSync(path.dirname(file), { recursive: true });
  const db = new DatabaseSync(file);
  db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;');
  const isReader = (sql) => /^\s*(SELECT|WITH|PRAGMA)\b/i.test(sql) || /\bRETURNING\b/i.test(sql);
  const plain = (r) => (r ? { ...r } : r);
  const exec = {
    all: async (sql, p = []) => { const [s, a] = toSqlite(sql, p, normNode); return db.prepare(s).all(...a).map(plain); },
    get: async (sql, p = []) => { const [s, a] = toSqlite(sql, p, normNode); const st = db.prepare(s); if (isReader(s)) return plain(st.get(...a)); st.run(...a); return undefined; },
    run: async (sql, p = []) => { const [s, a] = toSqlite(sql, p, normNode); const st = db.prepare(s); if (isReader(s)) { const rows = st.all(...a).map(plain); return { changes: rows.length, rows }; } const r = st.run(...a); return { changes: Number(r.changes), rows: [] }; },
    lockAudit: async () => {},
  };
  let queue = Promise.resolve();
  function serial(fn) { const r = queue.then(fn, fn); queue = r.catch(() => {}); return r; }
  return {
    dialect: 'sqlite', driver: 'node:sqlite',
    all: (s, p) => serial(() => exec.all(s, p)), get: (s, p) => serial(() => exec.get(s, p)), run: (s, p) => serial(() => exec.run(s, p)),
    tx: (fn) => serial(async () => { db.exec('BEGIN IMMEDIATE'); try { const r = await fn(exec); db.exec('COMMIT'); return r; } catch (e) { db.exec('ROLLBACK'); throw e; } }),
    migrate: async () => { db.exec(ddl('sqlite', S)); db.exec(S.SQLITE_TRIGGERS); },
    backupTo: async (dest) => serial(async () => { db.exec(`VACUUM INTO '${String(dest).replace(/'/g, "''")}'`); }),
    close: async () => db.close(),
    raw: db,
  };
}

function sqliteAdapter(file, S) {
  const Database = require('better-sqlite3');
  const fs = require('fs'); const path = require('path');
  if (file !== ':memory:') fs.mkdirSync(path.dirname(file), { recursive: true });
  const db = new Database(file);
  db.pragma('journal_mode = WAL'); db.pragma('foreign_keys = ON');
  const exec = {
    all: async (sql, p = []) => { const [s, a] = toSqlite(sql, p); return db.prepare(s).all(...a); },
    get: async (sql, p = []) => { const [s, a] = toSqlite(sql, p); const st = db.prepare(s); return st.reader ? st.get(...a) : (st.run(...a), undefined); },
    run: async (sql, p = []) => { const [s, a] = toSqlite(sql, p); const st = db.prepare(s); if (st.reader) { const rows = st.all(...a); return { changes: rows.length, rows }; } const r = st.run(...a); return { changes: r.changes, rows: [] }; },
    lockAudit: async () => {},
  };
  let queue = Promise.resolve();
  function serial(fn) { const r = queue.then(fn, fn); queue = r.catch(() => {}); return r; }
  return {
    dialect: 'sqlite',
    all: (s, p) => serial(() => exec.all(s, p)),
    get: (s, p) => serial(() => exec.get(s, p)),
    run: (s, p) => serial(() => exec.run(s, p)),
    tx: (fn) => serial(async () => {
      db.exec('BEGIN IMMEDIATE');
      try { const r = await fn(exec); db.exec('COMMIT'); return r; } catch (e) { db.exec('ROLLBACK'); throw e; }
    }),
    migrate: async () => { db.exec(ddl('sqlite', S)); db.exec(S.SQLITE_TRIGGERS); },
    backupTo: async (dest) => serial(async () => { await db.backup(dest); }),
    close: async () => db.close(),
    raw: db, driver: 'better-sqlite3',
  };
}

function pgAdapter(url, S) {
  const { Pool, types } = require('pg');
  types.setTypeParser(20, (v) => Number(v)); // BIGINT → number (집계용)
  types.setTypeParser(1700, (v) => Number(v));
  const pool = new Pool({ connectionString: url, max: 3, ssl: /localhost|127\.0\.0\.1|[?&]host=%2F|[?&]sslmode=disable/.test(url) ? false : { rejectUnauthorized: true } }); // 사내 서버판: 유닉스 소켓·내부 도커망은 TLS 없음, 클라우드는 검증된 TLS 필수
  const mk = (q) => ({
    all: async (s, p = []) => (await q(s, p.map(norm))).rows,
    get: async (s, p = []) => (await q(s, p.map(norm))).rows[0],
    run: async (s, p = []) => { const r = await q(s, p.map(norm)); return { changes: r.rowCount, rows: r.rows }; },
    lockAudit: async () => { await q('SELECT pg_advisory_xact_lock(7342101)', []); },
  });
  const base = mk((s, p) => pool.query(s, p));
  return {
    dialect: 'pg', ...base,
    tx: async (fn) => {
      const c = await pool.connect();
      try { await c.query('BEGIN'); const r = await fn(mk((s, p) => c.query(s, p))); await c.query('COMMIT'); return r; }
      catch (e) { try { await c.query('ROLLBACK'); } catch (_) {} throw e; }
      finally { c.release(); }
    },
    migrate: async () => {
      const c = await pool.connect();
      try { await c.query('SELECT pg_advisory_lock(' + (S.LOCK || 7342100) + ')'); await c.query(ddl('pg', S)); await c.query(S.PG_TRIGGERS); }
      finally { try { await c.query('SELECT pg_advisory_unlock(' + (S.LOCK || 7342100) + ')'); } catch (_) {} c.release(); }
    },
    close: async () => pool.end(),
  };
}

function ddl(d, S) {
  return S.SCHEMA_TABLES
    .replace(/\{\{ID\}\}/g, d === 'pg' ? 'INTEGER GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY' : 'INTEGER PRIMARY KEY AUTOINCREMENT')
    .replace(/\{\{REAL\}\}/g, d === 'pg' ? 'DOUBLE PRECISION' : 'REAL')
    .replace(/\{\{BIG\}\}/g, d === 'pg' ? 'BIGINT' : 'INTEGER');
}

// url(Postgres) 또는 sqlitePath 중 하나. S = { SCHEMA_TABLES, SQLITE_TRIGGERS, PG_TRIGGERS, LOCK }
function createDb({ url, sqlitePath }, S) {
  if (url) return pgAdapter(url, S);
  const drv = process.env.AEGIS_SQLITE_DRIVER || 'auto';
  if (drv === 'node') return nodeSqliteAdapter(sqlitePath, S);
  if (drv === 'better') return sqliteAdapter(sqlitePath, S);
  try { require.resolve('better-sqlite3'); return sqliteAdapter(sqlitePath, S); } catch (_) { return nodeSqliteAdapter(sqlitePath, S); }
}
module.exports = { createDb };
