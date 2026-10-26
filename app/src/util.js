'use strict';
const crypto = require('crypto');
let clock = () => Date.now();
const nowIso = () => new Date(clock()).toISOString();
// 데모 시드 전용: 시계를 과거로 돌려 이력을 만듭니다(운영 코드에서는 호출하지 않음)
function setClock(fn) { clock = fn || (() => Date.now()); }
const KST = 'Asia/Seoul';
function kst(iso, withSec = false) {
  if (!iso) return '';
  const d = new Date(iso); if (isNaN(d)) return '';
  const p = Object.fromEntries(new Intl.DateTimeFormat('en-CA', { timeZone: KST, year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23' }).formatToParts(d).map((x) => [x.type, x.value]));
  return `${p.year}-${p.month}-${p.day} ${p.hour}:${p.minute}${withSec ? ':' + p.second : ''}`;
}
function kstDate(iso) { return kst(iso || nowIso()).slice(0, 10); }
// KST 날짜(YYYY-MM-DD) → 그날 00:00 KST의 UTC ISO
function kstDayStartIso(day) { return new Date(`${day}T00:00:00+09:00`).toISOString(); }
function addDays(day, n) { const d = new Date(`${day}T00:00:00+09:00`); d.setUTCDate(d.getUTCDate() + n); return kstDate(d.toISOString()); }
function esc(v) { return String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }
const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');
const randomToken = (n = 32) => crypto.randomBytes(n).toString('base64url');
function num(v) { if (v === undefined || v === null || String(v).trim() === '') return null; const n = Number(String(v).replace(/,/g, '')); return Number.isFinite(n) ? n : NaN; }
const g = (v, d = 3) => (v === null || v === undefined || Number.isNaN(v)) ? '-' : Number(v).toFixed(d);
function canonical(o) {
  if (o === null || typeof o !== 'object') return JSON.stringify(o ?? null);
  if (Array.isArray(o)) return '[' + o.map(canonical).join(',') + ']';
  return '{' + Object.keys(o).sort().map((k) => JSON.stringify(k) + ':' + canonical(o[k])).join(',') + '}';
}
class AppError extends Error { constructor(msg, status = 400) { super(msg); this.status = status; this.expose = true; } }
module.exports = { setClock, nowIso, kst, kstDate, kstDayStartIso, addDays, esc, sha256, randomToken, num, g, canonical, AppError };
