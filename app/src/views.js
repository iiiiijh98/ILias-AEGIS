'use strict';
// 정식 명칭(2026-10-24 확정)
const FULL_NAME = 'ILias AEGIS — Audited Evidence Guarding & Inventory System'; const SUBTITLE = '시료 보관·반출 관리 시스템';
const ABOUT = 'ILias AEGIS — Audited Evidence Guarding &amp; Inventory System · 시료 보관·반출 관리 시스템';
const { esc, kst } = require('./util');
const { fmt } = require('./units');
const { ROLES, rolesOf } = require('./perm');
const NOTICE = '사내 보조 기록입니다. 법정 장부와 법정 보고를 대신하지 않습니다.';
function head(title, extra = '') {
  return `<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>${esc(title)} · AEGIS v2</title><link rel="stylesheet" href="/static/app.css"><style>
.envbar{background:#7c2d12;color:#fff;text-align:center;font-size:12px;padding:3px}.blind{background:#fef3c7;border:1px solid #f59e0b;padding:8px;border-radius:8px;margin:8px 0}
.j-normal{color:#047857;font-weight:700}.j-warning{color:#b45309;font-weight:700}.j-anomaly{color:#b91c1c;font-weight:700}.kpad input{font-size:22px;min-height:56px}
.wm{position:fixed;inset:0;pointer-events:none;opacity:.10;font-size:22px;color:#b91c1c;transform:rotate(-24deg);display:flex;flex-wrap:wrap;gap:60px;padding:40px;z-index:99}
.mask .secret{filter:blur(8px)}.lvl-err{color:#b91c1c}.lvl-warn{color:#b45309}.lvl-overdue{color:#fff;background:#b91c1c;padding:0 4px}
</style>${extra}</head>`;
}
const csrf = (req) => `<input type="hidden" name="_csrf" value="${esc(req.session ? req.session.csrf : '')}">`;
const flashBox = (f) => (f ? `<div class="flash ${esc(f.type || 'info')}">${esc(f.msg)}</div>` : '');
function page(req, { title, body, nav = [] }) {
  const u = req.user; const appName = { field: '현장 앱', admin: '관리 앱', vault: '매핑 금고(Vault)' }[req.appName] || '';
  return head(title) + `<body><div class="envbar">${esc(req.cfg.envLabel)} · ${esc(appName)}</div><div class="top"><img class="lg" src="/static/ilias_ai_logo.png" alt="ILias AI"><div class="pd"><b>AEGIS v2</b><small>${esc(appName)}</small></div>
  <nav class="nav">${nav.map(([h, l]) => `<a href="${h}" class="${req.path === h || (h !== '/' && req.path.startsWith(h)) ? 'on' : ''}">${l}</a>`).join('')}</nav><div class="sp"></div>
  ${u ? `<span class="chip">${esc(u.display_name)} · ${esc(rolesOf(u).map((r) => ROLES[r]).join(', '))}</span><form method="post" action="/logout" style="display:inline">${csrf(req)}<button class="o s">로그아웃</button></form>` : ''}</div>
  <main class="main">${flashBox(req.flash)}${body}</main><div class="foot"><span class="about">${ABOUT}</span><br>AEGIS v2 — 품목은 코드로만 표시 · 시각은 KST · ${NOTICE}</div><script src="/static/app.js"></script></body></html>`;
}
const badge = (t, k = 'mute') => `<span class="badge b-${k}">${esc(t)}</span>`;
const table = (headers, rows) => `<table><tr>${headers.map((h) => `<th>${esc(h)}</th>`).join('')}</tr>${rows.length ? rows.map((r) => `<tr>${r.map((c) => `<td>${c}</td>`).join('')}</tr>`).join('') : `<tr><td colspan="${headers.length}" class="muted">없음</td></tr>`}</table>`;
const pw = (label = '재인증 — 내 비밀번호') => `<label>${esc(label)}</label><input type="password" name="password" autocomplete="current-password" required>`;
const photo = (name = 'photo', label = '저울 표시창 사진(카메라)') => `<label>${esc(label)}</label><input type="file" name="${name}" accept="image/*" capture="environment" data-shrink required> <span class="pv small muted"></span>`;
const unitSel = () => `<label>단위</label><select name="unit"><option value="g">g</option><option value="mg">mg</option></select>`;
const num = (name, label) => `<label>${esc(label)}</label><input name="${name}" inputmode="decimal" autocomplete="off" required>`;
const loginPage = (req, { title, sub, action = '/login', extra = '' }) => head(title) + `<body><div class="envbar">${esc(req.cfg.envLabel)}</div><div class="login"><div class="card" style="max-width:420px;margin:60px auto"><img src="/static/ilias_ai_logo.png" alt="ILias AI" style="height:30px"><h1>${esc(title)}</h1><p class="muted">${esc(sub)}</p>${flashBox(req.flash)}
<form class="f" method="post" action="${action}">${csrf(req)}${extra || `<label>아이디</label><input name="username" autocomplete="username" required><label>비밀번호</label><input type="password" name="password" autocomplete="current-password" required>`}<button>확인</button></form><p class="small muted">${NOTICE}</p><p class="small muted about">${ABOUT}</p></div></div></body></html>`;
module.exports = { FULL_NAME, SUBTITLE, ABOUT, head, page, badge, table, pw, photo, unitSel, num, csrf, loginPage, esc, kst, fmt, NOTICE };
