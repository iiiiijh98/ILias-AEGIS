'use strict';
// HTTPS 역방향 프록시(Caddy) 설정 파일 생성. 4개 앱은 127.0.0.1에만 있고, 밖에서는 이 프록시의 HTTPS 포트로만 들어옵니다.
//  현장 :443 · 관리 :8443(허용 IP만) · 전광판 :8444 · 매핑 금고 :9444(기본 127.0.0.1 = 서버 콘솔/SSH 터널 전용)
const fs = require('fs'); const path = require('path');
const { buildAllowList } = require('../src/netallow');
const E = require('./server-env');
const env = process.env;
function build() {
  const names = E.list(env.AEGIS_SERVER_NAMES);
  if (!names.length) throw new Error('AEGIS_SERVER_NAMES(서버 주소: 호스트 이름 또는 IP, 쉼표 구분)를 설정하세요.');
  for (const n of names) if (!/^(\[[0-9a-fA-F:]+\]|[A-Za-z0-9.-]+)$/.test(n)) throw new Error('AEGIS_SERVER_NAMES 형식 오류: ' + n);
  const port = (k, d) => { const p = Number(env[k] || d); if (!Number.isInteger(p) || p < 1 || p > 65535) throw new Error(k + ' 포트 값 오류'); return p; };
  const P = { field: port('AEGIS_HTTPS_FIELD_PORT', 443), admin: port('AEGIS_HTTPS_ADMIN_PORT', 8443), board: port('AEGIS_HTTPS_BOARD_PORT', 8444), vault: port('AEGIS_HTTPS_VAULT_PORT', 9444) };
  const up = { field: Number(env.AEGIS2_FIELD_PORT || 3201), admin: Number(env.AEGIS2_ADMIN_PORT || 3202), board: Number(env.AEGIS2_BOARD_PORT || 3203), vault: Number(env.AEGIS2_VAULT_PORT || 3204) };
  const admin = E.adminAllow(); buildAllowList(admin.join(',')); // 형식 검사
  const vault = E.vaultAllow(); buildAllowList(vault.join(','));
  const board = E.list(env.AEGIS_BOARD_ALLOW_CIDRS); if (board.length && !board.includes('*')) buildAllowList(board.join(','));
  const mode = (env.AEGIS_TLS_MODE || 'internal').toLowerCase();
  let tls;
  if (mode === 'internal') tls = 'tls internal';
  else if (mode === 'files') {
    const c = env.AEGIS_TLS_CERT; const k = env.AEGIS_TLS_KEY;
    if (!c || !k) throw new Error('AEGIS_TLS_MODE=files 이면 AEGIS_TLS_CERT, AEGIS_TLS_KEY(인증서·개인키 PEM 경로)를 넣으세요.');
    tls = `tls ${c} ${k}`;
  } else throw new Error('AEGIS_TLS_MODE는 internal 또는 files');
  const vbind = env.AEGIS_VAULT_BIND || '127.0.0.1';
  const storage = env.AEGIS_CADDY_DIR || '/var/lib/aegis-proxy/caddy';
  const site = (p, extra = []) => [...names, ...extra].map((n) => `https://${n}:${p}`).join(', ');
  const deny = (cidrs) => `\t@blocked not remote_ip ${cidrs.join(' ')}\n\trespond @blocked "403 허용되지 않은 네트워크입니다." 403\n`;
  const vaultBody = `\theader {\n\t\tStrict-Transport-Security "max-age=31536000"\n\t\t-Server\n\t}\n${deny(vault)}\treverse_proxy 127.0.0.1:${up.vault}\n`;
  const common = (u) => `\timport aegis_common\n\treverse_proxy 127.0.0.1:${u}\n`;
  return `# AEGIS v2 서버판 — 자동 생성 파일(직접 고치지 말고 aegis.env를 고친 뒤 "aegisctl restart")
{
\tadmin off
\tauto_https disable_redirects
\tskip_install_trust
\tdefault_sni ${names[0]}
\tstorage file_system ${storage}
}
(aegis_common) {
\t${tls}
\theader {
\t\tStrict-Transport-Security "max-age=31536000"
\t\t-Server
\t}
\trequest_body {
\t\tmax_size 20MB
\t}
}
# 현장 앱
${site(P.field)} {
${common(up.field)}}
# 관리 앱 — 허용 IP 대역만(앱에서도 한 번 더 검사)
${site(P.admin)} {
${deny([...admin, '127.0.0.1/32', '::1/128'])}${common(up.admin)}}
# 전광판 — 기기 토큰 페어링(읽기 전용)
${site(P.board)} {
${board.length && !board.includes('*') ? deny([...board, '127.0.0.1/32', '::1/128']) : ''}${common(up.board)}}
# 매핑 금고 — 기본은 서버 자신(127.0.0.1)에서만: https://localhost:${P.vault} (관리자 PC는 SSH 터널, 안내서 참조)
https://localhost:${P.vault}, https://127.0.0.1:${P.vault} {
\tbind ${vbind}
\ttls internal
${vaultBody}}
${vbind === '127.0.0.1' || vbind === '::1' ? '' : `# 매핑 금고 — 별도 지정한 관리자 IP에서 서버 주소로 접속(AEGIS_VAULT_BIND 설정 시)
${site(P.vault)} {
\tbind ${vbind}
\t${tls}
${vaultBody}}
`}`;
}
function write(file = env.AEGIS_CADDYFILE) {
  if (!file) throw new Error('AEGIS_CADDYFILE(생성할 Caddyfile 경로)가 없습니다.');
  const txt = build(); fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file + '.tmp', txt, { mode: 0o644 }); fs.renameSync(file + '.tmp', file); return file;
}
module.exports = { build, write };
if (require.main === module) { try { console.log('Caddyfile 생성: ' + write(process.argv[2])); } catch (e) { console.error('설정 오류:', e.message); process.exit(1); } }
