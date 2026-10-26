'use strict';
// 오프라인 PC(Windows) 실행 환경: 데이터·키 폴더, 비밀값(PC에서 처음 실행할 때 생성), 127.0.0.1 전용.
// 비밀값은 화면·로그에 출력하지 않습니다. 패키지(zip)에는 비밀값이 들어 있지 않습니다.
const fs = require('fs'); const path = require('path'); const crypto = require('crypto');
const HOME = path.resolve(process.env.AEGIS2_HOME || path.join(__dirname, '..', '..'));
const DIRS = { home: HOME, data: path.join(HOME, 'data'), keys: path.join(HOME, 'keys'), run: path.join(HOME, 'data', 'run') };
const SECRETS = path.join(DIRS.keys, 'secrets.json');
function restrictAcl(p) {
  if (process.platform !== 'win32') { try { fs.chmodSync(p, 0o700); } catch (_) {} return; }
  try { require('child_process').execFileSync('icacls', [p, '/inheritance:r', '/grant:r', `${process.env.USERNAME}:(OI)(CI)F`], { stdio: 'ignore' }); } catch (_) { /* 권한 제한 실패는 안내서의 수동 절차로 */ }
}
function loadSecrets({ create = true } = {}) {
  if (!fs.existsSync(SECRETS)) {
    if (!create) throw new Error('키 파일이 없습니다. 먼저 AEGIS_시작.bat을 한 번 실행하세요.');
    fs.mkdirSync(DIRS.keys, { recursive: true }); restrictAcl(DIRS.keys);
    const s = { mappingKey: crypto.randomBytes(32).toString('base64'), vaultLinkSecret: crypto.randomBytes(32).toString('hex'), created_at: new Date().toISOString() };
    fs.writeFileSync(SECRETS, JSON.stringify(s, null, 2), { mode: 0o600, flag: 'wx' });
    return { ...s, created: true };
  }
  const s = JSON.parse(fs.readFileSync(SECRETS, 'utf8'));
  if (!s.mappingKey || Buffer.from(s.mappingKey, 'base64').length !== 32 || !s.vaultLinkSecret) throw new Error('키 파일 형식이 올바르지 않습니다(keys\\secrets.json).');
  return s;
}
function applyEnv(opts = {}) {
  const s = loadSecrets(opts);
  for (const k of ['VERCEL', 'AWS_LAMBDA_FUNCTION_NAME', 'AEGIS2_DATABASE_URL', 'AEGIS2_VAULT_DATABASE_URL', 'AEGIS2_BLOB_TOKEN', 'AEGIS2_INIT_ADMIN_PASSWORD']) delete process.env[k];
  Object.assign(process.env, {
    AEGIS_SQLITE_DRIVER: 'node', AEGIS2_DATA_DIR: DIRS.data, AEGIS2_HOST: '127.0.0.1',
    AEGIS2_ADMIN_ALLOW_CIDRS: '127.0.0.0/8,::1/128', AEGIS2_BOARD_ALLOW_CIDRS: '127.0.0.0/8,::1/128', AEGIS2_VAULT_ALLOW_CIDRS: '127.0.0.0/8,::1/128',
    AEGIS2_COOKIE_SECURE: '0', AEGIS2_TRUST_PROXY: '0', AEGIS2_MAPPING_KEY: s.mappingKey, AEGIS2_VAULT_LINK_SECRET: s.vaultLinkSecret,
    AEGIS2_ANCHOR_FILE: path.join(DIRS.keys, 'audit_anchors.jsonl'), AEGIS2_ENV_LABEL: '오프라인 PC 장부(실데이터) · 클라우드와 별개',
  });
  delete process.env.AEGIS2_VAULT_URL;
  return { created: !!s.created };
}
module.exports = { HOME, DIRS, SECRETS, applyEnv, loadSecrets };
