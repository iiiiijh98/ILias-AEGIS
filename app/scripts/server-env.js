'use strict';
// 회사 서버판 실행 환경. 설정은 /etc/aegis/aegis.env(리눅스) 또는 .env(도커)의 AEGIS_* 값으로 받습니다.
// 비밀값(매핑 키·Vault 연결 비밀)은 서버에서 처음 설치할 때 keys 폴더에 생성되며, 패키지·로그·화면에 나오지 않습니다.
const fs = require('fs'); const path = require('path'); const crypto = require('crypto');
const env = process.env;
const DIRS = {
  data: path.resolve(env.AEGIS_DATA_DIR || '/var/lib/aegis/data'),
  keys: path.resolve(env.AEGIS_KEYS_DIR || '/var/lib/aegis/keys'),
  backup: path.resolve(env.AEGIS_BACKUP_DIR || '/var/backups/aegis'),
};
DIRS.run = path.join(DIRS.data, 'run');
const SECRETS = path.join(DIRS.keys, 'secrets.json');
const SETUP_FILE = path.join(DIRS.keys, 'setup_code.txt');
const LOOP = '127.0.0.0/8,::1/128';
const list = (v) => String(v || '').split(/[\s,]+/).map((s) => s.trim()).filter(Boolean);
function loadSecrets({ create = false } = {}) {
  if (!fs.existsSync(SECRETS)) {
    if (!create) throw new Error(`키 파일이 없습니다(${SECRETS}). 설치 스크립트 또는 "aegisctl init"을 먼저 실행하세요.`);
    fs.mkdirSync(DIRS.keys, { recursive: true, mode: 0o700 }); try { fs.chmodSync(DIRS.keys, 0o700); } catch (_) {}
    const s = { mappingKey: crypto.randomBytes(32).toString('base64'), vaultLinkSecret: crypto.randomBytes(32).toString('hex'), created_at: new Date().toISOString(), edition: 'server' };
    fs.writeFileSync(SECRETS, JSON.stringify(s, null, 2), { mode: 0o600, flag: 'wx' });
    return { ...s, created: true };
  }
  const s = JSON.parse(fs.readFileSync(SECRETS, 'utf8'));
  if (!s.mappingKey || Buffer.from(s.mappingKey, 'base64').length !== 32 || !s.vaultLinkSecret) throw new Error('키 파일 형식이 올바르지 않습니다(secrets.json).');
  return s;
}
function adminAllow() {
  const a = list(env.AEGIS_ADMIN_ALLOW_CIDRS);
  if (!a.length) throw new Error('AEGIS_ADMIN_ALLOW_CIDRS(관리 앱 허용 IP 대역)를 설정 파일에 넣으세요. 예: 192.168.0.0/24');
  if (a.includes('*')) throw new Error('서버판에서는 관리 앱 전체 허용(*)을 쓸 수 없습니다.');
  return a;
}
function vaultAllow() { return [...LOOP.split(','), ...list(env.AEGIS_VAULT_ALLOW_CIDRS)]; }
function applyEnv(opts = {}) {
  const s = loadSecrets(opts);
  for (const k of ['VERCEL', 'AWS_LAMBDA_FUNCTION_NAME', 'AEGIS2_DATABASE_URL', 'AEGIS2_VAULT_DATABASE_URL', 'AEGIS2_BLOB_TOKEN', 'AEGIS2_INIT_ADMIN_PASSWORD', 'AEGIS2_VAULT_URL', 'AEGIS2_SQLITE_PATH', 'AEGIS2_VAULT_SQLITE_PATH']) delete env[k];
  Object.assign(env, {
    AEGIS2_EDITION: 'server', AEGIS_SQLITE_DRIVER: 'node', AEGIS2_DATA_DIR: DIRS.data, AEGIS2_HOST: '127.0.0.1', // 4개 앱은 서버 안(127.0.0.1)에서만 대기, 밖은 HTTPS 프록시
    AEGIS2_TRUST_PROXY: '1', AEGIS2_COOKIE_SECURE: '1',
    AEGIS2_ADMIN_ALLOW_CIDRS: [...adminAllow(), ...LOOP.split(',')].join(','),
    AEGIS2_BOARD_ALLOW_CIDRS: list(env.AEGIS_BOARD_ALLOW_CIDRS).join(',') || '*',
    AEGIS2_VAULT_ALLOW_CIDRS: vaultAllow().join(','),
    AEGIS2_MAPPING_KEY: s.mappingKey, AEGIS2_VAULT_LINK_SECRET: s.vaultLinkSecret,
    AEGIS2_ANCHOR_FILE: path.join(DIRS.keys, 'audit_anchors.jsonl'),
    AEGIS2_ENV_LABEL: env.AEGIS_ENV_LABEL || '회사 서버 장부(실데이터) · 클라우드·오프라인 PC와 별개',
  });
  return { created: !!s.created };
}
module.exports = { DIRS, SECRETS, SETUP_FILE, applyEnv, loadSecrets, adminAllow, vaultAllow, list };
