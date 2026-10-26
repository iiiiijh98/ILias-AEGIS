'use strict';
// v2 설정(모두 환경변수). 비밀값은 코드·로그·화면에 출력하지 않습니다.
const path = require('path');
const bool = (v, d) => (v === undefined || v === '' ? d : /^(1|true|yes|on)$/i.test(v));
function loadConfig(over = {}) {
  const env = process.env; const root = path.resolve(__dirname, '..');
  const dataDir = over.dataDir || env.AEGIS2_DATA_DIR || path.join(root, 'data');
  return {
    root, dataDir,
    envLabel: over.envLabel || env.AEGIS2_ENV_LABEL || 'v2 로컬(예시 데이터)',
    host: env.AEGIS2_HOST || '127.0.0.1',
    ports: { field: Number(env.AEGIS2_FIELD_PORT || 3201), admin: Number(env.AEGIS2_ADMIN_PORT || 3202), board: Number(env.AEGIS2_BOARD_PORT || 3203), vault: Number(env.AEGIS2_VAULT_PORT || 3204) },
    // 관리 앱 → Vault 서명 요청용 공유 비밀(HMAC). 없으면 관리 앱의 Vault 메타 조회가 꺼짐.
    vaultLinkSecret: over.vaultLinkSecret !== undefined ? over.vaultLinkSecret : (env.AEGIS2_VAULT_LINK_SECRET || ''),
    vaultUrl: over.vaultUrl || env.AEGIS2_VAULT_URL || `http://127.0.0.1:${Number(env.AEGIS2_VAULT_PORT || 3204)}`,
    vaultAllowCidrs: over.vaultAllowCidrs !== undefined ? over.vaultAllowCidrs : (env.AEGIS2_VAULT_ALLOW_CIDRS || '127.0.0.0/8,::1/128'),
    // 오프라인 첫 실행 설정 코드(시작 스크립트가 PC에서 생성). 사용자가 0명일 때만 /setup 사용 가능
    setupCode: over.setupCode !== undefined ? over.setupCode : (env.AEGIS2_SETUP_CODE || ''),
    anchorFile: over.anchorFile !== undefined ? over.anchorFile : (env.AEGIS2_ANCHOR_FILE || ''),
    // 업무 DB와 매핑 저장소는 서로 다른 DB. Postgres URL이 없으면 각각 별도 SQLite 파일.
    databaseUrl: over.databaseUrl !== undefined ? over.databaseUrl : (env.AEGIS2_DATABASE_URL || ''),
    sqlitePath: over.sqlitePath || env.AEGIS2_SQLITE_PATH || path.join(dataDir, 'aegis2.db'),
    vaultDatabaseUrl: over.vaultDatabaseUrl !== undefined ? over.vaultDatabaseUrl : (env.AEGIS2_VAULT_DATABASE_URL || ''),
    vaultSqlitePath: over.vaultSqlitePath || env.AEGIS2_VAULT_SQLITE_PATH || path.join(dataDir, 'vault', 'mapping.db'),
    // 매핑 암호 키: base64 32바이트(AES-256-GCM). 없으면 매핑 기능만 꺼짐(다른 기능은 동작).
    mappingKey: over.mappingKey !== undefined ? over.mappingKey : (env.AEGIS2_MAPPING_KEY || ''),
    mappingKeyId: env.AEGIS2_MAPPING_KEY_ID || 'k1',
    photoDir: over.photoDir || path.join(dataDir, 'photos'),
    blobToken: over.blobToken !== undefined ? over.blobToken : (env.AEGIS2_BLOB_TOKEN || ''),
    // 관리 앱 허용 IP 대역(기본: 사설망 + 이 PC). '*'는 전체 허용(권장하지 않음)
    adminAllowCidrs: over.adminAllowCidrs !== undefined ? over.adminAllowCidrs : (env.AEGIS2_ADMIN_ALLOW_CIDRS || '10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8,::1/128'),
    boardAllowCidrs: over.boardAllowCidrs !== undefined ? over.boardAllowCidrs : (env.AEGIS2_BOARD_ALLOW_CIDRS || '*'),
    cookieSecure: over.cookieSecure !== undefined ? over.cookieSecure : bool(env.AEGIS2_COOKIE_SECURE, false),
    trustProxy: over.trustProxy !== undefined ? over.trustProxy : bool(env.AEGIS2_TRUST_PROXY, false),
    initAdminPassword: over.initAdminPassword !== undefined ? over.initAdminPassword : (env.AEGIS2_INIT_ADMIN_PASSWORD || ''),
    bcryptRounds: Number(over.bcryptRounds || env.AEGIS2_BCRYPT_ROUNDS || 12),
    maxUploadBytes: 4 * 1024 * 1024,
    session: { field: { idleMin: 10, maxHours: 10 }, admin: { idleMin: 15, maxHours: 8 } }, // 〔예시〕
  };
}
module.exports = { loadConfig };
