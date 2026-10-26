'use strict';
// 관리 앱 → Vault: HMAC 서명 요청(메타데이터만). 관리 앱은 매핑 DB·키를 갖지 않습니다.
const crypto = require('crypto');
const sign = (secret, ts, path, actor) => crypto.createHmac('sha256', secret).update(`${ts}|${path}|${actor}`).digest('hex');
function verify(secret, { ts, path, actor, sig }, skewMs = 60000) {
  if (!secret || !ts || !sig || !actor) return false;
  if (Math.abs(Date.now() - Number(ts)) > skewMs) return false;
  const exp = Buffer.from(sign(secret, ts, path, actor)); const got = Buffer.from(String(sig));
  return exp.length === got.length && crypto.timingSafeEqual(exp, got);
}
async function fetchMeta(cfg, actor) {
  if (!cfg.vaultLinkSecret) return { error: 'Vault 연결 비밀값(AEGIS2_VAULT_LINK_SECRET)이 없어 조회를 끕니다.' };
  const ts = String(Date.now()); const path = '/internal/meta';
  try {
    const r = await fetch(cfg.vaultUrl + path, { headers: { 'x-aegis-ts': ts, 'x-aegis-actor': actor, 'x-aegis-sig': sign(cfg.vaultLinkSecret, ts, path, actor) }, signal: AbortSignal.timeout(3000) });
    if (!r.ok) return { error: `Vault 응답 ${r.status}` };
    return await r.json();
  } catch (e) { return { error: 'Vault에 연결할 수 없습니다.' }; }
}
module.exports = { sign, verify, fetchMeta };
