'use strict';
// RFC 6238 TOTP (SHA-1, 30초, 6자리) — 외부 라이브러리 없이 구현
const crypto = require('crypto');
const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function b32encode(buf) { let bits = 0, val = 0, out = ''; for (const b of buf) { val = (val << 8) | b; bits += 8; while (bits >= 5) { out += A[(val >>> (bits - 5)) & 31]; bits -= 5; } } if (bits > 0) out += A[(val << (5 - bits)) & 31]; return out; }
function b32decode(s) { s = s.replace(/=+$/, '').toUpperCase().replace(/\s/g, ''); let bits = 0, val = 0; const out = []; for (const c of s) { const i = A.indexOf(c); if (i < 0) throw new Error('bad base32'); val = (val << 5) | i; bits += 5; if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8; } } return Buffer.from(out); }
function hotp(secret, counter) {
  const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(counter));
  const h = crypto.createHmac('sha1', b32decode(secret)).update(b).digest();
  const o = h[h.length - 1] & 15;
  return String(((h.readUInt32BE(o) & 0x7fffffff) % 1e6)).padStart(6, '0');
}
const generateSecret = () => b32encode(crypto.randomBytes(20));
function totp(secret, t = Date.now()) { return hotp(secret, Math.floor(t / 30000)); }
function verify(secret, code, t = Date.now()) {
  code = String(code || '').replace(/\s/g, ''); if (!/^\d{6}$/.test(code)) return false;
  const c = Math.floor(t / 30000);
  for (const d of [-1, 0, 1]) { if (crypto.timingSafeEqual(Buffer.from(hotp(secret, c + d)), Buffer.from(code))) return true; }
  return false;
}
module.exports = { generateSecret, totp, verify, b32encode, b32decode };
