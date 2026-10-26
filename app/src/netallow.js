'use strict';
// 허용 IP 대역: "10.0.0.0/8,192.168.1.0/24,127.0.0.1,::1/128" 형식. '*' 이면 전체 허용(권장하지 않음)
const net = require('net');
function norm(ip) { if (!ip) return ''; const m = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip); return m ? m[1] : ip; }
function buildAllowList(spec) {
  const list = new net.BlockList(); const items = String(spec || '').split(',').map((s) => s.trim()).filter(Boolean);
  if (items.includes('*')) return { check: () => true, items };
  for (const it of items) {
    const [addr, bits] = it.split('/'); const fam = net.isIP(addr);
    if (!fam) throw new Error('AEGIS_ALLOW_CIDRS 형식 오류: ' + it);
    const type = fam === 6 ? 'ipv6' : 'ipv4';
    if (bits === undefined) list.addAddress(addr, type); else list.addSubnet(addr, Number(bits), type);
  }
  return { items, check: (ip) => { const a = norm(ip); const fam = net.isIP(a); if (!fam) return false; return list.check(a, fam === 6 ? 'ipv6' : 'ipv4'); } };
}
module.exports = { buildAllowList, norm };
