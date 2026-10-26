'use strict';
// 단위: 저장은 µg 정수(_ug). 입력은 g / mg / µg(질량)만. mL는 저장하지 않습니다(밀도는 매핑 쪽 속성, 2단계 표시 전용).
const { AppError } = require('./util');
const FACTOR = { g: 1e6, mg: 1e3, ug: 1, 'µg': 1 };
function toUg(value, unit = 'g', label = '무게') {
  const u = String(unit || 'g').toLowerCase();
  if (!(u in FACTOR)) throw new AppError(`${label}: 단위는 g, mg, µg만 쓸 수 있습니다.`);
  const s = String(value ?? '').replace(/,/g, '').trim();
  if (s === '') throw new AppError(`${label}을(를) 입력하세요.`);
  if (!/^\d+(\.\d+)?$/.test(s)) throw new AppError(`${label}: 0 이상의 숫자로 입력하세요.`);
  // 부동소수 오차 없이 10진 문자열로 환산
  const [ip, fp = ''] = s.split('.'); const exp = Math.round(Math.log10(FACTOR[u]));
  if (fp.length > exp) { if (/[1-9]/.test(fp.slice(exp))) throw new AppError(`${label}: µg 아래 자릿수는 기록할 수 없습니다.`); }
  const digits = (ip + fp.slice(0, exp).padEnd(exp, '0')).replace(/^0+(?=\d)/, '');
  const n = Number(digits);
  if (!Number.isSafeInteger(n)) throw new AppError(`${label}: 값이 너무 큽니다.`);
  return n;
}
// 표시: µg 정수 → "12.3456 g"(소수 자릿수는 분해능에 맞춤, 기본 4자리)
function fmt(ug, decimals = 4) {
  if (ug === null || ug === undefined || ug === '' || Number.isNaN(Number(ug))) return '-';
  const v = Math.round(Number(ug)); const sign = v < 0 ? '-' : ''; const a = Math.abs(v);
  const g = Math.floor(a / 1e6); const frac = String(a % 1e6).padStart(6, '0').slice(0, decimals);
  return `${sign}${g.toLocaleString('en-US')}${decimals ? '.' + frac : ''} g`;
}
const decimalsFor = (resolutionUg) => { const r = Number(resolutionUg) || 100; let d = 6; let x = r; while (x >= 10 && d > 0) { x /= 10; d--; } return d; };
const fmtSigned = (ug, d) => (Number(ug) > 0 ? '+' : '') + fmt(ug, d);
module.exports = { toUg, fmt, fmtSigned, decimalsFor };
