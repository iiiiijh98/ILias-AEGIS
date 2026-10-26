'use strict';
// 품목 코드 형식: SMP-###-C (C = 숫자부의 Luhn 체크 숫자). 오타를 잡기 위한 장치이며 의미는 담지 않습니다.
function luhnDigit(digits) {
  let sum = 0; const d = String(digits).split('').reverse().map(Number);
  for (let i = 0; i < d.length; i++) { let x = d[i]; if (i % 2 === 0) { x *= 2; if (x > 9) x -= 9; } sum += x; }
  return (10 - (sum % 10)) % 10;
}
function makeCode(n) { const num = String(n).padStart(3, '0'); return `SMP-${num}-${luhnDigit(num)}`; }
function isValidCode(code) {
  const m = /^SMP-(\d{3,6})-(\d)$/.exec(String(code || '').trim().toUpperCase());
  return !!m && luhnDigit(m[1]) === Number(m[2]);
}
const codeNumber = (code) => { const m = /^SMP-(\d{3,6})-\d$/.exec(code); return m ? Number(m[1]) : 0; };
// 중립 분류만 허용(자유 입력 금지 → 분류 문구로 실물 추정 방지)
const CATEGORIES = ['CAT-A', 'CAT-B', 'CAT-C', 'CAT-D'];
const FORMS = { solid: '고체', liquid: '액체', solution: '용액' };
module.exports = { luhnDigit, makeCode, isValidCode, codeNumber, CATEGORIES, FORMS };
