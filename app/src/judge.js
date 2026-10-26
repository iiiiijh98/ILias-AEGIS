'use strict';
// 칭량 판정 공통 모듈(유일한 판정식). 단위 µg 정수. 〔예시〕 기본값은 모두 설정에서 바꿉니다.
// 측정 잡음:  σ_D = √( m·(s² + d²/12) + σ_tare² )
//   m = 차이 계산에 들어간 판독 횟수, s = 저울 반복성(중간 정밀도), d = 분해능
// 한쪽 검정 두 개:
//   늘어남: 차이 > z_up·σ_D            → 이상(재계량 없이 즉시 잠금)
//   누락:   차이 < −max(z_anom·σ_D, MDL) → 이상(같은 입회자 1회 재계량 후에도 같으면 잠금)
//           차이 < −z_warn·σ_D           → 경고(사유 필수)
//   그 밖                               → 정상
// 비례항(pct·기준량)은 기본 0. 흡습·증발 근거 데이터가 있는 코드만 따로 설정(2단계).
const DEFAULTS = { z_warn: 3, z_anom: 4, z_up: 3, mdl_ug: 0, pct: 0 };
function sigmaD({ m, sUg, dUg, sigmaTareUg = 0 }) {
  if (sUg === null || sUg === undefined || sUg === '' || !(Number(sUg) > 0)) throw Object.assign(new Error('저울 반복성(s)이 등록되지 않아 판정할 수 없습니다.'), { code: 'NO_REPEATABILITY', status: 409, expose: true });
  const s = Number(sUg), d = Number(dUg) || 0, mm = Math.max(1, Number(m) || 1);
  return Math.sqrt(mm * (s * s + (d * d) / 12) + Number(sigmaTareUg || 0) ** 2);
}
function judge({ measuredUg, expectedUg, sigmaUg, baseUg = 0, opts = {} }) {
  const o = { ...DEFAULTS, ...Object.fromEntries(Object.entries(opts).filter(([, v]) => v !== undefined && v !== null && v !== '')) };
  const diff = Number(measuredUg) - Number(expectedUg); const sg = Number(sigmaUg);
  const prop = Math.abs(Number(baseUg) || 0) * Number(o.pct) / 100;
  const up = Number(o.z_up) * sg + prop;
  const warn = Number(o.z_warn) * sg + prop;
  const anom = Math.max(Number(o.z_anom) * sg + prop, Number(o.mdl_ug), warn);
  let result, reason, kind;
  if (Number(expectedUg) < 0) { result = 'anomaly'; kind = 'inconsistent'; reason = '계량된 사용량 합이 반출량보다 큼'; }
  else if (diff > up) { result = 'anomaly'; kind = 'increase'; reason = '무게 증가(희석·대체 의심)'; }
  else if (diff < -anom) { result = 'anomaly'; kind = 'loss'; reason = '누락(이상 기준 초과 감소)'; }
  else if (diff < -warn) { result = 'warning'; kind = 'loss'; reason = '감소(경고 기준 초과)'; }
  else { result = 'normal'; kind = 'ok'; reason = '측정 잡음 범위'; }
  return { diffUg: diff, sigmaUg: Math.round(sg), thresholds: { up: Math.round(up), warn: Math.round(warn), anom: Math.round(anom) }, result, kind, reason, immediateLock: result === 'anomaly' && kind !== 'loss' };
}
// 완결 검사: 반출량 = Σ사용(입회 계량) + 반납 실측  → 예상 반납 = 반출 − Σ사용
const expectedReturn = ({ outUg, usedUg = 0 }) => Number(outUg) - Number(usedUg);
// 블라인드 판독 일치: |a−b| ≤ max(d, k·s) 〔예시: k=2〕. 같은 화면 같은 저울 값을 따로 읽는 것이므로 분해능 수준만 허용
function readingsMatch(aUg, bUg, { dUg = 1, sUg = 0, k = 2 } = {}) { return Math.abs(Number(aUg) - Number(bUg)) <= Math.max(Number(dUg) || 1, k * (Number(sUg) || 0)); }
const LABEL = { normal: '정상', warning: '경고', anomaly: '이상' };
const FIELD_LABEL = { normal: '정상', warning: '확인 필요', anomaly: '보류' }; // 현장 화면 표시(아폴론 U3)
module.exports = { DEFAULTS, sigmaD, judge, expectedReturn, readingsMatch, LABEL, FIELD_LABEL };
