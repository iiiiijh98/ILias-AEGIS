'use strict';
// 저울 어댑터 인터페이스. 1단계는 manual(사람 입력 + 저울 표시창 사진)만 운영에 씁니다.
// 2단계: USB/RS-232(Web Serial 또는 저울 옆 중계 PC)·BLE 어댑터가 같은 형태의 판독 결과를 돌려줍니다.
//   reading = { grossUg, stable, unit, raw, method }
// 서버는 method !== 'manual' 이면 raw(저울 원문)를 weighings.raw에 그대로 보존합니다.
const { toUg } = require('../units');
class ScaleAdapter {
  constructor(scale) { this.scale = scale; }
  get method() { return 'abstract'; }
  async read() { throw new Error('not implemented'); }
}
class ManualAdapter extends ScaleAdapter {
  get method() { return 'manual'; }
  async read({ value, unit }) { return { grossUg: toUg(value, unit, '계량값'), stable: true, unit, raw: null, method: 'manual' }; }
}
// 시리얼 저울 출력 한 줄 해석. 흔한 형식 예: "ST,GS,+  12.345 g" (ST=안정, US=불안정), "+ 12345 mg", "12.345g"
// 실제 기종 형식은 저울 선정 후 확정 【확인 필요】
function parseSerialLine(line) {
  const s = String(line || '').trim();
  const m = /^(?:(ST|US|OL)\s*,\s*(?:GS|NT|TR)\s*,\s*)?([+-])?\s*(\d+(?:\.\d+)?)\s*(mg|g)\s*$/i.exec(s);
  if (!m) return null;
  const status = (m[1] || 'ST').toUpperCase();
  if (status === 'OL') return null;
  if (m[2] === '-') return null; // 음수 판독은 채택하지 않음(영점 이상)
  return { grossUg: toUg(m[3], m[4].toLowerCase()), stable: status === 'ST', unit: m[4].toLowerCase(), raw: s, method: 'serial' };
}
// 연속 판독 중 안정 표시가 n회 연속 같은 값일 때만 채택
function pickStable(readings, n = 3) {
  let run = 0; let last = null;
  for (const r of readings) {
    if (!r || !r.stable) { run = 0; last = null; continue; }
    if (last && last.grossUg === r.grossUg) run++; else run = 1;
    last = r; if (run >= n) return r;
  }
  return null;
}
class SerialAdapter extends ScaleAdapter {
  get method() { return 'serial'; }
  // lines: 중계 프로그램이 넘겨준 판독 줄 배열
  async read({ lines }) { const r = pickStable((lines || []).map(parseSerialLine)); if (!r) throw new Error('안정된 판독값이 없습니다.'); return r; }
}
function adapterFor(scale) { return (scale && scale.adapter === 'serial') ? new SerialAdapter(scale) : new ManualAdapter(scale); }
module.exports = { ScaleAdapter, ManualAdapter, SerialAdapter, parseSerialLine, pickStable, adapterFor };
