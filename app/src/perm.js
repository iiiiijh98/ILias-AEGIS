'use strict';
// 역할·권한 (서버에서 강제). 권한마다 쓸 수 있는 앱(field/admin)이 정해져 있어, 다른 앱 세션으로는 절대 통과하지 못합니다.
const ROLES = {
  sysadmin: '시스템관리자', manager: '관리책임자', deputy: '부책임자', custodian: '보관담당', researcher: '연구원',
  witness: '입회자', auditor: '감사(열람)', mapping_deputy: '매핑 지정 대행자', permit_holder: '허가 명의자',
};
const APP_ROLES = {
  field: ['manager', 'deputy', 'custodian', 'researcher', 'witness'],
  admin: ['sysadmin', 'manager', 'deputy', 'auditor', 'mapping_deputy', 'permit_holder'],
  vault: ['sysadmin', 'mapping_deputy', 'permit_holder'],
};
const P = {
  // 현장 앱
  'inventory.view': ['field', ['manager', 'deputy', 'custodian', 'researcher', 'witness']],
  'receipt.create': ['field', ['manager', 'deputy', 'custodian']],
  'witness.confirm': ['field', ['manager', 'deputy', 'witness']],
  'checkout.request': ['field', ['researcher']],
  'checkout.perform': ['field', ['manager', 'deputy', 'custodian', 'researcher']],
  'usage.log': ['field', ['researcher', 'manager', 'deputy']],
  'return.submit': ['field', ['manager', 'deputy', 'custodian', 'researcher']],
  'disposal.create': ['field', ['manager', 'deputy', 'custodian']],
  // 관리 앱
  'checkout.approve': ['admin', ['manager', 'deputy']],
  'code.view': ['admin', ['sysadmin', 'manager', 'deputy', 'auditor']],
  'code.request': ['admin', ['sysadmin', 'manager']],
  'code.approve': ['admin', ['manager', 'deputy']],
  'mapping.view': ['admin', ['sysadmin']],
  'mapping.request': ['admin', ['sysadmin']],
  'mapping.approve': ['admin', ['mapping_deputy']],
  'mapping.emergency': ['admin', ['mapping_deputy']],
  'master.manage': ['admin', ['manager', 'deputy']],
  'settings.manage': ['admin', ['manager']],
  'anomaly.view': ['admin', ['manager', 'deputy', 'auditor']],
  'anomaly.manage': ['admin', ['manager', 'deputy']],
  'audit.view': ['admin', ['manager', 'deputy', 'auditor', 'sysadmin']],
  'inventory.admin': ['admin', ['manager', 'deputy', 'auditor']],
  'ledger.unlock': ['admin', ['sysadmin', 'mapping_deputy', 'permit_holder']], // 점검 대장(품명 포함) 2인 해제
  'disposal.manage': ['admin', ['manager', 'deputy', 'permit_holder']], // 관청 신청·참관·결과 기록
  'incident.view': ['admin', ['manager', 'deputy', 'auditor', 'sysadmin', 'permit_holder']],
  'incident.manage': ['admin', ['manager', 'deputy', 'permit_holder']],
  'user.manage': ['admin', ['sysadmin']],
  'device.manage': ['admin', ['sysadmin']],
};
const rolesOf = (u) => (u && u.roles ? String(u.roles).split(',').filter(Boolean) : []);
function can(u, perm, app) {
  const def = P[perm]; if (!def) throw new Error('unknown perm ' + perm);
  const [permApp, roles] = def;
  if (app && app !== permApp) return false;
  return rolesOf(u).some((r) => roles.includes(r));
}
const canUseApp = (u, app) => rolesOf(u).some((r) => (APP_ROLES[app] || []).includes(r));
module.exports = { ROLES, APP_ROLES, P, can, canUseApp, rolesOf };
