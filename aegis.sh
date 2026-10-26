#!/usr/bin/env bash
# ILias AEGIS v2 서버판(도커) 관리 명령. 이 폴더에서 실행: ./aegis.sh <명령>
set -euo pipefail
cd "$(dirname "$0")"
die() { echo "오류: $*" >&2; exit 1; }
DC="docker compose"; command -v docker >/dev/null || die "docker 가 없습니다."
[ -f .env ] || { [ "${1:-}" = up ] && die ".env 가 없습니다: cp env.example .env 후 고치세요." ; }
ADMIN() { $DC exec -T -u node aegis node --disable-warning=ExperimentalWarning scripts/server-admin.js "$@"; }
inside() { case "$(realpath -m "$1")/" in "$(realpath -m "$2")"/*) return 0;; esac; return 1; }
cmd="${1:-help}"; shift || true
case "$cmd" in
  up)      mkdir -p data keys backups caddy-data certs; chmod 700 keys; $DC up -d --build; $DC ps ;;
  down)    $DC down ;;
  restart) $DC restart ;;
  status)  $DC ps ;;
  logs)    $DC logs --tail "${1:-200}" ;;
  setup-code) ADMIN setup-code ;;
  backup|list-backups|verify) ADMIN "$cmd" ;;
  restore) [ -n "${1:-}" ] || die "사용: ./aegis.sh restore backups/aegis-backup-YYYYMMDD-HHMMSS"
           name="$(basename "$1")"; [ -d "backups/$name" ] || die "backups/$name 가 없습니다."
           $DC stop caddy aegis
           $DC run --rm --no-deps -T --entrypoint "" -u node aegis node --disable-warning=ExperimentalWarning scripts/server-admin.js restore "/var/backups/aegis/$name" || true
           echo "확인 뒤 시작: ./aegis.sh up" ;;
  backup-keys) d="${1:-}"; [ -n "$d" ] || die "사용: ./aegis.sh backup-keys <USB 등 별도 매체 경로>"
           if [ "${2:-}" != --force ]; then for x in backups data keys; do inside "$d" "$x" && die "키 백업 위치가 $x 폴더와 겹칩니다. 다른 매체를 지정하세요."; done; fi
           out="$d/aegis-keys-$(date +%Y%m%d-%H%M%S)"; mkdir -p "$out"; chmod 700 "$out"
           cp keys/secrets.json "$out/"; [ -f keys/audit_anchors.jsonl ] && cp keys/audit_anchors.jsonl "$out/"; chmod 600 "$out"/*
           echo "키 백업 완료: $out"; echo " ★ 경고: 이 폴더와 자료 백업을 함께 가진 사람은 매핑을 풀 수 있습니다. 다른 매체·다른 보관자에게 두세요." ;;
  restore-keys) s="${1:-}"; [ -f "$s/secrets.json" ] || die "사용: ./aegis.sh restore-keys <aegis-keys-... 폴더>"
           $DC stop caddy aegis; [ -f keys/secrets.json ] && mv keys/secrets.json "keys/secrets.json.replaced-$(date +%Y%m%d-%H%M%S)"
           cp "$s/secrets.json" keys/; [ -f "$s/audit_anchors.jsonl" ] && cp "$s/audit_anchors.jsonl" keys/; chmod 600 keys/*; echo "키 복원 완료. ./aegis.sh up 으로 시작" ;;
  import)  f="${1:-}"; [ -f "$f" ] || die "사용: ./aegis.sh import <CSV 파일>"
           t="/var/lib/aegis/data/run/import-$$.csv"
           $DC exec -T -u 0 aegis sh -c "umask 077; cat > $t && chown node:node $t" < "$f"
           trap "$DC exec -T -u 0 aegis rm -f $t" EXIT
           $DC exec -it -u node aegis node --disable-warning=ExperimentalWarning scripts/import-intake.js "$t"
           echo "가져오기를 마쳤습니다. 원본 CSV는 서버에 남기지 말고 지정 보관 장소로 옮기세요." ;;
  ca-cert) out="${1:-./aegis-root-ca.crt}"; src=caddy-data/caddy/pki/authorities/local/root.crt
           [ -f "$src" ] || die "루트 인증서가 아직 없습니다(caddy가 한 번 시작해야 생성)."
           cp "$src" "$out"; echo "루트 인증서(공개용): $out"; command -v openssl >/dev/null && openssl x509 -in "$out" -noout -subject -enddate -fingerprint -sha256 || true ;;
  *) cat <<'H'
사용: ./aegis.sh <명령>
  up | down | restart | status | logs     컨테이너 관리(up = 빌드 후 시작)
  setup-code                              첫 관리자 설정 코드
  backup | list-backups | verify          지금 백업 / 목록 / 감사 체인·키 점검
  restore backups/<백업 폴더>             복원(컨테이너를 멈추고 진행)
  backup-keys <별도 매체 경로>            암호 키 백업(자료 백업과 다른 곳에!)
  restore-keys <aegis-keys-... 폴더>      암호 키 복원
  import <CSV>                            실데이터 CSV 가져오기(서버 콘솔에서)
  ca-cert [출력 파일]                     내장 인증기관 루트 인증서 내보내기
H
  ;;
esac
