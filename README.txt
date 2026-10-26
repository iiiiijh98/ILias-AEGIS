ILias AEGIS — Audited Evidence Guarding & Inventory System
시료 보관·반출 관리 시스템 · v2 회사 서버판 (Docker)

대상: 리눅스 서버 + Docker Engine 24 이상 + docker compose v2 (이 패키지의 도커 구성은 실제 도커에서 아직 시험하지 않았습니다 — 안내서 마지막 장)
빌드할 때 인터넷에서 node:24.22.1-bookworm-slim, caddy:2.11.7 이미지를 받습니다.
비밀값·실데이터는 들어 있지 않습니다. 암호 키는 첫 시작 때 ./keys 에 만들어집니다.

  unzip AEGIS_v2_server_docker.zip && cd AEGIS_v2_server_docker
  cp env.example .env && nano .env    # 서버 주소·관리 앱 허용 대역
  ./aegis.sh up
  ./aegis.sh setup-code
  ./aegis.sh backup-keys /media/<USB>

자세한 절차: 안내서_IT_서버설치.pdf (또는 .md)
