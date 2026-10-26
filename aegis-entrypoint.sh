#!/bin/sh
# 폴더 권한을 맞춘 뒤 node 사용자(root 아님)로 실행
set -eu
chown -R node:node /var/lib/aegis/data /var/lib/aegis/keys /var/backups/aegis /etc/aegis/caddy
chmod 700 /var/lib/aegis/keys
exec setpriv --reuid=node --regid=node --init-groups "$@"
