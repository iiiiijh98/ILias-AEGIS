# ILias AEGIS v2 회사 서버판 — 앱 이미지(4개 앱, 127.0.0.1 전용). HTTPS는 같은 네트워크 공간의 caddy 컨테이너가 담당.
FROM node:24.22.1-bookworm-slim
ENV NODE_ENV=production AEGIS2_EDITION=server TZ=Asia/Seoul
WORKDIR /opt/aegis/app
COPY app/ /opt/aegis/app/
COPY aegis-entrypoint.sh /usr/local/bin/aegis-entrypoint.sh
RUN chmod 0755 /usr/local/bin/aegis-entrypoint.sh \
 && mkdir -p /var/lib/aegis/data /var/lib/aegis/keys /var/backups/aegis /etc/aegis/caddy \
 && chown -R root:root /opt/aegis && chmod -R go-w /opt/aegis
EXPOSE 443 8443 8444 9444
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:3201/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
ENTRYPOINT ["/usr/local/bin/aegis-entrypoint.sh"]
CMD ["node", "--disable-warning=ExperimentalWarning", "scripts/server-start.js"]
