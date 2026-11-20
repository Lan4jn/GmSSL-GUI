#!/usr/bin/env bash
set +x
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
DEPLOY_DIR=$(cd -- "$SCRIPT_DIR/.." && pwd -P)

cd "$DEPLOY_DIR"

COMPOSE="docker compose"

printf '=== GmSSL GUI Service Status ===\n'
$COMPOSE ps

if [[ -f .env ]]; then
  PORT=$(grep -E '^GMSSL_WEB_PORT=' .env | cut -d '=' -f 2 || echo "8088")
  BIND=$(grep -E '^GMSSL_BIND_ADDRESS=' .env | cut -d '=' -f 2 || echo "127.0.0.1")
  TARGET_URL="http://${BIND:-127.0.0.1}:${PORT:-8088}/"
  printf '\n[INFO] Checking Web UI endpoint: %s\n' "$TARGET_URL"
  if command -v curl >/dev/null 2>&1; then
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 3 "$TARGET_URL" || echo "FAIL")
    if [[ "$HTTP_CODE" == "200" ]]; then
      printf '[OK] Web server responded with HTTP 200 OK\n'
    elif [[ "$HTTP_CODE" == "FAIL" ]]; then
      printf '[WAIT] Endpoint not yet reachable (services may still be initializing).\n'
    else
      printf '[STATUS] Web server responded with HTTP: %s\n' "$HTTP_CODE"
    fi
  fi
fi