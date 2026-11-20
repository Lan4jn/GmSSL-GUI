#!/usr/bin/env bash
set +x
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
DEPLOY_DIR=$(cd -- "$SCRIPT_DIR/.." && pwd -P)

cd "$DEPLOY_DIR"

if [[ ! -f "$DEPLOY_DIR/.env" ]]; then
  printf '[WARN] Configuration .env not found. Initializing now...\n'
  "$DEPLOY_DIR/scripts/init.sh"
fi

# Run pre-flight check
"$DEPLOY_DIR/scripts/check.sh"

COMPOSE="docker compose"

# Check if offline pre-compiled Docker images are available locally
HAS_LOCAL_IMAGES=1
for img in "gmssl-gui/engine:0.1.0-linux-amd64" "gmssl-gui/platform:0.1.0-linux-amd64" "gmssl-gui/web:0.1.0-linux-amd64"; do
  if ! docker image inspect "$img" >/dev/null 2>&1; then
    HAS_LOCAL_IMAGES=0
    break
  fi
done

if [[ $HAS_LOCAL_IMAGES -eq 1 ]]; then
  printf '[INFO] Local pre-compiled runtime images found. Starting offline stack without internet pull/build...\n'
  $COMPOSE up -d --no-build
else
  # If images tarball exists in images/ directory, offer automatic load
  if [[ -f "$DEPLOY_DIR/images/gmssl-gui-images-linux-amd64.tar" ]]; then
    printf '[INFO] Loading pre-compiled runtime images from %s...\n' "$DEPLOY_DIR/images/gmssl-gui-images-linux-amd64.tar"
    docker load -i "$DEPLOY_DIR/images/gmssl-gui-images-linux-amd64.tar"
    $COMPOSE up -d --no-build
  else
    printf '[WARN] Local runtime images (gmssl-gui/*) not loaded and images/ tarball not present.\n'
    printf '[INFO] Attempting local Docker build from pre-compiled artifacts...\n'
    $COMPOSE up -d --build
  fi
fi

PORT=$(grep -E '^GMSSL_WEB_PORT=' .env | cut -d '=' -f 2 || echo "8088")
BIND=$(grep -E '^GMSSL_BIND_ADDRESS=' .env | cut -d '=' -f 2 || echo "127.0.0.1")

SECURE_COOKIE=$(grep -E '^GMSSL_SESSION_COOKIE_SECURE=' .env | cut -d '=' -f 2 || echo "true")
printf '\n[INFO] Container creation and startup request dispatched.\n'
printf '[INFO] Backend proxy port listening on: http://%s:%s\n' "${BIND:-127.0.0.1}" "${PORT:-8088}"
if [[ "$SECURE_COOKIE" == "true" ]]; then
  printf '[SECURITY NOTICE] GMSSL_SESSION_COOKIE_SECURE=true is active.\n'
  printf '  Browser session cookies require an HTTPS connection (e.g. via TLS reverse proxy).\n'
  printf '  Logging in directly over plain HTTP will fail session authentication.\n'
  printf '  For temporary local-only HTTP evaluation without TLS, set GMSSL_SESSION_COOKIE_SECURE=false in .env\n'
fi
printf '[INFO] Backend database and Spring Boot containers require 5-15 seconds to initialize.\n'
printf '[INFO] Run ./status.sh to check container health and endpoint connectivity.\n'