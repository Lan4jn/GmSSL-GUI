#!/usr/bin/env bash
set +x
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
DEPLOY_DIR=$(cd -- "$SCRIPT_DIR/.." && pwd -P)

TAR_PATH="${1:-""}"

if [[ -z "$TAR_PATH" ]]; then
  if [[ -f "$DEPLOY_DIR/gmssl-gui-images-linux-amd64.tar" ]]; then
    TAR_PATH="$DEPLOY_DIR/gmssl-gui-images-linux-amd64.tar"
  elif [[ -f "$DEPLOY_DIR/images/gmssl-gui-images-linux-amd64.tar" ]]; then
    TAR_PATH="$DEPLOY_DIR/images/gmssl-gui-images-linux-amd64.tar"
  fi
fi

if [[ -z "$TAR_PATH" || ! -f "$TAR_PATH" ]]; then
  printf '=== GmSSL GUI Offline Images Loader ===\n'
  printf '[ERROR] Offline images tarball not found!\n' >&2
  printf 'Usage: %s <path-to-gmssl-gui-images-linux-amd64.tar>\n' "$0" >&2
  exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
  printf '[ERROR] Docker is not installed or not in PATH.\n' >&2
  exit 1
fi

printf '[INFO] Loading offline pre-compiled Docker images from %s...\n' "$TAR_PATH"
docker load -i "$TAR_PATH"

printf '\n[SUCCESS] Runtime images loaded into local Docker Engine:\n'
docker images | grep "gmssl-gui" || true
printf '\nYou can now run ./start.sh to start services completely offline.\n'
