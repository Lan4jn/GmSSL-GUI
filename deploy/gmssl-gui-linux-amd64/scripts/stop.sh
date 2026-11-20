#!/usr/bin/env bash
set +x
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
DEPLOY_DIR=$(cd -- "$SCRIPT_DIR/.." && pwd -P)

cd "$DEPLOY_DIR"

COMPOSE="docker compose"

printf '[INFO] Stopping GmSSL GUI services (volumes postgres-data and vault-data will be preserved)...\n'
$COMPOSE stop
printf '[INFO] GmSSL GUI services stopped.\n'