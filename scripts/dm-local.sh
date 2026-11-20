#!/usr/bin/env bash
set +x
set -euo pipefail
umask 077
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
exec python3 "$ROOT/.runtime/dm-local/manage.py" "${1:-status}"
