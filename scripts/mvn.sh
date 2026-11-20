#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
if [[ ! -f "$ROOT/.tools/env.sh" ]]; then
  printf 'Run bash scripts/bootstrap-tools.sh first.\n' >&2
  exit 1
fi
source "$ROOT/.tools/env.sh"
exec "$MAVEN_HOME/bin/mvn" -Dmaven.repo.local="$ROOT/.tools/m2/repository" "$@"
