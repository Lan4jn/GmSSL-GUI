#!/usr/bin/env bash
set -e
DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
exec "$DIR/scripts/status.sh" "$@"
