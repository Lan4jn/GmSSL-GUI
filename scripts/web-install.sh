#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Helper script to install frontend dependencies using frozen lockfile
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
WEB_DIR="$ROOT/web"

find_node() {
  if [[ -n "${NODE_BIN:-}" && -x "$NODE_BIN" ]]; then
    printf '%s' "$NODE_BIN"; return 0
  fi
  local runtime_node="/Users/mewcapoo/.dsh/dsh-runtimes/dsh-primary-runtime/dependencies/node/bin/node"
  if [[ -x "$runtime_node" ]]; then
    printf '%s' "$runtime_node"; return 0
  fi
  if command -v node >/dev/null 2>&1; then
    command -v node; return 0
  fi
  return 1
}

find_pnpm() {
  local runtime_pnpm="/Users/mewcapoo/.dsh/dsh-runtimes/dsh-primary-runtime/dependencies/pnpm/bin/pnpm.mjs"
  if [[ -f "$runtime_pnpm" ]]; then
    printf '%s' "$runtime_pnpm"; return 0
  fi
  if command -v pnpm >/dev/null 2>&1; then
    command -v pnpm; return 0
  fi
  return 1
}

NODE=$(find_node) || { printf 'Node.js runtime not found.\n' >&2; exit 1; }
PNPM=$(find_pnpm) || { printf 'pnpm not found.\n' >&2; exit 1; }

cd "$WEB_DIR"
printf 'Installing web dependencies with frozen lockfile (pnpm install --frozen-lockfile)...\n'
if [[ "$PNPM" == *.mjs || "$PNPM" == *.js ]]; then
  "$NODE" "$PNPM" install --frozen-lockfile
else
  "$PNPM" install --frozen-lockfile
fi
printf 'Dependencies installed successfully.\n'
