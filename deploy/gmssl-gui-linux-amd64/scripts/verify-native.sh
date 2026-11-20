#!/usr/bin/env bash
set +x
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
DEPLOY_DIR=$(cd -- "$SCRIPT_DIR/.." && pwd -P)

printf '=== GmSSL Linux Native Runner SM3 KAT Verification ===\n'

EXPECTED_HASH="66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
RAW_FRAME="\x47\x4d\x52\x55\x4e\x30\x30\x31\x00\x00\x00\x02\x00\x00\x00\x07\x00\x00\x00\x03\x73\x6d\x33\x00\x00\x00\x04\x2d\x62\x69\x6e\x61\x62\x63"

# Check if target command is user-supplied via arguments or default to containerized runner
if [[ $# -gt 0 ]]; then
  TARGET_CMD=("$@")
elif [[ -f "$DEPLOY_DIR/compose.yaml" ]] && command -v docker >/dev/null 2>&1; then
  ENV_OPT=()
  if [[ -f "$DEPLOY_DIR/.env" ]]; then
    ENV_OPT=(--env-file "$DEPLOY_DIR/.env")
  fi
  TARGET_CMD=(docker compose --project-directory "$DEPLOY_DIR" "${ENV_OPT[@]}" -f "$DEPLOY_DIR/compose.yaml" exec -T engine /app/gmssl-runner)
else
  printf '[ERROR] No execution target available.\n' >&2
  printf 'Usage: %s ["<command-to-invoke-runner>" [args...]]\n' "$0" >&2
  printf 'Example (container): %s\n' "$0" >&2
  printf 'Example (direct ELF): %s /path/to/gmssl-runner\n' "$0" >&2
  exit 1
fi

printf '[INFO] Testing runner invocation: %s\n' "${TARGET_CMD[*]}"

# Execute binary frame and capture raw output hex bytes
OUTPUT_HEX=$(printf "%b" "$RAW_FRAME" | "${TARGET_CMD[@]}" | od -An -v -tx1 | tr -d ' \n\t\r' || exit 1)

if [[ "$OUTPUT_HEX" == "$EXPECTED_HASH" ]]; then
  printf '[OK] SM3(abc) KAT PASSED: %s\n' "$OUTPUT_HEX"
  printf '=== Native Runner Verified Successfully ===\n'
  exit 0
else
  printf '[ERROR] SM3 KAT FAILED! Expected: %s, Got: %s\n' "$EXPECTED_HASH" "$OUTPUT_HEX" >&2
  exit 1
fi
