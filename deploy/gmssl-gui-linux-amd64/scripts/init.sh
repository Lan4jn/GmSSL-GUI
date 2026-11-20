#!/usr/bin/env bash
set +x
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
DEPLOY_DIR=$(cd -- "$SCRIPT_DIR/.." && pwd -P)

ENV_FILE="$DEPLOY_DIR/.env"
CREDENTIALS_FILE="$DEPLOY_DIR/credentials.txt"

# Retain existing configuration if either .env or credentials.txt exists
if [[ -e "$ENV_FILE" || -e "$CREDENTIALS_FILE" ]]; then
  printf '[INFO] Existing configuration retained:\n' >&2
  [[ -e "$ENV_FILE" ]] && printf '  - %s\n' "$ENV_FILE" >&2
  [[ -e "$CREDENTIALS_FILE" ]] && printf '  - %s\n' "$CREDENTIALS_FILE" >&2
  printf '[INFO] Both .env and credentials.txt must be absent to run a fresh initialization.\n' >&2
  exit 1
fi

# Reject symlinks or directories to avoid clobbering or link redirection attacks
if [[ -L "$ENV_FILE" || -L "$CREDENTIALS_FILE" ]]; then
  printf '[ERROR] Target configuration path is a symlink. Aborting for security.\n' >&2
  exit 1
fi

if ! command -v openssl >/dev/null 2>&1; then
  printf '[ERROR] openssl is required for cryptographic random token generation.\n' >&2
  exit 1
fi

umask 077
set -C

TOKEN=$(openssl rand -hex 32)
MASTER_KEY=$(openssl rand -base64 32 | tr -d '\n')
ADMIN_PASS=$(openssl rand -hex 16)

{
  printf '# GmSSL GUI Linux amd64 Deployment Environment (Dameng DM8 Edition)\n'
  printf '# Generated: %s\n\n' "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  printf 'GMSSL_BIND_ADDRESS=127.0.0.1\n'
  printf 'GMSSL_WEB_PORT=8088\n'
  printf 'GMSSL_SESSION_COOKIE_SECURE=true\n\n'
  printf 'GMSSL_ENGINE_TOKEN=%s\n' "$TOKEN"
  printf 'GMSSL_VAULT_MASTER_KEY=%s\n\n' "$MASTER_KEY"
  printf 'GMSSL_BOOTSTRAP_USERNAME=admin\n'
  printf 'GMSSL_BOOTSTRAP_PASSWORD=%s\n\n' "$ADMIN_PASS"
  printf 'SPRING_PROFILES_ACTIVE=dm\n\n'
  printf '# External Dameng (DM8) Database Configuration\n'
  printf '# Fill in your actual external DM8 host, port, schema and credentials below.\n'
  printf '# Note: Execute artifacts/01_schema_dm8.sql in your DM8 schema prior to first start.\n'
  printf 'SPRING_DATASOURCE_URL=jdbc:dm://YOUR_DM8_HOST:5236?schema=YOUR_SCHEMA\n'
  printf 'SPRING_DATASOURCE_USERNAME=YOUR_DM8_USERNAME\n'
  printf 'SPRING_DATASOURCE_PASSWORD=YOUR_DM8_PASSWORD\n'
} > "$ENV_FILE"

{
  printf '# GmSSL GUI Initial Administrator Credentials\n'
  printf '# Generated: %s\n\n' "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  printf 'Initial administrator username: admin\n'
  printf 'Initial administrator password: %s\n\n' "$ADMIN_PASS"
  printf 'WARNING:\n'
  printf 'Keep this private file secure and do not share or commit it.\n'
  printf 'After initial login, consider changing the administrator password or deleting this file.\n'
} > "$CREDENTIALS_FILE"

chmod 600 "$ENV_FILE" "$CREDENTIALS_FILE"

unset TOKEN MASTER_KEY ADMIN_PASS

printf '[INFO] Generated private configuration: %s (mode 600)\n' "$ENV_FILE"
printf '[INFO] Initial login credentials stored securely in: %s (mode 600)\n' "$CREDENTIALS_FILE"
printf '[INFO] Credentials have NOT been logged to stdout or console.\n'
printf '[ACTION REQUIRED] Please edit %s and configure your external Dameng (DM8) connection before running ./start.sh.\n' "$ENV_FILE"
