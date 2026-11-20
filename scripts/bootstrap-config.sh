#!/usr/bin/env bash
set +x
set -euo pipefail
umask 077
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
MODE=${1:-dev}
case "$MODE" in
  dev) ENV_FILE=${2:-"$ROOT/.env.local"} ;;
  server) ENV_FILE=${2:-"$ROOT/.env.server"} ;;
  *) printf 'Usage: %s [dev|server] [private-env-file]\n' "$0" >&2; exit 1 ;;
esac
CREDENTIALS="$ENV_FILE.credentials"
if [[ -e "$ENV_FILE" || -e "$CREDENTIALS" ]]; then
  printf 'Existing configuration retained: %s\n' "$ENV_FILE" >&2
  exit 1
fi
command -v openssl >/dev/null 2>&1 || { printf 'openssl is required for random configuration generation.\n' >&2; exit 1; }
TOKEN=$(openssl rand -hex 32)
MASTER=$(openssl rand -base64 32 | tr -d '\n')
PASSWORD=$(openssl rand -hex 24)

set -C
{
  printf 'GMSSL_ENGINE_TOKEN=%s\n' "$TOKEN"
  printf 'GMSSL_VAULT_MASTER_KEY=%s\n' "$MASTER"
  printf 'GMSSL_BOOTSTRAP_USERNAME=admin\n'
  printf 'GMSSL_BOOTSTRAP_PASSWORD=%s\n' "$PASSWORD"
  printf 'GMSSL_WEB_PORT=8088\nGMSSL_BIND_ADDRESS=127.0.0.1\n'
  if [[ "$MODE" == dev ]]; then
    printf 'GMSSL_SESSION_COOKIE_SECURE=false\n'
    printf 'GMSSL_ENGINE_URL=http://127.0.0.1:8081\n'
    printf 'GMSSL_RUNNER_PATH=%q\n' "$ROOT/native/.build/bin/gmssl-runner"
    printf 'GMSSL_ENGINE_WORK_DIR=%q\n' "$ROOT/.runtime/engine-work"
    printf 'GMSSL_VAULT_DIR=%q\n' "$ROOT/.data/vault"
    OPENSSL_BIN=$(command -v openssl || echo "/usr/bin/openssl")
    printf 'GMSSL_OPENSSL_PATH=%q\n' "$OPENSSL_BIN"
    printf 'SPRING_DATASOURCE_URL=%q\n' "jdbc:h2:file:$ROOT/.data/platform/database;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DEFAULT_NULL_ORDERING=HIGH"
    printf 'SPRING_DATASOURCE_USERNAME=sa\n'
    printf 'SPRING_DATASOURCE_PASSWORD=\n'
    printf 'SERVER_ADDRESS=127.0.0.1\n'
  else
    printf 'GMSSL_SESSION_COOKIE_SECURE=true\n'
    printf 'SPRING_PROFILES_ACTIVE=dm\n'
    printf '# Dameng (DM8) Database Configuration\n'
    printf '# Fill in your actual external DM8 host, port, schema and credentials.\n'
    printf 'SPRING_DATASOURCE_URL=jdbc:dm://YOUR_DM8_HOST:5236?schema=YOUR_SCHEMA\n'
    printf 'SPRING_DATASOURCE_USERNAME=YOUR_DM8_USERNAME\n'
    printf 'SPRING_DATASOURCE_PASSWORD=YOUR_DM8_PASSWORD\n'
  fi
} > "$ENV_FILE"

{
  printf 'Initial administrator username: admin\n'
  printf 'Initial administrator password: %s\n' "$PASSWORD"
  printf 'Keep this private file separate from shared logs. Do not commit it.\n'
} > "$CREDENTIALS"
chmod 600 "$ENV_FILE" "$CREDENTIALS"
unset TOKEN MASTER PASSWORD
printf 'Generated private configuration: %s\n' "$ENV_FILE"
printf 'Initial login is stored only in: %s\n' "$CREDENTIALS"
printf 'Keep the master key with your encrypted vault backup; changing it loses access to existing ciphertext.\n'
