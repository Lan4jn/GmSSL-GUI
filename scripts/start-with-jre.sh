#!/usr/bin/env bash
set +x
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
DEPLOY_DIR=$(cd -- "$SCRIPT_DIR/.." && pwd -P)

cd "$DEPLOY_DIR"

CLI_JRE_IMAGE=""
CLI_NGINX_IMAGE=""
CHECK_ONLY=0
ENV_FILE_PATH="$DEPLOY_DIR/.env"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --jre-image)
      if [[ $# -lt 2 || "$2" =~ ^-- ]]; then
        printf '[ERROR] Missing value for --jre-image\n' >&2
        exit 1
      fi
      CLI_JRE_IMAGE="$2"
      shift 2
      ;;
    --nginx-image)
      if [[ $# -lt 2 || "$2" =~ ^-- ]]; then
        printf '[ERROR] Missing value for --nginx-image\n' >&2
        exit 1
      fi
      CLI_NGINX_IMAGE="$2"
      shift 2
      ;;
    --env-file)
      if [[ $# -lt 2 || "$2" =~ ^-- ]]; then
        printf '[ERROR] Missing value for --env-file\n' >&2
        exit 1
      fi
      ENV_FILE_PATH="$2"
      shift 2
      ;;
    --check-only)
      CHECK_ONLY=1
      shift
      ;;
    -h|--help)
      printf 'Usage: %s --jre-image <IMAGE> [--nginx-image <IMAGE>] [--env-file <path>]\n\n' "$0"
      printf 'Options:\n'
      printf '  --jre-image <IMAGE>    Specify local Docker JRE 21 base image (required, or set JRE_IMAGE env)\n'
      printf '  --nginx-image <IMAGE>  Specify local Docker Nginx base image (default: nginx:1.28-alpine)\n'
      printf '  --env-file <path>      Specify configuration file path (default: .env)\n'
      printf '  -h, --help             Show this help message and exit\n\n'
      printf 'Examples:\n'
      printf '  %s --jre-image my-registry.local:5000/base/temurin:21-jre\n' "$0"
      printf '  %s --jre-image eclipse-temurin:21-jre-jammy --nginx-image nginx:1.28-alpine\n' "$0"
      exit 0
      ;;
    *)
      printf '[ERROR] Unknown argument: %s\n' "$1" >&2
      printf 'Run %s --help for usage information.\n' "$0" >&2
      exit 1
      ;;
  esac
done

TARGET_JRE_IMAGE="${CLI_JRE_IMAGE:-${JRE_IMAGE:-${GMSSL_JRE_IMAGE:-}}}"
if [[ -z "$TARGET_JRE_IMAGE" ]]; then
  printf '[ERROR] Local JRE image must be specified via --jre-image <IMAGE> or JRE_IMAGE environment variable.\n' >&2
  printf '[ERROR] In offline mode without pre-built gmssl images, an existing local JRE 21 image is required.\n' >&2
  exit 1
fi

TARGET_NGINX_IMAGE="${CLI_NGINX_IMAGE:-${NGINX_IMAGE:-${GMSSL_NGINX_IMAGE:-nginx:1.28-alpine}}}"

# 1. Check configuration
if [[ ! -f "$ENV_FILE_PATH" ]]; then
  printf '[ERROR] Configuration file not found at %s.\n' "$ENV_FILE_PATH" >&2
  printf '[ERROR] Please run ./init.sh first to generate secure private configuration.\n' >&2
  exit 1
fi

# 2. Check required artifacts
REQUIRED_ARTIFACTS=(
  "$DEPLOY_DIR/artifacts/engine-service-0.1.0-SNAPSHOT.jar"
  "$DEPLOY_DIR/artifacts/platform-service-0.1.0-SNAPSHOT.jar"
  "$DEPLOY_DIR/artifacts/gmssl-runner"
  "$DEPLOY_DIR/artifacts/web-dist/index.html"
  "$DEPLOY_DIR/config/nginx.conf"
  "$DEPLOY_DIR/compose.jre.yaml"
)
for art in "${REQUIRED_ARTIFACTS[@]}"; do
  if [[ ! -e "$art" ]]; then
    printf '[ERROR] Required release artifact missing: %s\n' "$art" >&2
    exit 1
  fi
done

# 3. Check Docker and Compose V2
if ! command -v docker >/dev/null 2>&1; then
  printf '[ERROR] Docker is not installed or not in PATH.\n' >&2
  exit 1
fi

if ! docker compose version >/dev/null 2>&1; then
  printf '[ERROR] Docker Compose V2 (docker compose) is required.\n' >&2
  exit 1
fi

# 4. Verify local image availability (strict offline check, no pull)
printf '[INFO] Checking local availability of JRE image: %s...\n' "$TARGET_JRE_IMAGE"
if ! docker image inspect "$TARGET_JRE_IMAGE" >/dev/null 2>&1; then
  printf '[ERROR] Specified JRE image not found locally: %s\n' "$TARGET_JRE_IMAGE" >&2
  printf '[ERROR] In offline mode, the JRE image must be loaded locally in advance (e.g. docker load -i ...).\n' >&2
  exit 1
fi

printf '[INFO] Checking local availability of Nginx image: %s...\n' "$TARGET_NGINX_IMAGE"
if ! docker image inspect "$TARGET_NGINX_IMAGE" >/dev/null 2>&1; then
  printf '[ERROR] Specified Nginx image not found locally: %s\n' "$TARGET_NGINX_IMAGE" >&2
  printf '[ERROR] In offline mode, the Nginx image must be loaded locally in advance.\n' >&2
  exit 1
fi

# 5. Read-only probe of JRE image: Java 21 version, OpenSSL availability, and target user file access
printf '[INFO] Probing JRE image runtime capabilities...\n'

# Standard Compose priority: shell export (if non-empty) > .env > default 10001:10001
RESOLVED_USER="${GMSSL_CONTAINER_USER:-}"
if [[ -z "$RESOLVED_USER" && -f "$ENV_FILE_PATH" ]]; then
  RESOLVED_USER=$(grep -E '^[[:space:]]*GMSSL_CONTAINER_USER=' "$ENV_FILE_PATH" 2>/dev/null | tail -n 1 | cut -d '=' -f 2- | tr -d '[:space:]"' || echo "")
fi
TARGET_USER="${RESOLVED_USER:-10001:10001}"
export GMSSL_CONTAINER_USER="$TARGET_USER"

# Strict validation: engine /work tmpfs (mode 0700) and historical vault-data volume are strictly locked to 10001:10001 (UID 10001, GID 10001)
# Any other effective user (including root, names, non-10001 UID, or non-10001 GID) triggers kernel EPERM under cap_drop: [ALL]
if [[ "$TARGET_USER" != "10001:10001" ]]; then
  printf '[ERROR] Container user mismatch: Configured user is "%s".\n' "$TARGET_USER" >&2
  printf '        engine service /work tmpfs and historical vault-data volume are strictly locked to 10001:10001 (UID 10001, GID 10001).\n' >&2
  printf '        Running with any other UID:GID under cap_drop: [ALL] will trigger kernel EPERM (Operation not permitted).\n' >&2
  printf '        Please configure GMSSL_CONTAINER_USER=10001:10001 or leave it unset to use the default.\n' >&2
  exit 1
fi

# Enforce safe local permissions on precompiled artifacts (0644 for jars, 0755 for runner and directory)
chmod 755 "$DEPLOY_DIR/artifacts" 2>/dev/null || true
chmod 644 "$DEPLOY_DIR/artifacts/platform-service-0.1.0-SNAPSHOT.jar" "$DEPLOY_DIR/artifacts/engine-service-0.1.0-SNAPSHOT.jar" 2>/dev/null || true
chmod 755 "$DEPLOY_DIR/artifacts/gmssl-runner" 2>/dev/null || true

JAVA_CHECK=$(docker run --rm --pull=never --user "$TARGET_USER" -v "$DEPLOY_DIR/artifacts/platform-service-0.1.0-SNAPSHOT.jar:/app/service.jar:ro" "$TARGET_JRE_IMAGE" java -version 2>&1 || echo "JAVA_PROBE_FAILED")
if [[ "$JAVA_CHECK" == *"JAVA_PROBE_FAILED"* || ! "$JAVA_CHECK" =~ (version[[:space:]]+21|openjdk[[:space:]]+21|java[[:space:]]+21|21\.[0-9]) ]]; then
  printf '[ERROR] JRE runtime validation failed for %s (user: %s):\n' "$TARGET_JRE_IMAGE" "$TARGET_USER" >&2
  printf '        Java 21 runtime is strictly required and target user must be able to read mounted JAR. Probe output:\n%s\n' "$JAVA_CHECK" >&2
  exit 1
fi
printf '[OK] JRE image verified as Java 21 runtime with user %s.\n' "$TARGET_USER"

OPENSSL_CHECK=$(docker run --rm --pull=never "$TARGET_JRE_IMAGE" openssl version 2>&1 || echo "OPENSSL_PROBE_FAILED")
if [[ "$OPENSSL_CHECK" == *"OPENSSL_PROBE_FAILED"* ]]; then
  printf '[ERROR] OpenSSL binary not found or not executable in JRE image %s.\n' "$TARGET_JRE_IMAGE" >&2
  printf '[ERROR] engine-service requires openssl in the container filesystem for SM2/SM3/SM4 cryptographic operations.\n' >&2
  exit 1
fi
printf '[OK] OpenSSL binary found in JRE image (%s).\n' "$(printf '%s\n' "$OPENSSL_CHECK" | head -n 1)"

if [[ $CHECK_ONLY -eq 1 ]]; then
  printf '[OK] All start-with-jre preflight checks passed successfully (--check-only).\n'
  exit 0
fi

# 6. Execute Docker Compose up with compose.jre.yaml
printf '[INFO] Starting GmSSL GUI stack with mounted pre-compiled artifacts using local JRE...\n'
export GMSSL_JRE_IMAGE="$TARGET_JRE_IMAGE"
export GMSSL_NGINX_IMAGE="$TARGET_NGINX_IMAGE"
export GMSSL_CONTAINER_USER="$TARGET_USER"

docker compose --env-file "$ENV_FILE_PATH" -f compose.jre.yaml up -d --pull never --no-build --force-recreate

PORT=$(grep -E '^[[:space:]]*GMSSL_WEB_PORT=' "$ENV_FILE_PATH" 2>/dev/null | cut -d '=' -f 2- | tr -d '[:space:]' | tr -d '"' || echo "8088")
BIND=$(grep -E '^[[:space:]]*GMSSL_BIND_ADDRESS=' "$ENV_FILE_PATH" 2>/dev/null | cut -d '=' -f 2- | tr -d '[:space:]' | tr -d '"' || echo "127.0.0.1")
SECURE_COOKIE=$(grep -E '^[[:space:]]*GMSSL_SESSION_COOKIE_SECURE=' "$ENV_FILE_PATH" 2>/dev/null | cut -d '=' -f 2- | tr -d '[:space:]' | tr -d '"' || echo "true")

printf '\n[INFO] Stack started with local JRE image (%s).\n' "$TARGET_JRE_IMAGE"
printf '[INFO] Web UI endpoint: http://%s:%s\n' "${BIND:-127.0.0.1}" "${PORT:-8088}"
if [[ "$SECURE_COOKIE" == "true" ]]; then
  printf '[SECURITY NOTICE] GMSSL_SESSION_COOKIE_SECURE=true is active.\n'
  printf '  Browser session cookies require an HTTPS connection (e.g. via TLS reverse proxy).\n'
  printf '  For temporary local-only HTTP evaluation without TLS, set GMSSL_SESSION_COOKIE_SECURE=false in .env\n'
fi
printf '[INFO] Run ./status.sh to check container health and endpoint connectivity.\n'
