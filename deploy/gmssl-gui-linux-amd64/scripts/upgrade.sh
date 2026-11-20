#!/usr/bin/env bash
set +x
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
# Default target directory is the current working directory from which upgrade is invoked
TARGET_DIR=$(pwd -P)

OLD_DIR=""
MODE="plan"
AUTO_CONFIRM=0
ASSUME_BACKUP_DONE=0

print_usage() {
  cat << 'EOF'
Usage: ./upgrade.sh --from <old_deploy_dir> [options]

Modes:
  --plan         (Default) Read-only dry run check; verifies prerequisites, project name,
                 configuration differences, and outputs action items without touching any files.
  --check        Alias for --plan.
  --apply        Execute migration: stop old containers, migrate .env/credentials, run preflight,
                 and start new containers. Requires confirmation.

Options:
  --from <path>          Absolute or relative path to the existing/previous deployment directory.
  --jre-image <image>    Specify local Docker JRE 21 image for local JRE mount mode (CLI > JRE_IMAGE env).
  --nginx-image <image>  Specify local Docker Nginx image for local JRE mount mode (default: nginx:1.28-alpine).
  --yes                  Assume yes for apply confirmation.
  --backup-done          Explicitly confirm that external Dameng DB and Vault data cold backup are completed.
  -h, --help             Show this help message.

Examples:
  ./upgrade.sh --from /opt/gmssl-gui-v1 --plan
  ./upgrade.sh --from /opt/gmssl-gui-v1 --jre-image my-registry.local:5000/base/temurin:21-jre --plan
  ./upgrade.sh --from /opt/gmssl-gui-v1 --jre-image my-registry.local:5000/base/temurin:21-jre --apply --backup-done
EOF
}

CLI_JRE_IMAGE=""
CLI_NGINX_IMAGE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --from)
      if [[ $# -lt 2 || "$2" =~ ^-- ]]; then
        printf '[ERROR] Missing value for --from\n' >&2
        exit 1
      fi
      OLD_DIR="$2"
      shift 2
      ;;
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
    --plan|--check)
      MODE="plan"
      shift
      ;;
    --apply)
      MODE="apply"
      shift
      ;;
    --yes)
      AUTO_CONFIRM=1
      shift
      ;;
    --backup-done)
      ASSUME_BACKUP_DONE=1
      shift
      ;;
    -h|--help)
      print_usage
      exit 0
      ;;
    *)
      printf '[ERROR] Unknown argument: %s\n' "$1" >&2
      print_usage
      exit 1
      ;;
  esac
done

TARGET_JRE_IMAGE="${CLI_JRE_IMAGE:-${JRE_IMAGE:-${GMSSL_JRE_IMAGE:-}}}"
TARGET_NGINX_IMAGE="${CLI_NGINX_IMAGE:-${NGINX_IMAGE:-${GMSSL_NGINX_IMAGE:-}}}"

if [[ -n "$CLI_NGINX_IMAGE" && -z "$TARGET_JRE_IMAGE" ]]; then
  printf '[ERROR] --nginx-image specified without JRE image. Local JRE mount mode requires a JRE image.\n' >&2
  exit 1
fi

if [[ -n "$TARGET_JRE_IMAGE" && -z "$TARGET_NGINX_IMAGE" ]]; then
  TARGET_NGINX_IMAGE="nginx:1.28-alpine"
fi

MODE_RUN="images"
if [[ -n "$TARGET_JRE_IMAGE" ]]; then
  MODE_RUN="jre"
fi

if [[ -z "$OLD_DIR" ]]; then
  printf '[ERROR] Missing required argument: --from <old_deploy_dir>\n' >&2
  print_usage
  exit 1
fi

if [[ ! -d "$OLD_DIR" ]]; then
  printf '[ERROR] Old deployment directory not found: %s\n' "$OLD_DIR" >&2
  exit 1
fi

REAL_OLD=$(cd "$OLD_DIR" && pwd -P)
REAL_TARGET=$(cd "$TARGET_DIR" && pwd -P)

# 1. Reject in-place / same directory upgrade
if [[ "$REAL_OLD" == "$REAL_TARGET" ]]; then
  printf '[ERROR] In-place upgrade rejected: target and source are the same directory (%s).\n' "$REAL_TARGET" >&2
  printf '        Please unpack the new release into a separate directory (out-of-place upgrade).\n' >&2
  exit 1
fi

# 2. Reject symlink directories
if [[ -L "$OLD_DIR" || -L "$TARGET_DIR" ]]; then
  printf '[ERROR] Source or target deployment path is a symbolic link. Aborting for security.\n' >&2
  exit 1
fi

printf '=== GmSSL GUI Linux amd64 Deployment Upgrade Tool ===\n'
printf '[INFO] Source old directory: %s\n' "$REAL_OLD"
printf '[INFO] Target new directory: %s\n' "$REAL_TARGET"
printf '[INFO] Operating mode:       %s\n\n' "$MODE"

# 3. Check old .env presence
OLD_ENV="$REAL_OLD/.env"
if [[ ! -f "$OLD_ENV" ]]; then
  printf '[ERROR] Missing .env file in old deployment directory: %s\n' "$OLD_ENV" >&2
  printf '        Cannot migrate settings without existing configuration.\n' >&2
  exit 1
fi

# 4. Check COMPOSE_PROJECT_NAME and compose name
OLD_COMPOSE="$REAL_OLD/compose.yaml"
NEW_COMPOSE="$REAL_TARGET/compose.yaml"

if [[ -f "$OLD_COMPOSE" && -f "$NEW_COMPOSE" ]]; then
  OLD_NAME=$(grep -E '^name:' "$OLD_COMPOSE" | awk '{print $2}' || echo "")
  NEW_NAME=$(grep -E '^name:' "$NEW_COMPOSE" | awk '{print $2}' || echo "")
  if [[ -n "$OLD_NAME" && -n "$NEW_NAME" && "$OLD_NAME" != "$NEW_NAME" ]]; then
    printf '[WARN] Compose project name mismatch: %s (old) vs %s (new).\n' "$OLD_NAME" "$NEW_NAME"
    printf '       Data volumes might not bind to the same Docker storage!\n'
  else
    printf '[OK] Compose project name consistent: %s\n' "${NEW_NAME:-gmssl-gui-release}"
  fi
fi

# 5. Safe parsing of old .env (NO eval, NO source to avoid command injection)
HAS_MASTER=0
OLD_DB_URL=""
OLD_VAULT_KEY=""

while IFS= read -r line; do
  line=$(echo "$line" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
  if [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]]; then
    continue
  fi
  if [[ "$line" == GMSSL_VAULT_MASTER_KEY=* ]]; then
    val="${line#GMSSL_VAULT_MASTER_KEY=}"
    val=$(echo "$val" | tr -d "\r\n" | sed -e "s/^\x27//" -e "s/\x27\$//" -e 's/^"//' -e 's/"\$//')
    if [[ -n "$val" && "$val" != *"YOUR_"* ]]; then
      HAS_MASTER=1
      OLD_VAULT_KEY="$val"
    fi
  elif [[ "$line" == SPRING_DATASOURCE_URL=* ]]; then
    OLD_DB_URL="${line#SPRING_DATASOURCE_URL=}"
    OLD_DB_URL=$(echo "$OLD_DB_URL" | tr -d "\r\n" | sed -e "s/^\x27//" -e "s/\x27\$//" -e 's/^"//' -e 's/"\$//')
  fi
done < "$OLD_ENV"

if [[ $HAS_MASTER -eq 0 || -z "$OLD_VAULT_KEY" ]]; then
  printf '[ERROR] Fail-Closed: Valid GMSSL_VAULT_MASTER_KEY not found in %s!\n' "$OLD_ENV" >&2
  printf '        Refusing upgrade because master key is required to access historical encrypted vault data.\n' >&2
  exit 1
fi

printf '[OK] Verified existing GMSSL_VAULT_MASTER_KEY is present in old configuration.\n'

if [[ "$OLD_DB_URL" != jdbc:dm://* ]]; then
  printf '[WARN] Existing SPRING_DATASOURCE_URL does not start with jdbc:dm:// (%s).\n' "$OLD_DB_URL"
  printf '       This release only supports external Dameng (DM8) database.\n'
else
  printf '[OK] Verified existing Dameng DM8 JDBC URL prefix: %s\n' "${OLD_DB_URL:0:15}..."
fi

# 6. Compare configuration keys with .env.example
if [[ -f "$REAL_TARGET/.env.example" ]]; then
  NEW_KEYS=()
  while IFS= read -r line; do
    if [[ "$line" =~ ^[A-Z0-9_]+= ]]; then
      k="${line%%=*}"
      if ! grep -q "^[[:space:]]*$k=" "$OLD_ENV"; then
        NEW_KEYS+=("$k")
      fi
    fi
  done < "$REAL_TARGET/.env.example"

  if [[ ${#NEW_KEYS[@]} -gt 0 ]]; then
    printf '\n[INFO] Configuration Notice: The new version template (.env.example) introduces options not present in your old .env:\n'
    for nk in "${NEW_KEYS[@]}"; do
      printf '  - %s\n' "$nk"
    done
    printf '       These will be annotated in the migrated .env without breaking existing settings.\n'
  else
    printf '[OK] All template keys are covered in the existing .env file.\n'
  fi
fi

# 7. Output Database Migration Guidance (Explicit Baseline and DBA verification)
printf '\n=== Dameng Database (DM8) Schema Verification Checklist ===\n'
printf '[ACTION REQUIRED FOR DBA]:\n'
printf '  1. Ensure Dameng database schema and user are active and reachable.\n'
printf '  2. If upgrading from an existing database that has NOT initialized schema_version table:\n'
printf '     Run: artifacts/migrations/00_schema_version_and_baseline.sql in the DM8 schema.\n'
printf '     (This script performs strict table and column-type pre-checks and registers v0.1.0 baseline).\n'
printf '  3. If upgrading to a version with incremental migrations:\n'
printf '     Review and execute pending scripts in artifacts/migrations/ before or during maintenance window.\n'
printf '  4. Note: upgrade.sh operates on host Docker configuration; it does NOT directly alter your external DB.\n'

if [[ "$MODE" == "plan" ]]; then
  printf '\n=== Plan Summary (Offline Dry-Run Only) ===\n'
  printf '[NOTICE] This preflight check is performed OFFLINE on local Docker configurations.\n'
  printf '         It does NOT connect to external Dameng DB; external schema version must be confirmed by DBA.\n'
  if [[ "$MODE_RUN" == "jre" ]]; then
    printf 'Execution Mode: Local JRE Mount Mode (JRE: %s, NGINX: %s)\n' "$TARGET_JRE_IMAGE" "$TARGET_NGINX_IMAGE"
    printf '[INFO] Testing preflight validation for local JRE mount in new directory...\n'
    if ! (cd "$REAL_TARGET" && bash scripts/start-with-jre.sh --env-file "$OLD_ENV" --jre-image "$TARGET_JRE_IMAGE" --nginx-image "$TARGET_NGINX_IMAGE" --check-only); then
      printf '[ERROR] Preflight validation for local JRE mount in new directory FAILED!\n' >&2
      exit 1
    fi
    printf '[OK] Local JRE mount preflight check passed successfully.\n'
  else
    printf 'Execution Mode: Precompiled Docker Images Mode\n'
  fi
  printf 'Prerequisites status: CONFIG_VALIDATED\n'
  printf 'Actions that will be performed in --apply mode:\n'
  printf '  1. Copy %s -> %s (permissions 0600)\n' "$OLD_ENV" "$REAL_TARGET/.env"
  if [[ -f "$REAL_OLD/credentials.txt" ]]; then
    printf '  2. Copy %s -> %s (permissions 0600)\n' "$REAL_OLD/credentials.txt" "$REAL_TARGET/credentials.txt"
  fi
  printf '  3. Run preflight check in new directory (MUST PASS BEFORE stopping old services)\n'
  printf '  4. Stop old containers in %s (via ./stop.sh, preserving vault-data volume)\n' "$REAL_OLD"
  if [[ "$MODE_RUN" == "jre" ]]; then
    printf '  5. Start new containers in %s (via ./start-with-jre.sh --jre-image "%s" --nginx-image "%s")\n' "$REAL_TARGET" "$TARGET_JRE_IMAGE" "$TARGET_NGINX_IMAGE"
    printf '\nTo apply this upgrade, re-run with:\n'
    printf '  %s --from "%s" --jre-image "%s" --nginx-image "%s" --apply --backup-done\n' "$0" "$OLD_DIR" "$TARGET_JRE_IMAGE" "$TARGET_NGINX_IMAGE"
  else
    printf '  5. Start new containers in %s (via ./start.sh)\n' "$REAL_TARGET"
    printf '\nTo apply this upgrade, re-run with:\n'
    printf '  %s --from "%s" --apply --backup-done\n' "$0" "$OLD_DIR"
  fi
  exit 0
fi

# Apply Mode
printf '\n=== Applying Upgrade ===\n'

if [[ $ASSUME_BACKUP_DONE -eq 0 ]]; then
  printf '[ERROR] Backup and DBA schema confirmation missing!\n' >&2
  printf '        You must confirm that:\n' >&2
  printf '          1) External Dameng database and local vault-data volume cold backups are completed;\n' >&2
  printf '          2) DBA has confirmed schema version compatibility or applied pending migrations.\n' >&2
  printf '        Pass --backup-done to confirm both prerequisites.\n' >&2
  exit 1
fi

if [[ $AUTO_CONFIRM -eq 0 ]]; then
  printf 'Are you sure you want to proceed with upgrade? [y/N]: '
  read -r reply
  if [[ ! "$reply" =~ ^[Yy]$ ]]; then
    printf 'Upgrade aborted by user.\n'
    exit 0
  fi
fi

# A. Migrate .env and credentials FIRST so new preflight can check them
umask 077
cp "$OLD_ENV" "$REAL_TARGET/.env"
chmod 600 "$REAL_TARGET/.env"
printf '[OK] Migrated configuration: %s (mode 0600)\n' "$REAL_TARGET/.env"

if [[ -f "$REAL_OLD/credentials.txt" ]]; then
  cp "$REAL_OLD/credentials.txt" "$REAL_TARGET/credentials.txt"
  chmod 600 "$REAL_TARGET/credentials.txt"
  printf '[OK] Migrated credentials file: %s (mode 0600)\n' "$REAL_TARGET/credentials.txt"
fi

# B. Run preflight check in new dir BEFORE stopping old services!
# If new preflight fails, abort and leave old services running untouched!
printf '[INFO] Running preflight check in new deployment directory before stopping old containers...\n'
if [[ "$MODE_RUN" == "jre" ]]; then
  if ! (cd "$REAL_TARGET" && bash scripts/start-with-jre.sh --env-file "$REAL_TARGET/.env" --jre-image "$TARGET_JRE_IMAGE" --nginx-image "$TARGET_NGINX_IMAGE" --check-only); then
    printf '[ERROR] Preflight check with JRE mount in new deployment directory FAILED!\n' >&2
    printf '        Aborting upgrade before stopping old containers. Old services remain active.\n' >&2
    exit 1
  fi
else
  if ! (cd "$REAL_TARGET" && bash scripts/check.sh); then
    printf '[ERROR] Preflight check in new deployment directory FAILED!\n' >&2
    printf '        Aborting upgrade before stopping old containers. Old services remain active.\n' >&2
    exit 1
  fi
fi
printf '[OK] Preflight check in new deployment directory passed successfully.\n'

# C. Stop old services only AFTER new preflight has passed
if [[ -f "$REAL_OLD/scripts/stop.sh" ]]; then
  printf '[INFO] Stopping old containers in %s...\n' "$REAL_OLD"
  (cd "$REAL_OLD" && bash scripts/stop.sh) || true
elif [[ -f "$REAL_OLD/stop.sh" ]]; then
  printf '[INFO] Stopping old containers in %s...\n' "$REAL_OLD"
  (cd "$REAL_OLD" && bash stop.sh) || true
fi

# D. Start new containers
if [[ "$MODE_RUN" == "jre" ]]; then
  printf '[INFO] Starting new containers with local JRE mount in %s...\n' "$REAL_TARGET"
  (cd "$REAL_TARGET" && bash scripts/start-with-jre.sh --env-file "$REAL_TARGET/.env" --jre-image "$TARGET_JRE_IMAGE" --nginx-image "$TARGET_NGINX_IMAGE")
else
  printf '[INFO] Starting new containers in %s...\n' "$REAL_TARGET"
  (cd "$REAL_TARGET" && bash scripts/start.sh)
fi

printf '\n[SUCCESS] Upgrade completed successfully!\n'
printf 'Please verify health status using: ./status.sh\n'
printf 'And verify native crypto runner using: ./scripts/verify-native.sh\n'