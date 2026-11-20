#!/usr/bin/env bash
set +x
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
DEPLOY_DIR=$(cd -- "$SCRIPT_DIR/.." && pwd -P)

printf '=== GmSSL GUI Linux amd64 Deployment Environment Check ===\n'

HAS_ERRORS=0

# 1. Check host OS and architecture (Must be Linux x86_64)
# Allow ALLOW_CROSS_CHECK=1 for verification / packaging in non-Linux environments
ALLOW_CROSS="${ALLOW_CROSS_CHECK:-0}"
HOST_OS=$(uname -s 2>/dev/null || echo "UNKNOWN")
HOST_ARCH=$(uname -m 2>/dev/null || echo "UNKNOWN")

if [[ "$HOST_OS" != "Linux" || "$HOST_ARCH" != "x86_64" ]]; then
  if [[ "$ALLOW_CROSS" == "1" ]]; then
    printf '[WARN] Non-Linux x86_64 host detected (%s %s), but ALLOW_CROSS_CHECK=1; continuing verification.\n' "$HOST_OS" "$HOST_ARCH"
  else
    printf '[ERROR] Host platform mismatch: Current system is %s %s. This package requires Linux x86_64.\n' "$HOST_OS" "$HOST_ARCH" >&2
    printf '[ERROR] For local packaging or cross-verification only, set ALLOW_CROSS_CHECK=1.\n' >&2
    HAS_ERRORS=1
  fi
else
  printf '[OK] Host platform matches target: Linux x86_64.\n'
fi

# 2. Check gmssl-runner binary architecture (Must be Linux x86_64 ELF)
RUNNER_BIN="$DEPLOY_DIR/artifacts/gmssl-runner"
if [[ ! -f "$RUNNER_BIN" ]]; then
  printf '[ERROR] Artifact missing: %s\n' "$RUNNER_BIN" >&2
  HAS_ERRORS=1
else
  # Validate ELF 64-bit x86-64 binary header
  IS_ELF_X86_64="UNKNOWN"
  if command -v python3 >/dev/null 2>&1; then
    IS_ELF_X86_64=$(python3 -c '
import sys
try:
    with open(sys.argv[1], "rb") as f:
        hdr = f.read(20)
    if len(hdr) < 20:
        print("TOO_SHORT")
    elif hdr[:4] == b"\x7fELF":
        ei_class = hdr[4] # 2 = 64-bit
        e_machine = int.from_bytes(hdr[18:20], "little") # 0x3E = x86_64
        if ei_class == 2 and e_machine == 0x3E:
            print("ELF_X86_64")
        else:
            print(f"ELF_OTHER_{ei_class}_{e_machine}")
    elif hdr[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        print("MACHO")
    else:
        print("UNKNOWN")
except Exception as e:
    print(f"ERROR_{e}")
' "$RUNNER_BIN")
  else
    if file "$RUNNER_BIN" 2>/dev/null | grep -qi "ELF 64-bit.*x86-64"; then
      IS_ELF_X86_64="ELF_X86_64"
    elif file "$RUNNER_BIN" 2>/dev/null | grep -qi "Mach-O"; then
      IS_ELF_X86_64="MACHO"
    fi
  fi

  if [[ "$IS_ELF_X86_64" == "ELF_X86_64" ]]; then
    printf '[OK] gmssl-runner is verified Linux x86_64 ELF binary.\n'
  elif [[ "$IS_ELF_X86_64" == "MACHO" ]]; then
    printf '[ERROR] gmssl-runner is a macOS Mach-O binary! Must be Linux x86_64 ELF.\n' >&2
    HAS_ERRORS=1
  else
    printf '[ERROR] gmssl-runner is not a valid Linux x86_64 ELF binary (%s).\n' "$IS_ELF_X86_64" >&2
    HAS_ERRORS=1
  fi
fi

# 3. Check required offline release artifacts existence (zero network, zero file-hash barrier)
REQUIRED_ARTIFACTS=(
  "$DEPLOY_DIR/artifacts/engine-service-0.1.0-SNAPSHOT.jar"
  "$DEPLOY_DIR/artifacts/platform-service-0.1.0-SNAPSHOT.jar"
  "$DEPLOY_DIR/artifacts/gmssl-runner"
  "$DEPLOY_DIR/artifacts/01_schema_dm8.sql"
  "$DEPLOY_DIR/artifacts/web-dist/index.html"
)
for art in "${REQUIRED_ARTIFACTS[@]}"; do
  if [[ ! -e "$art" ]]; then
    printf '[ERROR] Required release artifact missing: %s\n' "$art" >&2
    HAS_ERRORS=1
  fi
done
if [[ $HAS_ERRORS -eq 0 ]]; then
  printf '[OK] All required offline release artifacts present.\n'
fi

# 4. Check Docker
if command -v docker >/dev/null 2>&1; then
  DOCKER_VER=$(docker --version 2>&1 | head -n 1)
  printf '[OK] Docker found: %s\n' "$DOCKER_VER"
else
  printf '[ERROR] Docker is not installed or not in PATH.\n' >&2
  HAS_ERRORS=1
fi

# 5. Check Docker Compose (Requires Compose V2: docker compose)
if docker compose version >/dev/null 2>&1; then
  COMPOSE_VER=$(docker compose version 2>&1 | head -n 1)
  printf '[OK] Docker Compose V2 found: %s\n' "$COMPOSE_VER"
else
  printf '[ERROR] Docker Compose V2 (`docker compose`) is required. Compose V1 is not supported.\n' >&2
  HAS_ERRORS=1
fi

# 6. Check OpenSSL
if command -v openssl >/dev/null 2>&1; then
  printf '[OK] OpenSSL found: %s\n' "$(openssl version 2>&1 | head -n 1)"
else
  printf '[WARN] OpenSSL not found on host (needed only for ./init.sh random token generation).\n'
fi


# 7. Check Dameng (DM8) Database Configuration
if [[ -f "$DEPLOY_DIR/.env" ]]; then
  ENV_PERM=$(perl -e 'printf "%o", (stat(shift))[2] & 0777' "$DEPLOY_DIR/.env" 2>/dev/null || stat -c "%a" "$DEPLOY_DIR/.env" 2>/dev/null || stat -f "%Lp" "$DEPLOY_DIR/.env" 2>/dev/null || echo "")
  if [[ -n "$ENV_PERM" && "$ENV_PERM" =~ [0-7][0-7][1-7] ]]; then
    printf '[WARN] .env has insecure permissions (%s). Recommended: chmod 600 .env\n' "$ENV_PERM"
  else
    printf '[OK] .env configuration present with secure permissions.\n'
  fi

  DM_URL=$(grep -E '^[[:space:]]*SPRING_DATASOURCE_URL=' "$DEPLOY_DIR/.env" | cut -d '=' -f 2- | tr -d '"\r\n' || echo "")
  DM_USER=$(grep -E '^[[:space:]]*SPRING_DATASOURCE_USERNAME=' "$DEPLOY_DIR/.env" | cut -d '=' -f 2- | tr -d '"\r\n' || echo "")
  DM_PASS=$(grep -E '^[[:space:]]*SPRING_DATASOURCE_PASSWORD=' "$DEPLOY_DIR/.env" | cut -d '=' -f 2- | tr -d "\r\n" | sed -e "s/^'//" -e "s/'\$//" -e 's/^"//' -e 's/"\$//' || echo "")
  DM_PROFILE=$(grep -E '^[[:space:]]*SPRING_PROFILES_ACTIVE=' "$DEPLOY_DIR/.env" | cut -d '=' -f 2- | tr -d '"\r\n' || echo "")

  if [[ -z "$DM_URL" || "$DM_URL" == *"YOUR_DM8_HOST"* || "$DM_URL" == *"YOUR_SCHEMA"* ]]; then
    printf '[ERROR] Dameng (DM8) database configuration incomplete in %s:\n' "$DEPLOY_DIR/.env" >&2
    printf '        SPRING_DATASOURCE_URL contains placeholder values (%s).\n' "$DM_URL" >&2
    printf '        Please configure your external DM8 connection parameters.\n' >&2
    HAS_ERRORS=1
  elif [[ "$DM_URL" != jdbc:dm://* ]]; then
    printf '[ERROR] Invalid database configuration in %s:\n' "$DEPLOY_DIR/.env" >&2
    printf '        SPRING_DATASOURCE_URL must be a valid DM8 JDBC URL starting with jdbc:dm:// (got: %s).\n' "$DM_URL" >&2
    printf '        Embedded H2 and PostgreSQL fallback are strictly forbidden in this release.\n' >&2
    HAS_ERRORS=1
  else
    printf '[OK] SPRING_DATASOURCE_URL is configured for Dameng DM8: %s\n' "$DM_URL"
  fi

  if [[ "$DM_USER" == *"YOUR_DM8_USERNAME"* || -z "$DM_USER" ]]; then
    printf '[ERROR] SPRING_DATASOURCE_USERNAME is empty or contains placeholder in %s.\n' "$DEPLOY_DIR/.env" >&2
    HAS_ERRORS=1
  fi
  if [[ "$DM_PASS" == *"YOUR_DM8_PASSWORD"* || -z "$DM_PASS" ]]; then
    printf '[ERROR] SPRING_DATASOURCE_PASSWORD is empty or contains placeholder in %s.\n' "$DEPLOY_DIR/.env" >&2
    HAS_ERRORS=1
  fi
  if [[ "$DM_PROFILE" != *"dm"* ]]; then
    printf '[ERROR] SPRING_PROFILES_ACTIVE must include "dm" (got: %s) in %s.\n' "$DM_PROFILE" "$DEPLOY_DIR/.env" >&2
    HAS_ERRORS=1
  fi
else
  printf '[INFO] .env not found. Run ./init.sh to generate secure configuration.\n'
fi

if [[ $HAS_ERRORS -ne 0 ]]; then
  printf '=== Check Finished with Errors. ===\n' >&2
  exit 1
fi

printf '=== Check Complete: Ready for deployment. ===\n'
exit 0