#!/usr/bin/env bash
set +x
set -euo pipefail

REPO_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
DEPLOY_DIR="$REPO_ROOT/deploy/gmssl-gui-linux-amd64"
CUSTOM_RUNNER=""
SKIP_TAR=0
RELEASE_VERSION="${RELEASE_VERSION:-0.1.5}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --runner)
      if [[ $# -lt 2 || "$2" =~ ^-- ]]; then
        printf '[ERROR] Missing value for --runner\n' >&2
        exit 1
      fi
      CUSTOM_RUNNER="$2"
      shift 2
      ;;
    --version)
      if [[ $# -lt 2 || "$2" =~ ^-- ]]; then
        printf '[ERROR] Missing value for --version\n' >&2
        exit 1
      fi
      RELEASE_VERSION="$2"
      shift 2
      ;;
    --skip-tar)
      SKIP_TAR=1
      shift
      ;;
    -h|--help)
      printf 'Usage: %s [--version <version>] [--runner <path-to-linux-runner>] [--skip-tar]\n' "$0"
      exit 0
      ;;
    *)
      printf '[ERROR] Unknown argument: %s\n' "$1" >&2
      exit 1
      ;;
  esac
done

if [[ ! "$RELEASE_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  printf '[ERROR] Invalid release version: %s (expected numeric X.Y.Z)\n' "$RELEASE_VERSION" >&2
  exit 1
fi

printf '=== Packaging GmSSL GUI Linux amd64 Standalone Release (Dameng DM8 Edition) ===\n'

# 1. Allowlist source paths
ENGINE_JAR="$REPO_ROOT/engine-service/target/engine-service-0.1.0-SNAPSHOT.jar"
PLATFORM_JAR="$REPO_ROOT/platform-service/target/platform-service-0.1.0-SNAPSHOT.jar"
WEB_DIST="$REPO_ROOT/web/dist"
RUNNER_SRC="${CUSTOM_RUNNER:-"$REPO_ROOT/native/.build-linux-amd64/bin/gmssl-runner"}"
LICENSE_SRC="$REPO_ROOT/deploy/gmssl-gui-linux-amd64/artifacts/GMSSL-LICENSE"
DM_SQL_SRC="$REPO_ROOT/ops/dm8/01_schema_dm8.sql"
DM_BASELINE_SQL="$REPO_ROOT/ops/dm8/migrations/00_schema_version_and_baseline.sql"

# Verify required sources exist
for req in "$ENGINE_JAR" "$PLATFORM_JAR" "$WEB_DIST/index.html" "$DM_SQL_SRC" "$DM_BASELINE_SQL"; do
  if [[ ! -f "$req" ]]; then
    printf '[ERROR] Required build artifact missing: %s\n' "$req" >&2
    exit 1
  fi
done

if [[ ! -f "$RUNNER_SRC" ]]; then
  printf '[ERROR] Linux amd64 gmssl-runner missing: %s\n' "$RUNNER_SRC" >&2
  printf 'Please ensure task-28 has built the Linux x86_64 ELF binary via scripts/build-linux-amd64.sh\n' >&2
  exit 1
fi

if [[ ! -f "$LICENSE_SRC" ]]; then
  printf '[ERROR] Fixed GMSSL-LICENSE missing at %s; will not fallback to unverified root LICENSE.\n' "$LICENSE_SRC" >&2
  exit 1
fi

# 2. Verify runner is Linux x86_64 ELF
printf '[INFO] Verifying gmssl-runner binary architecture...\n'
ELF_CHECK=$(python3 -c '
import sys
path = sys.argv[1]
with open(path, "rb") as f:
    hdr = f.read(20)
if len(hdr) < 20:
    print("TOO_SHORT")
elif hdr[:4] == b"\x7fELF":
    ei_class = hdr[4] # 2 = 64-bit
    e_machine = int.from_bytes(hdr[18:20], "little") # 0x3E = x86_64
    if ei_class == 2 and e_machine == 0x3E:
        print("PASS")
    else:
        print(f"ELF_NOT_X86_64 (class={ei_class}, machine={hex(e_machine)})")
elif hdr[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
    print("MACHO_REJECTED")
else:
    print("INVALID_HEADER")
' "$RUNNER_SRC")

if [[ "$ELF_CHECK" != "PASS" ]]; then
  printf '[ERROR] Binary architecture validation failed for %s: %s\n' "$RUNNER_SRC" "$ELF_CHECK" >&2
  exit 1
fi
printf '[OK] gmssl-runner verified as Linux x86_64 ELF binary.\n'

# 3. Prepare target artifacts directory
mkdir -p "$DEPLOY_DIR/artifacts" "$DEPLOY_DIR/artifacts/migrations" "$DEPLOY_DIR/scripts"

# Realpath and symlink validation before any rm -rf
TARGET_WEB_DIST="$DEPLOY_DIR/artifacts/web-dist"
REAL_DEPLOY=$(cd "$DEPLOY_DIR" && pwd -P)
if [[ -L "$TARGET_WEB_DIST" ]]; then
  printf '[ERROR] %s is a symlink! Aborting to prevent symlink escape.\n' "$TARGET_WEB_DIST" >&2
  exit 1
fi
if [[ -e "$TARGET_WEB_DIST" ]]; then
  REAL_WEB_DIST=$(cd "$TARGET_WEB_DIST" && pwd -P)
  if [[ "$REAL_WEB_DIST" != "$REAL_DEPLOY/artifacts/web-dist" ]]; then
    printf '[ERROR] Realpath mismatch for %s (%s vs %s)! Aborting.\n' "$TARGET_WEB_DIST" "$REAL_WEB_DIST" "$REAL_DEPLOY/artifacts/web-dist" >&2
    exit 1
  fi
  rm -rf "$TARGET_WEB_DIST"
fi

printf '[INFO] Copying allowlisted precompiled artifacts...\n'
cp "$ENGINE_JAR" "$DEPLOY_DIR/artifacts/engine-service-0.1.0-SNAPSHOT.jar"
cp "$PLATFORM_JAR" "$DEPLOY_DIR/artifacts/platform-service-0.1.0-SNAPSHOT.jar"
cp "$RUNNER_SRC" "$DEPLOY_DIR/artifacts/gmssl-runner"
cp "$DM_SQL_SRC" "$DEPLOY_DIR/artifacts/01_schema_dm8.sql"
cp "$DM_BASELINE_SQL" "$DEPLOY_DIR/artifacts/migrations/00_schema_version_and_baseline.sql"
cp "$REPO_ROOT/docs/离线部署说明.md" "$DEPLOY_DIR/离线部署说明.md"
cp "$REPO_ROOT/docs/离线更新说明.md" "$DEPLOY_DIR/离线更新说明.md"
cp "$REPO_ROOT/scripts/build-offline-images.sh" "$DEPLOY_DIR/scripts/build-offline-images.sh"
cp "$REPO_ROOT/scripts/build-offline-images.sh" "$DEPLOY_DIR/build-offline-images.sh"
chmod +x "$DEPLOY_DIR/scripts/build-offline-images.sh" "$DEPLOY_DIR/build-offline-images.sh"
cp "$REPO_ROOT/compose.jre.yaml" "$DEPLOY_DIR/compose.jre.yaml"
chmod 644 "$DEPLOY_DIR/compose.jre.yaml"
cp "$REPO_ROOT/scripts/start-with-jre.sh" "$DEPLOY_DIR/scripts/start-with-jre.sh"
chmod 755 "$DEPLOY_DIR/scripts/start-with-jre.sh" "$DEPLOY_DIR/start-with-jre.sh"
chmod 755 "$DEPLOY_DIR/artifacts" "$DEPLOY_DIR/artifacts/gmssl-runner"
chmod 644 "$DEPLOY_DIR/artifacts/"*.jar "$DEPLOY_DIR/artifacts/GMSSL-LICENSE" "$DEPLOY_DIR/compose.yaml" "$DEPLOY_DIR/compose.jre.yaml"
chmod 644 "$DEPLOY_DIR/离线部署说明.md" "$DEPLOY_DIR/离线更新说明.md"
chmod 755 "$DEPLOY_DIR/upgrade.sh" "$DEPLOY_DIR/scripts/upgrade.sh"

# Copy web-dist cleanly
cp -r "$WEB_DIST" "$DEPLOY_DIR/artifacts/web-dist"

# 4. Strict exclusion security check (Rejecting symlinks, secrets, dev artifacts, and Mach-O)
printf '[INFO] Performing strict exclusion security audit on release tree...\n'
LEAK_FOUND=0
while IFS= read -r file; do
  rel="${file#$DEPLOY_DIR/}"
  # Reject any symlinks in the release tree
  if [[ -L "$file" ]]; then
    printf '[SECURITY ERROR] Symlink detected in release tree: %s\n' "$rel" >&2
    LEAK_FOUND=1
  fi
  # Check forbidden patterns
  if [[ "$rel" =~ (^|/)\.env($|\.) && "$rel" != ".env.example" ]]; then
    printf '[SECURITY ERROR] Forbidden env file found: %s\n' "$rel" >&2
    LEAK_FOUND=1
  elif [[ "$rel" =~ credentials\.txt ]]; then
    printf '[SECURITY ERROR] Forbidden credentials file found: %s\n' "$rel" >&2
    LEAK_FOUND=1
  elif [[ "$rel" =~ \.mv\.db$ ]]; then
    printf '[SECURITY ERROR] Forbidden database file found: %s\n' "$rel" >&2
    LEAK_FOUND=1
  elif [[ "$rel" =~ (^|/)node_modules(/|$) ]]; then
    printf '[SECURITY ERROR] Forbidden node_modules found: %s\n' "$rel" >&2
    LEAK_FOUND=1
  elif [[ "$rel" =~ (^|/)(\.git|\.tools|\.runtime)(/|$) ]]; then
    printf '[SECURITY ERROR] Forbidden dev directory found: %s\n' "$rel" >&2
    LEAK_FOUND=1
  elif [[ "$rel" =~ \.(java|ts|vue|c|h)$ || "$rel" =~ (pom\.xml|package\.json)$ ]]; then
    printf '[SECURITY ERROR] Forbidden source code file found: %s\n' "$rel" >&2
    LEAK_FOUND=1
  fi
done < <(find "$DEPLOY_DIR" -type f -o -type l)

# Check all files for Mach-O magic bytes portably via Python (compatible with BSD and GNU)
while IFS= read -r anyfile; do
  if python3 -c '
import sys
try:
    with open(sys.argv[1], "rb") as f:
        h = f.read(4)
    if h in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        sys.exit(0)
except Exception:
    pass
sys.exit(1)
' "$anyfile" 2>/dev/null; then
    printf '[SECURITY ERROR] Mach-O binary detected in release tree: %s\n' "$anyfile" >&2
    LEAK_FOUND=1
  fi
done < <(find "$DEPLOY_DIR" -type f)

if [[ $LEAK_FOUND -ne 0 ]]; then
  printf '[ERROR] Strict exclusion audit failed! Release packaging aborted.\n' >&2
  exit 1
fi
printf '[OK] Strict exclusion audit passed: Zero secrets, zero source code, zero Mach-O files.\n'

# 5. Remove legacy SHA256SUMS and outer tar.sha256 per user hard requirement (No file-hash barriers)
rm -f "$DEPLOY_DIR/SHA256SUMS" "$REPO_ROOT/deploy/gmssl-gui-linux-amd64.tar.gz.sha256"

# 6. Generate manifest.json (Package inventory and runtime base images, without hash verification enforcement)
printf '[INFO] Generating manifest.json inventory...\n'
python3 -c '
import json, os, sys, datetime

deploy_dir = sys.argv[1]
release_ver = sys.argv[2]
manifest_file = os.path.join(deploy_dir, "manifest.json")

artifacts = {}
for root, _, files in os.walk(os.path.join(deploy_dir, "artifacts")):
    for f in files:
        full_path = os.path.join(root, f)
        rel_path = os.path.relpath(full_path, deploy_dir)
        sz = os.path.getsize(full_path)
        artifacts[rel_path] = {"size": sz}

manifest = {
    "name": "gmssl-gui-linux-amd64",
    "version": release_ver,
    "target_architecture": "linux-amd64",
    "delivery_model": "precompiled-docker-compose-dm8",
    "database": "Dameng Database (DM8) External Connection",
    "verification_mode": "offline-structure-only",
    "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "runtime_base_images": {
        "engine": "gmssl-gui/engine:0.1.0-linux-amd64 (base: eclipse-temurin:21-jre-jammy)",
        "platform": "gmssl-gui/platform:0.1.0-linux-amd64 (base: eclipse-temurin:21-jre-jammy)",
        "web": "gmssl-gui/web:0.1.0-linux-amd64 (base: nginx:1.28-alpine)"
    },
    "artifacts": artifacts
}

with open(manifest_file, "w") as fp:
    json.dump(manifest, fp, indent=2)

print(f"Saved manifest.json successfully (version: {release_ver}).")
' "$DEPLOY_DIR" "$RELEASE_VERSION"

# 7. Create tar.gz distribution archive (pure tar archive, no outer .sha256 file)
if [[ $SKIP_TAR -eq 0 ]]; then
  ARCHIVE_TAR="$REPO_ROOT/deploy/gmssl-gui-linux-${RELEASE_VERSION}.tar.gz"
  printf '[INFO] Creating compressed distribution archive: %s...\n' "$ARCHIVE_TAR"
  tar -czf "$ARCHIVE_TAR" -C "$REPO_ROOT/deploy" gmssl-gui-linux-amd64
  TAR_SIZE=$(du -h "$ARCHIVE_TAR" | cut -f 1)
  printf '[SUCCESS] Release archive created: %s (%s)\n' "$ARCHIVE_TAR" "$TAR_SIZE"
fi

printf '=== Packaging Complete: deploy/gmssl-gui-linux-amd64 is ready for distribution ===\n'