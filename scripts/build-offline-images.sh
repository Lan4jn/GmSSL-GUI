#!/usr/bin/env bash
set +x
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
# If running inside standalone deploy directory:
if [[ -f "$SCRIPT_DIR/compose.yaml" || -f "$SCRIPT_DIR/.env.example" ]]; then
  DEPLOY_DIR="$SCRIPT_DIR"
elif [[ -f "$SCRIPT_DIR/../compose.yaml" || -f "$SCRIPT_DIR/../.env.example" ]]; then
  DEPLOY_DIR=$(cd "$SCRIPT_DIR/.." && pwd -P)
else
  # Running from source repo scripts/
  REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd -P)
  DEPLOY_DIR="$REPO_ROOT/deploy/gmssl-gui-linux-amd64"
fi

IMAGES_DIR="$DEPLOY_DIR/images"
TAR_OUTPUT=""
CUSTOM_JRE=""

print_usage() {
  cat << 'EOF'
Usage: ./build-offline-images.sh [options] [tar_output_path]

Options:
  --jre-image <image>  Explicit base JRE image to use for engine & platform images
                       (e.g. local.registry:5000/custom/java:21).
                       Priority: CLI argument > JRE_IMAGE env variable > default.
  -h, --help           Show this help message.

Environment Variables:
  JRE_IMAGE            Optional default JRE image if --jre-image is omitted.

Prerequisites & Compatibility:
  - Base JRE image MUST be Java 21+ on Linux amd64.
  - Base JRE image for engine MUST be a Debian/Ubuntu derived image with apt package manager
    or have openssl CLI, groupadd/useradd installed, and write access to /app and /work.
  - Arbitrary Alpine/BusyBox/UBI images lacking apt or groupadd will fail build clearly.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --jre-image)
      if [[ $# -lt 2 || -z "$2" ]]; then
        printf '[ERROR] Missing value for --jre-image\n' >&2
        print_usage
        exit 1
      fi
      CUSTOM_JRE="$2"
      shift 2
      ;;
    -h|--help)
      print_usage
      exit 0
      ;;
    *)
      if [[ -z "$TAR_OUTPUT" ]]; then
        TAR_OUTPUT="$1"
        shift
      else
        printf '[ERROR] Unknown argument: %s\n' "$1" >&2
        print_usage
        exit 1
      fi
      ;;
  esac
done

# Resolve JRE image by priority: CLI > JRE_IMAGE env > default
EFFECTIVE_JRE="${CUSTOM_JRE:-${JRE_IMAGE:-"eclipse-temurin:21-jre-jammy"}}"
TAR_OUTPUT="${TAR_OUTPUT:-"$DEPLOY_DIR/gmssl-gui-images-linux-amd64.tar"}"

printf '=== GmSSL GUI Offline Docker Images Exporter (Build Node) ===\n'
printf '[INFO] Deploy context:    %s\n' "$DEPLOY_DIR"
printf '[INFO] Effective JRE:     %s\n' "$EFFECTIVE_JRE"
printf '[INFO] Target output tar: %s\n\n' "$TAR_OUTPUT"

if ! command -v docker >/dev/null 2>&1; then
  printf '[ERROR] Docker Engine is required to build and save offline images.\n' >&2
  exit 1
fi

mkdir -p "$IMAGES_DIR"
mkdir -p "$(dirname "$TAR_OUTPUT")"

TAG_ENGINE="gmssl-gui/engine:0.1.0-linux-amd64"
TAG_PLATFORM="gmssl-gui/platform:0.1.0-linux-amd64"
TAG_WEB="gmssl-gui/web:0.1.0-linux-amd64"

printf '[1/4] Building engine image: %s (base JRE: %s)...\n' "$TAG_ENGINE" "$EFFECTIVE_JRE"
docker build --platform linux/amd64 \
  --build-arg BASE_JRE_IMAGE="$EFFECTIVE_JRE" \
  -t "$TAG_ENGINE" \
  -f "$DEPLOY_DIR/docker/engine.Dockerfile" \
  "$DEPLOY_DIR"

printf '[2/4] Building platform image: %s (base JRE: %s)...\n' "$TAG_PLATFORM" "$EFFECTIVE_JRE"
docker build --platform linux/amd64 \
  --build-arg BASE_JRE_IMAGE="$EFFECTIVE_JRE" \
  -t "$TAG_PLATFORM" \
  -f "$DEPLOY_DIR/docker/platform.Dockerfile" \
  "$DEPLOY_DIR"

printf '[3/4] Building web image: %s...\n' "$TAG_WEB"
docker build --platform linux/amd64 \
  -t "$TAG_WEB" \
  -f "$DEPLOY_DIR/docker/web.Dockerfile" \
  "$DEPLOY_DIR"

printf '[4/4] Saving all runtime images to: %s...\n' "$TAR_OUTPUT"
docker save -o "$TAR_OUTPUT" "$TAG_ENGINE" "$TAG_PLATFORM" "$TAG_WEB"

SZ=$(du -h "$TAR_OUTPUT" | cut -f 1)
printf '\n[SUCCESS] Offline images archive created successfully: %s (%s)\n' "$TAR_OUTPUT" "$SZ"
printf '[INFO] Transport %s to your isolated internal network host.\n' "$TAR_OUTPUT"
printf '[INFO] On internal host, run: ./load-images.sh %s (or docker load -i %s)\n' "$TAR_OUTPUT" "$TAR_OUTPUT"
