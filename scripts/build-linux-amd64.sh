#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
BUILD_DIR="${REPO_ROOT}/native/.build-linux-amd64"
LOG_DIR="${REPO_ROOT}/.tools/logs"
TOOLCHAIN_FILE="${REPO_ROOT}/ops/cmake/linux-amd64-zig.cmake"

mkdir -p "${LOG_DIR}"

printf '=== Building GmSSL Runner for Linux x86_64 (Release musl static, portable baseline) ===\n'

# 1. Locate Zig compiler
if [[ -n "${ZIG_BIN:-}" && -x "${ZIG_BIN}" ]]; then
  ZIG_EXECUTABLE="${ZIG_BIN}"
elif [[ -x "/opt/homebrew/bin/zig" ]]; then
  ZIG_EXECUTABLE="/opt/homebrew/bin/zig"
elif command -v zig >/dev/null 2>&1; then
  ZIG_EXECUTABLE=$(command -v zig)
else
  printf '[ERROR] zig compiler not found (expected at /opt/homebrew/bin/zig or in PATH)\n' >&2
  exit 1
fi

ZIG_VER=$("${ZIG_EXECUTABLE}" version)
printf '[INFO] Using Zig compiler: %s (version: %s)\n' "${ZIG_EXECUTABLE}" "${ZIG_VER}"

# Export for wrapper scripts
export ZIG_BIN="${ZIG_EXECUTABLE}"

# 2. Locate pristine upstream checkout: priority GMSSL_SOURCE_DIR -> repo cache -> historical tmp
if [[ -n "${GMSSL_SOURCE_DIR:-}" && -d "${GMSSL_SOURCE_DIR}" ]]; then
  SOURCE_DIR="${GMSSL_SOURCE_DIR}"
elif [[ -d "${REPO_ROOT}/native/.cache/upstream" ]]; then
  SOURCE_DIR="${REPO_ROOT}/native/.cache/upstream"
elif [[ -d "/tmp/gmssl-review.V5gpYG/upstream" ]]; then
  SOURCE_DIR="/tmp/gmssl-review.V5gpYG/upstream"
else
  printf '[ERROR] GmSSL upstream source checkout not found.\n' >&2
  printf '        Set GMSSL_SOURCE_DIR or run: python3 native/fetch-source.py\n' >&2
  exit 1
fi

EXPECTED_COMMIT="24ae482701a7b124826c382fffc55c19f76d475d"
ACTUAL_COMMIT=$(git -C "${SOURCE_DIR}" rev-parse HEAD 2>/dev/null || true)
if [[ "${ACTUAL_COMMIT}" != "${EXPECTED_COMMIT}" ]]; then
  printf '[ERROR] Upstream source commit mismatch at %s (expected %s, got %s)\n' "${SOURCE_DIR}" "${EXPECTED_COMMIT}" "${ACTUAL_COMMIT}" >&2
  exit 1
fi
printf '[INFO] Verified upstream source at %s (commit %s)\n' "${SOURCE_DIR}" "${ACTUAL_COMMIT:0:8}"

# 3. Configure via CMake (Strictly aligned with ops/engine.Dockerfile release portable profile)
printf '[INFO] Configuring CMake in %s...\n' "${BUILD_DIR}"
cmake -S "${REPO_ROOT}/native" -B "${BUILD_DIR}" \
  -DCMAKE_TOOLCHAIN_FILE="${TOOLCHAIN_FILE}" \
  -DGMSSL_SOURCE_DIR="${SOURCE_DIR}" \
  -DCMAKE_BUILD_TYPE=Release \
  -DENABLE_SM2_AMD64=OFF \
  -DENABLE_SM3_SSE=OFF \
  -DENABLE_SM4_AVX2=OFF \
  -DENABLE_SM4_AESNI=OFF \
  -DENABLE_SM4_CTR_AESNI_AVX=OFF \
  2>&1 | tee "${LOG_DIR}/linux-release-native-configure.log"

# 4. Build gmssl-runner
printf '[INFO] Building target gmssl-runner...\n'
cmake --build "${BUILD_DIR}" --target gmssl-runner 2>&1 | tee "${LOG_DIR}/linux-release-native-build.log"

RUNNER_BIN="${BUILD_DIR}/bin/gmssl-runner"
if [[ ! -f "${RUNNER_BIN}" ]]; then
  printf '[ERROR] Build output missing: %s\n' "${RUNNER_BIN}" >&2
  exit 1
fi

# 5. Inspection and Verification
printf '\n=== Verification of Built ELF Binary ===\n'
RUNNER_TYPE=$(file "${RUNNER_BIN}")
printf '[INFO] file output: %s\n' "${RUNNER_TYPE}"
if [[ "${RUNNER_TYPE}" != *"ELF 64-bit"* ]] || [[ "${RUNNER_TYPE}" != *"x86-64"* ]]; then
  printf '[ERROR] Output is not Linux x86_64 ELF!\n' >&2
  exit 1
fi

# Optional Darwin check: only run otool if available on macOS host
if command -v otool >/dev/null 2>&1; then
  OTOOL_OUT=$(otool -L "${RUNNER_BIN}" 2>&1 || true)
  if [[ "${OTOOL_OUT}" != *"is not an object file"* && "${OTOOL_OUT}" != *"not a Mach-O"* ]]; then
    printf '[ERROR] Unexpected otool output, binary might be Mach-O: %s\n' "${OTOOL_OUT}" >&2
    exit 1
  fi
  printf '[INFO] otool check (Darwin): confirmed not Mach-O / no macOS dylib dependency\n'
else
  printf '[INFO] otool not present (non-Darwin host), skipping Mach-O check\n'
fi

# Platform-independent ELF verification via Python
python3 -c '
import struct, sys

bin_path = sys.argv[1]
with open(bin_path, "rb") as f:
    hdr = f.read(64)
    magic = hdr[:4]
    assert magic == b"\x7fELF", "Bad magic"
    ei_class = hdr[4] # 2 = 64-bit
    ei_data = hdr[5] # 1 = little-endian
    ei_osabi = hdr[7]
    e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = struct.unpack("<HHIQQQIHHHHHH", hdr[16:64])
    assert e_machine == 62, f"Bad machine: {e_machine} (expected 62 EM_X86_64)"
    assert ei_class == 2, "Not 64-bit"
    
    f.seek(e_phoff)
    has_interp = False
    has_dynamic = False
    for i in range(e_phnum):
        ph = f.read(e_phentsize)
        p_type = struct.unpack("<I", ph[:4])[0]
        if p_type == 3: # PT_INTERP
            has_interp = True
        elif p_type == 2: # PT_DYNAMIC
            has_dynamic = True
    assert not has_interp, "Binary has PT_INTERP (not statically linked)"
    assert not has_dynamic, "Binary has PT_DYNAMIC (not statically linked)"
    print("[INFO] Python ELF parse: verified ELF64, EM_X86_64 (62), statically linked (no PT_INTERP, no PT_DYNAMIC)")
' "${RUNNER_BIN}"

SHA256_HEX=$(shasum -a 256 "${RUNNER_BIN}" 2>/dev/null | awk '{print $1}' || sha256sum "${RUNNER_BIN}" | awk '{print $1}')
FILE_SIZE=$(du -h "${RUNNER_BIN}" | cut -f 1)
printf '[SUCCESS] Linux amd64 runner built successfully (portable Release baseline):\n'
printf '          Path:   %s\n' "${RUNNER_BIN}"
printf '          Size:   %s\n' "${FILE_SIZE}"
printf '          SHA256: %s\n' "${SHA256_HEX}"
