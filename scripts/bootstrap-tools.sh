#!/usr/bin/env bash
set -euo pipefail
umask 077
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
TOOLS="$ROOT/.tools"
mkdir -p "$TOOLS/downloads" "$TOOLS/logs" "$TOOLS/m2/repository"

checksum() {
  local bits=$1 file=$2 expected=$3 actual
  if command -v shasum >/dev/null 2>&1; then
    actual=$(shasum -a "$bits" "$file" | awk '{print $1}')
  elif command -v "sha${bits}sum" >/dev/null 2>&1; then
    actual=$("sha${bits}sum" "$file" | awk '{print $1}')
  else
    printf 'Missing SHA%s checksum tool\n' "$bits" >&2; return 1
  fi
  [[ "$actual" == "$expected" ]] || { printf 'Checksum mismatch: %s\n' "$file" >&2; return 1; }
}

download() {
  local url=$1 file=$2 bits=$3 expected=$4
  if [[ ! -f "$file" ]]; then
    curl -fLsS --retry 2 --connect-timeout 20 --max-time 900 "$url" -o "$file.partial"
    checksum "$bits" "$file.partial" "$expected"
    [[ "$(dirname -- "$file.partial")" == "$TOOLS/downloads" && "$(dirname -- "$file")" == "$TOOLS/downloads" ]] || return 1
    mv -- "$file.partial" "$file"
  fi
  checksum "$bits" "$file" "$expected"
}

case "$(uname -s):$(uname -m)" in
  Darwin:arm64) JDK_OS=mac; JDK_ARCH=aarch64; JDK_SHA=3623232f33a9c3baadf304480b2535f9a3cba8a58d42ecbb438ba267315d9998 ;;
  Darwin:x86_64) JDK_OS=mac; JDK_ARCH=x64; JDK_SHA=44db0f08196daf19a47f90d13388b0c943b67663cb537f998fe29e836fa842ce ;;
  Linux:aarch64|Linux:arm64) JDK_OS=linux; JDK_ARCH=aarch64; JDK_SHA=23e37e026f12f3e706f18938ff611db3032d075b09d0879a25d06718c773e223 ;;
  Linux:x86_64) JDK_OS=linux; JDK_ARCH=x64; JDK_SHA=ce79869e1307ed8ee1e2baa86a412b1eb5b75d10a01006d788a6f968bcfaee94 ;;
  *) printf 'Supported bootstrap platforms: macOS/Linux arm64/x86_64\n' >&2; exit 1 ;;
esac
JDK_FILE="OpenJDK21U-jdk_${JDK_ARCH}_${JDK_OS}_hotspot_21.0.12.1_1.tar.gz"
JDK_URL="https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.12.1%2B1/$JDK_FILE"
MAVEN_VERSION=3.9.16
MAVEN_FILE="apache-maven-$MAVEN_VERSION-bin.tar.gz"
MAVEN_SHA=831a8591fe20c8243b1dbe7d71e3244f31d1665b0804b2e825e38cbbe5ce0cafb8338851f90780735568773e0a6cd07bbec107cda0b896b008b861075358b6f6
MAVEN_URL="https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/$MAVEN_VERSION/$MAVEN_FILE"

download "$JDK_URL" "$TOOLS/downloads/$JDK_FILE" 256 "$JDK_SHA"
download "$MAVEN_URL" "$TOOLS/downloads/$MAVEN_FILE" 512 "$MAVEN_SHA"
JDK_ROOT="$TOOLS/jdk-21.0.12.1+1"
if [[ "$JDK_OS" == mac ]]; then JAVA_HOME="$JDK_ROOT/Contents/Home"; else JAVA_HOME="$JDK_ROOT"; fi
MAVEN_HOME="$TOOLS/apache-maven-$MAVEN_VERSION"
if [[ ! -x "$JAVA_HOME/bin/java" ]]; then tar -xzf "$TOOLS/downloads/$JDK_FILE" -C "$TOOLS"; fi
if [[ ! -x "$MAVEN_HOME/bin/mvn" ]]; then tar -xzf "$TOOLS/downloads/$MAVEN_FILE" -C "$TOOLS"; fi
"$JAVA_HOME/bin/java" -version 2>&1 | grep -q 'version "21\.'
export JAVA_HOME MAVEN_HOME
export PATH="$JAVA_HOME/bin:$MAVEN_HOME/bin:$PATH"
{
  printf 'export JAVA_HOME=%q\n' "$JAVA_HOME"
  printf 'export MAVEN_HOME=%q\n' "$MAVEN_HOME"
  printf 'export PATH="$JAVA_HOME/bin:$MAVEN_HOME/bin:$PATH"\n'
} > "$TOOLS/env.sh"
chmod 600 "$TOOLS/env.sh"
printf 'Verified Temurin 21.0.12.1+1 (%s/%s), SHA256 %s\n' "$JDK_OS" "$JDK_ARCH" "$JDK_SHA"
printf 'Verified Maven %s, SHA512 %s\n' "$MAVEN_VERSION" "$MAVEN_SHA"
printf 'Tool environment: %s\n' "$TOOLS/env.sh"
"$JAVA_HOME/bin/java" -version
"$MAVEN_HOME/bin/mvn" --version
