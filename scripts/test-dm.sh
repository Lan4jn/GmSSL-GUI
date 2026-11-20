#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
LOG_DIR="${REPO_ROOT}/.tools/logs/dm-acceptance"
mkdir -p "${LOG_DIR}"

printf '=== DM8 Database Acceptance Verification Runner ===\n'

ENV_FILE="${REPO_ROOT}/.env.dm-test"

if [[ ! -f "${ENV_FILE}" ]]; then
  printf '[INFO] Status: NOT_RUN\n'
  printf '       .env.dm-test is not present. Awaiting user configuration of dedicated DM8 instance.\n'
  printf '       Refer to docs/DM8-CONNECTION.md and .env.dm-test.example.\n'
  
  cat << 'EOF' > "${LOG_DIR}/run_summary.json"
{
  "status": "NOT_RUN",
  "reason": ".env.dm-test not configured by user",
  "dm8_tests_executed": 0,
  "dm8_tests_passed": 0
}
EOF
  exit 0
fi

# Ensure 0600 permissions
chmod 600 "${ENV_FILE}" 2>/dev/null || true

# 1. Run Python safety checks
printf '[INFO] Running security boundary & safety checks on .env.dm-test...\n'
python3 "${REPO_ROOT}/tests/dm/harness.py"

# 2. Locate DmJdbcDriver18 JAR
DM_JAR="${REPO_ROOT}/.tools/logs/dm-dependency/DmJdbcDriver18-8.1.3.140.jar"
if [[ ! -f "${DM_JAR}" ]]; then
  DM_JAR="${REPO_ROOT}/.tools/m2/repository/com/dameng/DmJdbcDriver18/8.1.3.140/DmJdbcDriver18-8.1.3.140.jar"
fi

if [[ ! -f "${DM_JAR}" ]]; then
  printf '[ERROR] DmJdbcDriver18-8.1.3.140.jar not found! Run scripts/mvn.sh dependency:get first.\n' >&2
  exit 1
fi
printf '[INFO] Found DM8 JDBC driver: %s\n' "${DM_JAR}"

# 3. Locate JDK 21 compiler and runtime from .tools
if [[ -f "${REPO_ROOT}/.tools/env.sh" ]]; then
  source "${REPO_ROOT}/.tools/env.sh"
fi

JAVA_BIN="${JAVA_HOME:-}/bin/java"
JAVAC_BIN="${JAVA_HOME:-}/bin/javac"

if [[ ! -x "${JAVAC_BIN}" ]]; then
  JAVAC_BIN=$(command -v javac)
  JAVA_BIN=$(command -v java)
fi

printf '[INFO] Using Java Compiler: %s (%s)\n' "${JAVAC_BIN}" "$("${JAVAC_BIN}" -version 2>&1)"

printf '[INFO] Compiling Dm8CompatibilityHarness...\n'
mkdir -p "${REPO_ROOT}/tests/dm/target"
"${JAVAC_BIN}" -cp "${DM_JAR}" -d "${REPO_ROOT}/tests/dm/target"   "${REPO_ROOT}/tests/dm/src/org/gmssl/gui/platform/dm/Dm8CompatibilityHarness.java"

printf '[INFO] Compilation SUCCESS (Green).\n'

# 4. Read credentials safely into environment via Python (no shell eval/expansion)
eval $(python3 -c '
import pathlib, shlex

env_path = pathlib.Path("'"${ENV_FILE}"'")
for line in env_path.read_text(encoding="utf-8").splitlines():
    line = line.strip()
    if not line or line.startswith("#"):
        continue
    if "=" in line:
        k, v = line.split("=", 1)
        k, v = k.strip(), v.strip()
        if (v.startswith(""") and v.endswith(""")) or (v.startswith("'") and v.endswith("'")):
            v = v[1:-1]
        print(f"export {k}={shlex.quote(v)}")
')

# 5. Execute Harness
printf '[INFO] Executing DM8 Acceptance Test Suite...\n'
"${JAVA_BIN}" -cp "${REPO_ROOT}/tests/dm/target:${DM_JAR}"   org.gmssl.gui.platform.dm.Dm8CompatibilityHarness 2>&1 | tee "${LOG_DIR}/dm-acceptance-execution.log"

chmod 600 "${LOG_DIR}/dm-acceptance-execution.log" 2>/dev/null || true
printf '[SUCCESS] DM8 Acceptance Suite execution finished.\n'
