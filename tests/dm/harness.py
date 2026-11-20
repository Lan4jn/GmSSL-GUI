#!/usr/bin/env python3
"""
DM8 Database Acceptance Test Harness (Isolated & Secure)
SPDX-License-Identifier: Apache-2.0

Responsibilities:
1. Safely parses .env.dm-test without shell eval/source.
2. Enforces security boundary: schema must match regex GMSSL_TEST(_[A-Z0-9_]+)?, rejects SYSDBA/SYS.
3. Does NOT print raw connection passwords, full URLs, or raw SQL errors containing secrets.
"""

import os
import sys
import re
import json
import pathlib

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
LOG_DIR = REPO_ROOT / ".tools" / "logs" / "dm-acceptance"
LOG_DIR.mkdir(parents=True, exist_ok=True)

ENV_FILE = REPO_ROOT / ".env.dm-test"

def parse_dotenv(path: pathlib.Path) -> dict:
    """Robust dotenv parser without shell eval/expansion."""
    data = {}
    if not path.is_file():
        return data
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            key, val = line.split("=", 1)
            key = key.strip()
            val = val.strip()
            if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
                val = val[1:-1]
            data[key] = val
    return data

def sanitize_url(url: str) -> str:
    """Mask host/ip and credentials if any from JDBC URL."""
    if not url:
        return ""
    return re.sub(r'//[^:/?]+:', '//***:', url)

def check_security_rules(env: dict) -> tuple[bool, str]:
    """Validate safety boundaries for target DM instance."""
    schema = env.get("DM_TEST_SCHEMA", "").strip()
    user = env.get("DM_TEST_USERNAME", "").strip()
    
    forbidden_users = ["SYSDBA", "SYSSSO", "SYSAUDITOR", "SYS"]
    if user.upper() in forbidden_users:
        return False, f"Forbidden user: {user.upper()} is a privileged system administrator account!"
    
    if schema.upper() in ["SYS", "CTISYS"]:
        return False, f"Forbidden schema: {schema.upper()} is a system schema!"
        
    schema_pattern = r"^GMSSL_TEST(_[A-Z0-9_]+)?$"
    if not re.match(schema_pattern, schema, re.IGNORECASE):
        return False, f"Schema isolation rule: schema '{schema}' must match regex ^GMSSL_TEST(_[A-Z0-9_]+)?$!"
        
    return True, "Security checks passed"

def main():
    print("=== GmSSL-GUI DM8 Acceptance Harness ===")
    if not ENV_FILE.is_file():
        print(f"[STATUS] NOT_RUN: {ENV_FILE.name} does not exist.")
        summary = {
            "status": "NOT_RUN",
            "reason": ".env.dm-test not configured by user",
            "tests_run": 0,
            "tests_passed": 0
        }
        (LOG_DIR / "run_summary.json").write_text(json.dumps(summary, indent=2))
        sys.exit(0)

    # Check file permissions (chmod 600 required)
    mode = ENV_FILE.stat().st_mode & 0o777
    if mode not in (0o600, 0o400):
        print(f"[WARN] .env.dm-test permissions are {oct(mode)}, enforcing 0600...")
        os.chmod(ENV_FILE, 0o600)

    env = parse_dotenv(ENV_FILE)
    ok, msg = check_security_rules(env)
    if not ok:
        print(f"[ERROR] Security check failed: {msg}")
        sys.exit(1)

    print(f"[INFO] Target schema: {env.get('DM_TEST_SCHEMA')}")
    print(f"[INFO] Target sanitized URL: {sanitize_url(env.get('DM_TEST_JDBC_URL'))}")
    print(f"[INFO] Target user: {env.get('DM_TEST_USERNAME')}")
    print("[INFO] Security rules verified successfully.")

if __name__ == "__main__":
    main()
