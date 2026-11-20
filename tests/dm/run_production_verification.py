#!/usr/bin/env python3
"""Verify frozen production Beans on the sole configured DM test schema; never print secrets."""
import base64
import hashlib
import json
import os
import pathlib
import re
import secrets
import subprocess
import sys
import tempfile
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
JAR = ROOT / "deploy/gmssl-gui-linux-amd64/artifacts/platform-service-0.1.0-SNAPSHOT.jar"
DDL = ROOT / "deploy/gmssl-gui-linux-amd64/artifacts/01_schema_dm8.sql"
EXPECTED_JAR = "19842a750c9581479163727febdb3fedac8078620b8e0645571f9fd04a3279d8"
EXPECTED_DDL = "32d422f198c02819ed54710a17eac363b4487e63b0f33261c6d7777349c799da"
SOURCE = ROOT / "tests/dm/src/org/gmssl/gui/platform/Dm8ProductionVerification.java"

def read_test_env():
    result = {}
    path = ROOT / ".env.dm-test"
    if path.stat().st_mode & 0o077:
        raise ValueError("PRIVATE_ENV_PERMISSIONS")
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = (part.strip() for part in line.split("=", 1))
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if key in {"DM_TEST_JDBC_URL", "DM_TEST_USERNAME", "DM_TEST_PASSWORD", "DM_TEST_SCHEMA"}:
            result[key] = value
    if not re.fullmatch(r"GMSSL_TEST(?:_[A-Z0-9_]+)?", result.get("DM_TEST_SCHEMA", "")):
        raise ValueError("SCHEMA_BOUNDARY")
    if not re.fullmatch(r"GMSSL_TEST(?:_[A-Z0-9_]+)?", result.get("DM_TEST_USERNAME", "").upper()):
        raise ValueError("USER_BOUNDARY")
    if not result.get("DM_TEST_JDBC_URL", "").startswith("jdbc:dm://") or not result.get("DM_TEST_PASSWORD"):
        raise ValueError("DM_CONFIGURATION")
    return result

def main():
    for path, expected in [(JAR, EXPECTED_JAR), (DDL, EXPECTED_DDL)]:
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError("FROZEN_ARTIFACT_MISMATCH")
    print("DMPROD ARTIFACT jar=" + EXPECTED_JAR, flush=True)
    print("DMPROD ARTIFACT ddl=" + EXPECTED_DDL, flush=True)
    jdk = next((ROOT / ".tools").glob("jdk-21*/Contents/Home"))
    target = ROOT / "tests/dm/target"
    target.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="production-", dir=target) as directory:
        work = pathlib.Path(directory)
        with zipfile.ZipFile(JAR) as archive:
            for item in archive.infolist():
                if item.filename.startswith(("BOOT-INF/classes/", "BOOT-INF/lib/")) and not item.is_dir():
                    path = work / item.filename
                    if not path.resolve().is_relative_to(work.resolve()):
                        raise ValueError("ARCHIVE_PATH_BOUNDARY")
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(archive.read(item))
        classpath = os.pathsep.join([str(work / "BOOT-INF/classes"), str(work / "BOOT-INF/lib/*")])
        compiled = subprocess.run([str(jdk / "bin/javac"), "-cp", classpath, "-d", str(work / "helper"), str(SOURCE)],
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
        if compiled.returncode:
            # javac receives source and frozen artifacts only; it never reads the private environment file.
            print(compiled.stdout.decode("utf-8", errors="replace"))
            return compiled.returncode
        print("DMPROD COMPILE PASS", flush=True)
        if "--compile-only" in sys.argv:
            return 0
        env = read_test_env()
        ledger = target / ("dm-production-ledger-" + secrets.token_hex(8) + ".json")
        fd = os.open(ledger, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            json.dump({"users": [], "projects": [], "materials": []}, output)
        env["DM_PRODUCTION_LEDGER"] = str(ledger)
        print("DMPROD LEDGER " + str(ledger.relative_to(ROOT)), flush=True)
        if "--recover-first-run" in sys.argv:
            env["DM_PRODUCTION_RECOVER"] = "true"
        env.update({"PATH": str(jdk / "bin") + os.pathsep + os.defpath, "HOME": str(work),
                    "GMSSL_BOOTSTRAP_USERNAME": "dmprobe-admin-" + secrets.token_hex(10),
                    "GMSSL_BOOTSTRAP_PASSWORD": secrets.token_urlsafe(24),
                    "GMSSL_VAULT_MASTER_KEY": base64.b64encode(secrets.token_bytes(32)).decode(),
                    "GMSSL_VAULT_DIR": str(work / "vault"), "GMSSL_SESSION_COOKIE_SECURE": "false",
                    "SPRING_PROFILES_ACTIVE": "dm", "SERVER_PORT": "0", "SERVER_ADDRESS": "127.0.0.1",
                    "LOGGING_LEVEL_ROOT": "OFF", "LOGGING_LEVEL_ORG_APACHE_CATALINA": "OFF",
                    "SPRING_MAIN_BANNER_MODE": "off", "SPRING_FLYWAY_ENABLED": "false",
                    "SPRING_SQL_INIT_MODE": "never"})
        run = subprocess.run([str(jdk / "bin/java"), "-cp", str(work / "helper") + os.pathsep + classpath,
                              "org.gmssl.gui.platform.Dm8ProductionVerification"], env=env,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180)
        # Persist only fixed-shape test assertions and status numbers, never raw framework/SQL output.
        safe = []
        for line in run.stdout.decode("utf-8", errors="replace").splitlines():
            if re.fullmatch(r"DMPROD (?:PASS [A-Z0-9_]+|HTTP [A-Z0-9_]+ (?:GET|POST) path=/api/v1/[a-z/{}]+ status=[0-9]{3}|FAIL stage=[a-z-]+ type=[A-Za-z0-9]+|RESULT PASS checks=[0-9]+)", line):
                safe.append(line)
        if not any(line.startswith("DMPROD RESULT PASS checks=") for line in safe) and run.returncode == 0:
            raise ValueError("MISSING_SUCCESS_ASSERTION")
        safe.append("DMPROD EXIT " + str(run.returncode))
        text = "\n".join(safe) + "\n"
        logdir = ROOT / ".tools/logs"
        logdir.mkdir(parents=True, exist_ok=True)
        log = logdir / ("dm-production-recovery.log" if "--recover-first-run" in sys.argv else "dm-production-verification.log")
        fd = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            out.write(text)
        print(text, end="")
        return run.returncode

if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as failure:
        print("DMPROD RUNNER_FAIL type=" + type(failure).__name__)
        sys.exit(1)
