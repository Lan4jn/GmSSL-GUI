#!/usr/bin/env python3
"""
Unit tests for DM8 Test Harness (Offline / Mocked tests)
Verifies:
1. Dotenv parser with complex passwords ($, &, quotes, spaces)
2. Security boundary enforcement (schema regex GMSSL_TEST(_[A-Z0-9_]+)?, sysdba rejection)
3. Offline compilation of Java Harness
"""

import unittest
import tempfile
import pathlib
import subprocess
import os
import sys

# Ensure repository root is in python path
ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from tests.dm.harness import parse_dotenv, check_security_rules, sanitize_url

class TestDmHarnessOffline(unittest.TestCase):

    def test_dotenv_parser_complex_passwords(self):
        content = """
# Test comment
DM_TEST_JDBC_URL="jdbc:dm://127.0.0.1:5236?schema=GMSSL_TEST&compatibleMode=oracle"
DM_TEST_USERNAME='GMSSL_TEST'
DM_TEST_PASSWORD="P@$$w0rd&with$pecial!chars and spaces="
DM_TEST_SCHEMA=GMSSL_TEST
"""
        with tempfile.NamedTemporaryFile("w+", delete=False) as f:
            f.write(content)
            f.flush()
            parsed = parse_dotenv(pathlib.Path(f.name))
        
        self.assertEqual(parsed.get("DM_TEST_JDBC_URL"), "jdbc:dm://127.0.0.1:5236?schema=GMSSL_TEST&compatibleMode=oracle")
        self.assertEqual(parsed.get("DM_TEST_USERNAME"), "GMSSL_TEST")
        self.assertEqual(parsed.get("DM_TEST_PASSWORD"), "P@$$w0rd&with$pecial!chars and spaces=")
        self.assertEqual(parsed.get("DM_TEST_SCHEMA"), "GMSSL_TEST")
        os.unlink(f.name)

    def test_security_rules_positive(self):
        valid_envs = [
            {"DM_TEST_USERNAME": "GMSSL_TEST", "DM_TEST_SCHEMA": "GMSSL_TEST"},
            {"DM_TEST_USERNAME": "GMSSL_TEST_USER", "DM_TEST_SCHEMA": "GMSSL_TEST_01"},
            {"DM_TEST_USERNAME": "my_user", "DM_TEST_SCHEMA": "GMSSL_TEST_CI_RUN"},
        ]
        for env in valid_envs:
            ok, msg = check_security_rules(env)
            self.assertTrue(ok, f"Expected valid for {env}: {msg}")

    def test_security_rules_negative_sysdba(self):
        invalid_users = ["SYSDBA", "sysdba", "SYS", "SYSSSO", "SYSAUDITOR"]
        for u in invalid_users:
            env = {"DM_TEST_USERNAME": u, "DM_TEST_SCHEMA": "GMSSL_TEST"}
            ok, msg = check_security_rules(env)
            self.assertFalse(ok, f"Expected forbidden user for {u}")
            self.assertIn("Forbidden user", msg)

    def test_security_rules_negative_schema_regex(self):
        invalid_schemas = ["PUBLIC", "SYSTEM", "SYS", "PROD", "TEST", "GMSSL", "GMSSL_TEST-01", "gmssl_test_foo!"]
        for s in invalid_schemas:
            env = {"DM_TEST_USERNAME": "test_user", "DM_TEST_SCHEMA": s}
            ok, msg = check_security_rules(env)
            self.assertFalse(ok, f"Expected rejected schema for {s}")

    def test_sanitize_url(self):
        raw = "jdbc:dm://192.168.1.100:5236?schema=GMSSL_TEST"
        masked = sanitize_url(raw)
        self.assertNotIn("192.168.1.100", masked)
        self.assertIn("//***:5236", masked)

    def test_offline_java_compilation(self):
        root = ROOT
        dm_jar = root / ".tools/logs/dm-dependency/DmJdbcDriver18-8.1.3.140.jar"
        if not dm_jar.is_file():
            dm_jar = root / ".tools/m2/repository/com/dameng/DmJdbcDriver18/8.1.3.140/DmJdbcDriver18-8.1.3.140.jar"
        
        java_home = os.environ.get("JAVA_HOME")
        javac_bin = f"{java_home}/bin/javac" if java_home and os.path.isfile(f"{java_home}/bin/javac") else "javac"
        
        target_dir = root / "tests/dm/target"
        target_dir.mkdir(parents=True, exist_ok=True)
        
        cmd = [
            javac_bin,
            "-cp", str(dm_jar),
            "-d", str(target_dir),
            str(root / "tests/dm/src/org/gmssl/gui/platform/dm/Dm8CompatibilityHarness.java")
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, f"Compilation failed: {res.stderr}")
        self.assertTrue((target_dir / "org/gmssl/gui/platform/dm/Dm8CompatibilityHarness.class").is_file())

if __name__ == "__main__":
    unittest.main()
