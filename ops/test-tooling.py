#!/usr/bin/env python3
"""Reproducible tooling checks; fixtures stay in the ignored .tools directory."""
import base64
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
TEST_ROOT = ROOT / ".tools" / "tests"
TEST_ROOT.mkdir(parents=True, exist_ok=True)


class ToolingTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(tempfile.mkdtemp(prefix="tooling-", dir=TEST_ROOT))
        assert self.directory.resolve().is_relative_to(TEST_ROOT.resolve())

    def test_engine_docker_java_resources(self):
        stage = (ROOT / "ops/engine.Dockerfile").read_text().split("FROM ")[1]
        copied = set()
        for line in stage.splitlines():
            if line.startswith("COPY "):
                copied.update(line.split()[1:-1])
        for name in ("catalog.json", "extensions-catalog.json"):
            self.assertIn("native/" + name, copied)
            json.loads((ROOT / "native" / name).read_text())

    def test_compose_openssl_uses_container_path(self):
        compose = (ROOT / "compose.yaml").read_text()
        self.assertIn("GMSSL_OPENSSL_PATH: /usr/bin/openssl", compose)
        self.assertNotIn("${GMSSL_OPENSSL_PATH", compose)

    def test_private_config_and_no_overwrite(self):
        config = self.directory / "config.env"
        subprocess.run(["bash", str(ROOT / "scripts/bootstrap-config.sh"), "dev", str(config)],
                       check=True, stdout=subprocess.DEVNULL)
        original = config.read_bytes()
        again = subprocess.run(["bash", str(ROOT / "scripts/bootstrap-config.sh"), "dev", str(config)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.assertNotEqual(again.returncode, 0)
        self.assertEqual(original, config.read_bytes())
        command = 'set -a; source "$1"; python3 -c \'import os,json; print(json.dumps(dict(os.environ)))\''
        values = json.loads(subprocess.check_output(["bash", "-c", command, "test", str(config)], text=True))
        self.assertEqual(len(base64.b64decode(values["GMSSL_VAULT_MASTER_KEY"])), 32)
        self.assertEqual(len(values["GMSSL_BOOTSTRAP_PASSWORD"]), 48)
        self.assertEqual(values["GMSSL_SESSION_COOKIE_SECURE"], "false")
        for path in [config, Path(str(config) + ".credentials")]:
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_streaming_redaction_and_limit(self):
        secret = "test-token-123456789012345678901234567890"
        env = dict(os.environ, GMSSL_ENGINE_TOKEN=secret,
                   GMSSL_VAULT_MASTER_KEY="test-master-key",
                   GMSSL_BOOTSTRAP_PASSWORD="test-bootstrap-password",
                   SPRING_DATASOURCE_PASSWORD="test-db-password")
        payload = b"a" * (8192 - 10) + secret.encode() + b" test-master-key test-bootstrap-password test-db-password\n"
        payload += b"x" * (11 * 1024 * 1024) + secret.encode()
        log = self.directory / "redacted.log"
        subprocess.run([sys.executable, str(ROOT / "ops/redact-log.py"), str(log)],
                       input=payload, env=env, check=True, timeout=10)
        output = log.read_bytes()
        for name in ["GMSSL_ENGINE_TOKEN", "GMSSL_VAULT_MASTER_KEY", "GMSSL_BOOTSTRAP_PASSWORD", "SPRING_DATASOURCE_PASSWORD"]:
            self.assertNotIn(env[name].encode(), output)
        self.assertIn(b"[REDACTED]", output)
        self.assertIn(b"Log retention limit reached", output)
        self.assertLess(len(output), 10 * 1024 * 1024 + 128)
        self.assertEqual(stat.S_IMODE(log.stat().st_mode), 0o600)

    def test_precise_process_tree_shutdown(self):
        child_file = self.directory / "child.pid"
        worker = self.directory / "worker.py"
        worker.write_text('import subprocess,sys,time\np=subprocess.Popen([sys.executable,"-c","import time;time.sleep(60)"])\nopen(sys.argv[1],"w").write(str(p.pid))\ntime.sleep(60)\n')
        jar = str(self.directory / "test.jar")
        root = subprocess.Popen([sys.executable, str(worker), str(child_file), "-jar", jar])
        unrelated = subprocess.Popen([sys.executable, "-c", "import time;time.sleep(60)"])
        child = None
        try:
            for _ in range(50):
                if child_file.exists() and child_file.read_text().strip():
                    break
                time.sleep(0.1)
            child = int(child_file.read_text())
            for process, expected_jar, should_stop in [(unrelated, jar, False), (root, jar, True)]:
                started = subprocess.check_output(["ps", "-p", str(process.pid), "-o", "lstart="], text=True).rstrip("\n")
                identity = self.directory / (str(process.pid) + ".pid")
                identity.write_text(f"{process.pid}\n{started}\n")
                subprocess.run([sys.executable, str(ROOT / "ops/stop-process.py"), "--pid-file", str(identity), "--jar", expected_jar],
                               check=True, timeout=15, stdout=subprocess.DEVNULL)
                if should_stop:
                    process.wait(timeout=2)
                else:
                    self.assertIsNone(process.poll())
            state = subprocess.run(["ps", "-p", str(child), "-o", "stat="], capture_output=True, text=True).stdout.strip()
            self.assertTrue(not state or state.startswith("Z"))
        finally:
            for process in [root, unrelated]:
                if process.poll() is None:
                    process.terminate()
                process.wait(timeout=2)
            if child:
                state = subprocess.run(["ps", "-p", str(child), "-o", "stat="], capture_output=True, text=True).stdout.strip()
                if state and not state.startswith("Z"):
                    raise AssertionError("Test child unexpectedly survived")


if __name__ == "__main__":
    unittest.main(verbosity=2)
