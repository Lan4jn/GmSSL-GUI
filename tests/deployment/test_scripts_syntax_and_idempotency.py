#!/usr/bin/env python3
import os
import stat
import subprocess
import tempfile
import unittest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
DEPLOY_DIR = os.path.join(REPO_ROOT, "deploy/gmssl-gui-linux-amd64")


class TestDeploymentScripts(unittest.TestCase):

    def test_01_shell_syntax(self):
        """All deployment shell scripts must have valid bash syntax (bash -n)."""
        scripts = [
            os.path.join(REPO_ROOT, "scripts/package-linux-amd64.sh"),
            os.path.join(DEPLOY_DIR, "init.sh"),
            os.path.join(DEPLOY_DIR, "start.sh"),
            os.path.join(DEPLOY_DIR, "stop.sh"),
            os.path.join(DEPLOY_DIR, "status.sh"),
            os.path.join(DEPLOY_DIR, "check.sh"),
            os.path.join(DEPLOY_DIR, "scripts/init.sh"),
            os.path.join(DEPLOY_DIR, "scripts/start.sh"),
            os.path.join(DEPLOY_DIR, "scripts/stop.sh"),
            os.path.join(DEPLOY_DIR, "scripts/status.sh"),
            os.path.join(DEPLOY_DIR, "scripts/check.sh"),
            os.path.join(DEPLOY_DIR, "scripts/upgrade.sh"),
            os.path.join(DEPLOY_DIR, "upgrade.sh"),
        ]
        for s in scripts:
            self.assertTrue(os.path.exists(s), f"Script missing: {s}")
            res = subprocess.run(["bash", "-n", s], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, f"Syntax error in {s}: {res.stderr}")

    def test_02_no_volume_destruction_in_scripts(self):
        """Scripts must never call 'down -v' or rm volumes."""
        scripts_dir = os.path.join(DEPLOY_DIR, "scripts")
        for fname in os.listdir(scripts_dir):
            if fname.endswith(".sh"):
                path = os.path.join(scripts_dir, fname)
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read()
                self.assertNotIn("down -v", content, f"'down -v' found in {fname}")
                self.assertNotIn("volume rm", content, f"'volume rm' found in {fname}")

    def test_03_init_idempotency_and_security(self):
        """Test init.sh in isolated sandbox: creates .env and credentials.txt with 0600, idempotent."""
        with tempfile.TemporaryDirectory() as tmpdir:
            scripts_dir = os.path.join(tmpdir, "scripts")
            os.makedirs(scripts_dir)
            init_script = os.path.join(scripts_dir, "init.sh")
            with open(os.path.join(DEPLOY_DIR, "scripts/init.sh"), "r") as src:
                content = src.read()
            with open(init_script, "w") as dst:
                dst.write(content)
            os.chmod(init_script, 0o755)

            # 1st run
            res1 = subprocess.run(["bash", init_script], cwd=tmpdir, capture_output=True, text=True)
            self.assertEqual(res1.returncode, 0, f"init.sh failed: {res1.stderr}")
            env_file = os.path.join(tmpdir, ".env")
            cred_file = os.path.join(tmpdir, "credentials.txt")
            self.assertTrue(os.path.exists(env_file))
            self.assertTrue(os.path.exists(cred_file))

            # Verify permissions are 0600
            mode_env = stat.S_IMODE(os.stat(env_file).st_mode)
            mode_cred = stat.S_IMODE(os.stat(cred_file).st_mode)
            self.assertEqual(mode_env, 0o600, f"Wrong .env mode: {oct(mode_env)}")
            self.assertEqual(mode_cred, 0o600, f"Wrong credentials.txt mode: {oct(mode_cred)}")

            # Verify no secrets in stdout/stderr
            with open(cred_file, "r") as f:
                cred_text = f.read()
            pass_line = [l for l in cred_text.splitlines() if "administrator password:" in l][0]
            password = pass_line.split(":")[-1].strip()
            self.assertNotIn(password, res1.stdout)
            self.assertNotIn(password, res1.stderr)

            # 2nd run: must retain existing config (idempotent)
            res2 = subprocess.run(["bash", init_script], cwd=tmpdir, capture_output=True, text=True)
            self.assertEqual(res2.returncode, 1) # Retains and returns non-zero to prevent accidental overwriting
            self.assertIn("Existing configuration retained", res2.stderr)

            # Check content unchanged
            with open(cred_file, "r") as f:
                cred_text2 = f.read()
            self.assertEqual(cred_text, cred_text2)

    def test_04_init_credentials_only_retention(self):
        """If credentials.txt exists but .env is missing, init.sh must NOT overwrite credentials.txt."""
        with tempfile.TemporaryDirectory() as tmpdir:
            scripts_dir = os.path.join(tmpdir, "scripts")
            os.makedirs(scripts_dir)
            init_script = os.path.join(scripts_dir, "init.sh")
            with open(os.path.join(DEPLOY_DIR, "scripts/init.sh"), "r") as src:
                content = src.read()
            with open(init_script, "w") as dst:
                dst.write(content)
            os.chmod(init_script, 0o755)

            # Create existing credentials.txt
            cred_file = os.path.join(tmpdir, "credentials.txt")
            with open(cred_file, "w") as f:
                f.write("EXISTING_SECRET_CREDENTIALS")

            res = subprocess.run(["bash", init_script], cwd=tmpdir, capture_output=True, text=True)
            self.assertEqual(res.returncode, 1)
            self.assertIn("Existing configuration retained", res.stderr)
            with open(cred_file, "r") as f:
                self.assertEqual(f.read(), "EXISTING_SECRET_CREDENTIALS")
            self.assertFalse(os.path.exists(os.path.join(tmpdir, ".env")))

    def test_05_check_script_host_platform_interception(self):
        """check.sh must reject non-Linux or non-x86_64 hosts unless ALLOW_CROSS_CHECK=1."""
        with tempfile.TemporaryDirectory() as tmpdir:
            scripts_dir = os.path.join(tmpdir, "scripts")
            os.makedirs(scripts_dir)
            check_script = os.path.join(scripts_dir, "check.sh")
            with open(os.path.join(DEPLOY_DIR, "scripts/check.sh"), "r") as src:
                content = src.read()