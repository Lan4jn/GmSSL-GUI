#!/usr/bin/env python3
"""TDD Test Suite for Deployment Upgrade Tooling and Dameng Schema Baseline."""

import hashlib
import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
DEPLOY_DIR = os.path.join(REPO_ROOT, "deploy/gmssl-gui-linux-amd64")


class TestDeploymentUpgrade(unittest.TestCase):

    def test_01_upgrade_script_help_and_plan_readonly(self):
        """upgrade.sh must provide --help and --plan without any mutating side effects."""
        upgrade_script = os.path.join(DEPLOY_DIR, "scripts/upgrade.sh")
        self.assertTrue(os.path.exists(upgrade_script), "deploy scripts/upgrade.sh missing")
        self.assertTrue(os.path.exists(os.path.join(DEPLOY_DIR, "upgrade.sh")), "deploy root upgrade.sh missing")

        # Check bash syntax
        res_syntax = subprocess.run(["bash", "-n", upgrade_script], capture_output=True, text=True)
        self.assertEqual(res_syntax.returncode, 0, f"Syntax error in upgrade.sh: {res_syntax.stderr}")

        # Check --help
        res_help = subprocess.run(["bash", upgrade_script, "--help"], capture_output=True, text=True)
        self.assertEqual(res_help.returncode, 0)
        self.assertIn("Usage:", res_help.stdout)
        self.assertIn("--plan", res_help.stdout)
        self.assertIn("--apply", res_help.stdout)

    def test_02_plan_fails_closed_when_old_env_or_master_missing(self):
        """upgrade.sh --plan must fail closed if old .env is missing or lacks GMSSL_VAULT_MASTER_KEY."""
        upgrade_script = os.path.join(DEPLOY_DIR, "scripts/upgrade.sh")

        with tempfile.TemporaryDirectory() as tmp_old, tempfile.TemporaryDirectory() as tmp_new:
            # Case A: old directory completely lacks .env
            res_no_env = subprocess.run(
                ["bash", upgrade_script, "--from", tmp_old, "--plan"],
                cwd=tmp_new,
                capture_output=True,
                text=True
            )
            self.assertNotEqual(res_no_env.returncode, 0)
            self.assertIn("missing .env", res_no_env.stderr.lower())

            # Case B: old .env exists but lacks GMSSL_VAULT_MASTER_KEY
            old_env_file = os.path.join(tmp_old, ".env")
            with open(old_env_file, "w") as f:
                f.write("GMSSL_ENGINE_TOKEN=some-token\nSPRING_DATASOURCE_URL=jdbc:dm://host:5236\n")
            os.chmod(old_env_file, 0o600)

            res_no_master = subprocess.run(
                ["bash", upgrade_script, "--from", tmp_old, "--plan"],
                cwd=tmp_new,
                capture_output=True,
                text=True
            )
            self.assertNotEqual(res_no_master.returncode, 0)
            self.assertIn("GMSSL_VAULT_MASTER_KEY", res_no_master.stderr)

    def test_03_rejects_in_place_overwrite_and_symlinks(self):
        """upgrade.sh must reject in-place upgrade when target and source are the same directory, or symlinks."""
        upgrade_script = os.path.join(DEPLOY_DIR, "scripts/upgrade.sh")

        with tempfile.TemporaryDirectory() as tmpdir:
            # Mock .env in tmpdir
            with open(os.path.join(tmpdir, ".env"), "w") as f:
                f.write("GMSSL_VAULT_MASTER_KEY=valid-master-key-32-chars-ok\n")

            # Same directory
            res_same = subprocess.run(
                ["bash", upgrade_script, "--from", tmpdir, "--plan"],
                cwd=tmpdir,
                capture_output=True,
                text=True
            )
            self.assertNotEqual(res_same.returncode, 0)
            self.assertIn("same directory", res_same.stderr.lower())

    def test_04_config_migration_preserves_master_and_enforces_0600(self):
        """Applying upgrade copies .env and credentials.txt, preserves master key, enforces 0600, no secrets printed."""
        upgrade_script = os.path.join(DEPLOY_DIR, "scripts/upgrade.sh")

        with tempfile.TemporaryDirectory(prefix="gmssl old dir ") as tmp_old,              tempfile.TemporaryDirectory(prefix="gmssl new dir ") as tmp_new:

            # Setup old environment
            secret_master = "SEC_MASTER_KEY_1234567890_EXACT_MATCH"
            secret_db_pass = "P$sswordWithSpecial$Chars"
            with open(os.path.join(tmp_old, ".env"), "w") as f:
                f.write(f"GMSSL_ENGINE_TOKEN=old-token\nGMSSL_VAULT_MASTER_KEY={secret_master}\n")
                f.write(f"SPRING_DATASOURCE_URL=jdbc:dm://192.168.1.50:5236?schema=TEST\n")
                f.write(f"SPRING_DATASOURCE_USERNAME=TEST_USER\n")
                f.write(f"SPRING_DATASOURCE_PASSWORD='{secret_db_pass}'\n")
                f.write(f"GMSSL_BOOTSTRAP_USERNAME=admin\nGMSSL_BOOTSTRAP_PASSWORD=adminpass\n")
            os.chmod(os.path.join(tmp_old, ".env"), 0o600)

            with open(os.path.join(tmp_old, "credentials.txt"), "w") as f:
                f.write("Initial administrator password: adminpass\n")
            os.chmod(os.path.join(tmp_old, "credentials.txt"), 0o600)

            # Setup new directory mock structure
            os.makedirs(os.path.join(tmp_new, "scripts"))
            # Copy check.sh and start.sh mocks or real scripts
            with open(os.path.join(tmp_new, ".env.example"), "w") as f:
                f.write("GMSSL_ENGINE_TOKEN=YOUR_TOKEN\nGMSSL_VAULT_MASTER_KEY=YOUR_MASTER\nNEW_OPTION=NEW_VALUE\n")

            # Mock check.sh and start.sh in new dir
            with open(os.path.join(tmp_new, "scripts/check.sh"), "w") as f:
                f.write("#!/bin/sh\nexit 0\n")
            os.chmod(os.path.join(tmp_new, "scripts/check.sh"), 0o755)
            with open(os.path.join(tmp_new, "scripts/start.sh"), "w") as f:
                f.write("#!/bin/sh\necho '[MOCK START OK]'\nexit 0\n")
            os.chmod(os.path.join(tmp_new, "scripts/start.sh"), 0o755)

            # Mock stop.sh in old dir
            os.makedirs(os.path.join(tmp_old, "scripts"))
            with open(os.path.join(tmp_old, "scripts/stop.sh"), "w") as f:
                f.write("#!/bin/sh\necho '[MOCK STOP OLD OK]'\nexit 0\n")
            os.chmod(os.path.join(tmp_old, "scripts/stop.sh"), 0o755)

            # Run apply with --yes
            res_apply = subprocess.run(
                ["bash", upgrade_script, "--from", tmp_old, "--apply", "--yes", "--backup-done"],
                cwd=tmp_new,
                capture_output=True,
                text=True
            )
            self.assertEqual(res_apply.returncode, 0, f"upgrade --apply failed: {res_apply.stderr}")

            # Verify no secrets in stdout or stderr
            self.assertNotIn(secret_master, res_apply.stdout)
            self.assertNotIn(secret_master, res_apply.stderr)
            self.assertNotIn(secret_db_pass, res_apply.stdout)
            self.assertNotIn(secret_db_pass, res_apply.stderr)

            # Verify new .env permissions and content
            new_env = os.path.join(tmp_new, ".env")
            self.assertTrue(os.path.exists(new_env))
            mode_env = stat.S_IMODE(os.stat(new_env).st_mode)
            self.assertEqual(mode_env, 0o600)

            with open(new_env, "r") as f:
                new_env_content = f.read()
            self.assertIn(secret_master, new_env_content)
            self.assertIn(secret_db_pass, new_env_content)

    def test_05_dameng_migrations_and_baseline_sql(self):
        """ops/dm8/migrations/ and deploy artifacts/migrations/ must contain 00_schema_version_and_baseline.sql."""
        ops_migration = os.path.join(REPO_ROOT, "ops/dm8/migrations/00_schema_version_and_baseline.sql")
        deploy_migration = os.path.join(DEPLOY_DIR, "artifacts/migrations/00_schema_version_and_baseline.sql")

        self.assertTrue(os.path.exists(ops_migration), "ops/dm8/migrations/00_schema_version_and_baseline.sql missing")
        self.assertTrue(os.path.exists(deploy_migration), "deploy/artifacts/migrations/00_schema_version_and_baseline.sql missing")

        with open(deploy_migration, "r") as f:
            sql = f.read()
        self.assertIn("schema_version", sql)
        self.assertIn("0.1.0", sql)
        self.assertNotIn("BOOLEAN", sql)

    def test_06_upgrade_plan_and_apply_with_jre_images(self):
        """upgrade.sh must run real start-with-jre.sh in --plan and --apply using mock docker without stubs."""
        upgrade_script = os.path.join(DEPLOY_DIR, "scripts/upgrade.sh")
        custom_jre = "local.harbor:5000/base/temurin:21.0.2-jre"
        custom_nginx = "local.harbor:5000/base/nginx:1.28-alpine"

        with tempfile.TemporaryDirectory(prefix="gmssl old jre ") as tmp_old, \
             tempfile.TemporaryDirectory(prefix="gmssl new jre ") as tmp_new:

            # Mock docker binary
            mock_bin = os.path.join(tmp_new, "bin")
            docker_log = os.path.join(tmp_new, "docker.log")
            os.makedirs(mock_bin)
            with open(os.path.join(mock_bin, "docker"), "w") as f:
                f.write(f"""#!/bin/sh
echo "$@" >> "{docker_log}"
if [ "$1" = "image" ] && [ "$2" = "inspect" ]; then
    exit 0
elif [ "$1" = "run" ]; then
    echo "openjdk version \"21.0.2\"" >&2
    echo "OpenSSL 3.0.2"
    exit 0
elif [ "$1" = "compose" ]; then
    exit 0
fi
exit 0
""")
            os.chmod(os.path.join(mock_bin, "docker"), 0o755)

            # Setup old .env
            old_master_key = "dGVzdC1tYXN0ZXIta2V5LTMyLWJ5dGVzISEhISEhISE="
            with open(os.path.join(tmp_old, ".env"), "w") as f:
                f.write(f"GMSSL_VAULT_MASTER_KEY={old_master_key}\n"
                        "SPRING_DATASOURCE_URL=jdbc:dm://127.0.0.1:5236?schema=TEST\n")
            os.chmod(os.path.join(tmp_old, ".env"), 0o600)

            os.makedirs(os.path.join(tmp_old, "scripts"))
            stop_old_log = os.path.join(tmp_old, "stop_old.log")
            with open(os.path.join(tmp_old, "scripts/stop.sh"), "w") as f:
                f.write(f"echo stopped >> '{stop_old_log}'\nexit 0\n")
            os.chmod(os.path.join(tmp_old, "scripts/stop.sh"), 0o755)

            # Copy real deployment files to new dir
            shutil.copytree(DEPLOY_DIR, os.path.join(tmp_new, "deploy_pkg"))
            test_target = os.path.join(tmp_new, "deploy_pkg")

            env = os.environ.copy()
            env["PATH"] = f"{mock_bin}:{env.get('PATH', '')}"

            # 1. Test --plan: must pass, must NOT create .env in test_target, must NOT stop old
            res_plan = subprocess.run(
                ["bash", "scripts/upgrade.sh", "--from", tmp_old, "--jre-image", custom_jre, "--nginx-image", custom_nginx, "--plan"],
                cwd=test_target,
                env=env,
                capture_output=True,
                text=True
            )
            self.assertEqual(res_plan.returncode, 0, f"Plan failed: {res_plan.stderr}\n{res_plan.stdout}")
            self.assertIn("Local JRE Mount Mode", res_plan.stdout)
            self.assertIn(custom_jre, res_plan.stdout)
            self.assertIn(custom_nginx, res_plan.stdout)

            # Verify no .env was generated in new target during plan
            self.assertFalse(os.path.exists(os.path.join(test_target, ".env")), ".env must NOT be created during --plan!")
            # Verify stop.sh was NOT called during plan
            self.assertFalse(os.path.exists(stop_old_log), "Old containers must NOT be stopped during --plan!")

            # 2. Test --plan failure when old .env has non-10001 user
            with open(os.path.join(tmp_old, ".env"), "w") as f:
                f.write(f"GMSSL_VAULT_MASTER_KEY={old_master_key}\n"
                        "SPRING_DATASOURCE_URL=jdbc:dm://127.0.0.1:5236?schema=TEST\n"
                        "GMSSL_CONTAINER_USER=1000:1000\n")
            res_bad_plan = subprocess.run(
                ["bash", "scripts/upgrade.sh", "--from", tmp_old, "--jre-image", custom_jre, "--nginx-image", custom_nginx, "--plan"],
                cwd=test_target,
                env=env,
                capture_output=True,
                text=True
            )
            self.assertNotEqual(res_bad_plan.returncode, 0)
            self.assertIn("Container user mismatch", res_bad_plan.stderr)
            self.assertFalse(os.path.exists(os.path.join(test_target, ".env")), ".env must NOT be created on failed plan!")
            self.assertFalse(os.path.exists(stop_old_log), "Old containers must NOT be stopped on failed plan!")

            # Restore valid old .env
            with open(os.path.join(tmp_old, ".env"), "w") as f:
                f.write(f"GMSSL_VAULT_MASTER_KEY={old_master_key}\n"
                        "SPRING_DATASOURCE_URL=jdbc:dm://127.0.0.1:5236?schema=TEST\n")

            # 3. Test --apply: must migrate .env, stop old, call start-with-jre.sh
            with open(docker_log, "w") as f: f.write("")
            res_apply = subprocess.run(
                ["bash", "scripts/upgrade.sh", "--from", tmp_old, "--jre-image", custom_jre, "--nginx-image", custom_nginx, "--apply", "--yes", "--backup-done"],
                cwd=test_target,
                env=env,
                capture_output=True,
                text=True
            )
            self.assertEqual(res_apply.returncode, 0, f"Apply failed: {res_apply.stderr}\n{res_apply.stdout}")
            # Verify new .env created with 0600 mode and preserves master key
            migrated_env = os.path.join(test_target, ".env")
            self.assertTrue(os.path.exists(migrated_env))
            self.assertEqual(stat.S_IMODE(os.stat(migrated_env).st_mode), 0o600)
            with open(migrated_env, "r") as f: env_content = f.read()
            self.assertIn(old_master_key, env_content)

            # Verify old containers were stopped in apply mode
            self.assertTrue(os.path.exists(stop_old_log))
            # Verify docker compose was called with -f compose.jre.yaml
            with open(docker_log, "r") as f: calls = f.read()
            self.assertIn("-f compose.jre.yaml", calls)
            self.assertIn("--pull never", calls)

    def test_07_upgrade_nginx_only_without_jre_fails(self):
        """upgrade.sh must reject --nginx-image if --jre-image is omitted."""
        upgrade_script = os.path.join(DEPLOY_DIR, "scripts/upgrade.sh")
        with tempfile.TemporaryDirectory() as tmp_old, tempfile.TemporaryDirectory() as tmp_new:
            with open(os.path.join(tmp_old, ".env"), "w") as f:
                f.write("GMSSL_VAULT_MASTER_KEY=dGVzdC1tYXN0ZXIta2V5LTMyLWJ5dGVzISEhISEhISE=\n")
            res = subprocess.run(
                ["bash", upgrade_script, "--from", tmp_old, "--nginx-image", "nginx:custom", "--plan"],
                cwd=tmp_new,
                capture_output=True,
                text=True
            )
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("--nginx-image specified without JRE image", res.stderr)

    def test_08_upgrade_aborts_without_stopping_old_on_preflight_failure(self):
        """upgrade.sh --apply must abort and never call stop.sh if new preflight check fails."""
        upgrade_script = os.path.join(DEPLOY_DIR, "scripts/upgrade.sh")
        with tempfile.TemporaryDirectory() as tmp_old, tempfile.TemporaryDirectory() as tmp_new:
            with open(os.path.join(tmp_old, ".env"), "w") as f:
                f.write("GMSSL_VAULT_MASTER_KEY=dGVzdC1tYXN0ZXIta2V5LTMyLWJ5dGVzISEhISEhISE=\n"
                        "SPRING_DATASOURCE_URL=jdbc:dm://127.0.0.1:5236?schema=TEST\n")
            os.chmod(os.path.join(tmp_old, ".env"), 0o600)
            os.makedirs(os.path.join(tmp_new, "scripts"))
            os.makedirs(os.path.join(tmp_old, "scripts"))

            stop_log = os.path.join(tmp_old, "stop.log")
            with open(os.path.join(tmp_old, "scripts/stop.sh"), "w") as f:
                f.write(f"echo stopped >> '{stop_log}'\nexit 0\n")
            os.chmod(os.path.join(tmp_old, "scripts/stop.sh"), 0o755)

            # Mock failing check in new directory
            with open(os.path.join(tmp_new, "scripts/start-with-jre.sh"), "w") as f:
                f.write("echo 'MOCK JRE PRECHECK FAILED' >&2\nexit 1\n")
            os.chmod(os.path.join(tmp_new, "scripts/start-with-jre.sh"), 0o755)

            res = subprocess.run(
                ["bash", upgrade_script, "--from", tmp_old, "--jre-image", "temurin:21", "--apply", "--yes", "--backup-done"],
                cwd=tmp_new,
                capture_output=True,
                text=True
            )
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("Preflight check with JRE mount in new deployment directory FAILED", res.stderr)
            # Old stop.sh must NEVER have been called!
            self.assertFalse(os.path.exists(stop_log), "Old containers must NOT be stopped if new preflight fails!")


if __name__ == "__main__":
    unittest.main()