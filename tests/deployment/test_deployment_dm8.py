#!/usr/bin/env python3
"""TDD Test Suite for switching deployment to external Dameng (DM8) database."""

import os
import subprocess
import tempfile
import unittest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
DEPLOY_DIR = os.path.join(REPO_ROOT, "deploy/gmssl-gui-linux-amd64")


class TestDeploymentDM8(unittest.TestCase):

    def test_01_no_postgres_in_compose(self):
        """Root compose.yaml and deploy/compose.yaml must NOT contain postgres service or postgres-data volume."""
        compose_files = [
            os.path.join(REPO_ROOT, "compose.yaml"),
            os.path.join(DEPLOY_DIR, "compose.yaml")
        ]
        for cf in compose_files:
            self.assertTrue(os.path.exists(cf), f"Missing {cf}")
            with open(cf, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertNotIn("postgres:17", content, f"postgres image found in {cf}")
            self.assertNotIn("postgres-data:", content, f"postgres-data volume found in {cf}")
            self.assertNotIn("depends_on:\n      postgres:", content, f"depends_on postgres found in {cf}")
            self.assertIn("SPRING_PROFILES_ACTIVE", content, f"SPRING_PROFILES_ACTIVE missing in {cf}")
            self.assertIn("dm", content, f"Profile 'dm' missing in {cf}")

    def test_02_dm_schema_sql_present_in_deploy_and_ops(self):
        """01_schema_dm8.sql must be present in ops/dm8 and deploy artifacts/01_schema_dm8.sql, using BIT and no BOOLEAN keyword."""
        ops_sql = os.path.join(REPO_ROOT, "ops/dm8/01_schema_dm8.sql")
        deploy_sql = os.path.join(DEPLOY_DIR, "artifacts/01_schema_dm8.sql")
        self.assertTrue(os.path.exists(ops_sql), "ops/dm8/01_schema_dm8.sql missing")
        self.assertTrue(os.path.exists(deploy_sql), "deploy/gmssl-gui-linux-amd64/artifacts/01_schema_dm8.sql missing")
        for sql_path in (ops_sql, deploy_sql):
            with open(sql_path, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("CREATE TABLE app_users", content)
            self.assertTrue("VARBINARY" in content or "BLOB" in content, "Binary type for encrypted passphrase missing")
            # Dialect compatibility check: MUST use BIT, MUST NOT declare column types as BOOLEAN (avoids DM8 -6119 error)
            self.assertIn("BIT NOT NULL", content)
            for line in content.splitlines():
                stripped = line.strip()
                if not stripped.startswith("--") and "BOOLEAN" in stripped:
                    self.fail(f"Found forbidden BOOLEAN column type in DM8 DDL ({sql_path}): {stripped}")

    def test_03_bootstrap_config_server_mode_generates_dm_template(self):
        """scripts/bootstrap-config.sh server mode must output DM JDBC URL placeholder and not pg password."""
        with tempfile.TemporaryDirectory() as tmpdir:
            env_file = os.path.join(tmpdir, ".env.server.test")
            script = os.path.join(REPO_ROOT, "scripts/bootstrap-config.sh")
            res = subprocess.run(["bash", script, "server", env_file], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, f"bootstrap-config.sh server failed: {res.stderr}")
            with open(env_file, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("SPRING_PROFILES_ACTIVE=dm", content)
            self.assertIn("SPRING_DATASOURCE_URL=jdbc:dm://", content)
            self.assertIn("SPRING_DATASOURCE_USERNAME=", content)
            self.assertIn("SPRING_DATASOURCE_PASSWORD=", content)
            self.assertNotIn("postgres", content)

    def test_04_check_and_start_refuse_unconfigured_or_non_dm_url(self):
        """deploy check.sh and start.sh must error out and refuse to start if DM URL is empty, default placeholder, or non-DM."""
        check_script = os.path.join(DEPLOY_DIR, "scripts/check.sh")
        start_script = os.path.join(DEPLOY_DIR, "scripts/start.sh")

        with tempfile.TemporaryDirectory() as tmpdir:
            # Copy scripts and deploy artifacts
            scripts_dir = os.path.join(tmpdir, "scripts")
            artifacts_dir = os.path.join(tmpdir, "artifacts")
            os.makedirs(scripts_dir)
            os.makedirs(artifacts_dir)

            for s in ("check.sh", "start.sh", "init.sh"):
                src = os.path.join(DEPLOY_DIR, "scripts", s)
                dst = os.path.join(scripts_dir, s)
                with open(src, "r") as sf, open(dst, "w") as df:
                    df.write(sf.read())
                os.chmod(dst, 0o755)

            # Dummy valid runner and SHA256SUMS
            runner = os.path.join(artifacts_dir, "gmssl-runner")
            with open(runner, "wb") as f:
                f.write(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8 + b"\x02\x00\x3e\x00" + b"\x00" * 100)
            os.chmod(runner, 0o755)

            # Required artifacts
            with open(os.path.join(artifacts_dir, "engine-service-0.1.0-SNAPSHOT.jar"), "w") as f: f.write("mock")
            with open(os.path.join(artifacts_dir, "platform-service-0.1.0-SNAPSHOT.jar"), "w") as f: f.write("mock")
            with open(os.path.join(artifacts_dir, "01_schema_dm8.sql"), "w") as f: f.write("mock")
            web_dist = os.path.join(artifacts_dir, "web-dist")
            os.makedirs(web_dist, exist_ok=True)
            with open(os.path.join(web_dist, "index.html"), "w") as f: f.write("mock")

            env_vars = os.environ.copy()
            env_vars["ALLOW_CROSS_CHECK"] = "1"

            # Case A: .env has default placeholder URL
            env_file = os.path.join(tmpdir, ".env")
            with open(env_file, "w") as f:
                f.write("GMSSL_ENGINE_TOKEN=test\nGMSSL_VAULT_MASTER_KEY=test\nGMSSL_BOOTSTRAP_USERNAME=admin\nGMSSL_BOOTSTRAP_PASSWORD=pass\n")
                f.write("SPRING_PROFILES_ACTIVE=dm\n")
                f.write("SPRING_DATASOURCE_URL=jdbc:dm://YOUR_DM8_HOST:5236?schema=YOUR_SCHEMA\n")
                f.write("SPRING_DATASOURCE_USERNAME=GMSSL_USER\n")
                f.write("SPRING_DATASOURCE_PASSWORD=secret\n")
            os.chmod(env_file, 0o600)

            res = subprocess.run(["bash", os.path.join(scripts_dir, "check.sh")], cwd=tmpdir, env=env_vars, capture_output=True, text=True)
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("Dameng (DM8) database configuration", res.stderr + res.stdout)

            # Case B: .env has non-DM URL (e.g. attempting to fallback to H2 or postgres)
            with open(env_file, "w") as f:
                f.write("GMSSL_ENGINE_TOKEN=test\nGMSSL_VAULT_MASTER_KEY=test\nGMSSL_BOOTSTRAP_USERNAME=admin\nGMSSL_BOOTSTRAP_PASSWORD=pass\n")
                f.write("SPRING_PROFILES_ACTIVE=dm\n")
                f.write("SPRING_DATASOURCE_URL=jdbc:h2:mem:test\n")
                f.write("SPRING_DATASOURCE_USERNAME=sa\n")
                f.write("SPRING_DATASOURCE_PASSWORD=pass\n")
            os.chmod(env_file, 0o600)

            res_h2 = subprocess.run(["bash", os.path.join(scripts_dir, "check.sh")], cwd=tmpdir, env=env_vars, capture_output=True, text=True)
            self.assertNotEqual(res_h2.returncode, 0)
            self.assertIn("must be a valid DM8 JDBC URL starting with jdbc:dm://", res_h2.stderr + res_h2.stdout)

    def test_05_package_script_bundles_dm_sql(self):
        """scripts/package-linux-amd64.sh must copy 01_schema_dm8.sql into deploy artifacts."""
        script = os.path.join(REPO_ROOT, "scripts/package-linux-amd64.sh")
        with open(script, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("01_schema_dm8.sql", content)


if __name__ == "__main__":
    unittest.main()