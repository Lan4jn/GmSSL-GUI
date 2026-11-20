#!/usr/bin/env python3
"""TDD Test Suite for task-76: User-defined Local JRE Image offline startup script."""

import os
import shutil
import stat
import subprocess
import tempfile
import unittest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
DEPLOY_DIR = os.path.join(REPO_ROOT, "deploy/gmssl-gui-linux-amd64")


class TestStartWithJre(unittest.TestCase):

    def test_01_script_files_exist_and_syntax(self):
        scripts = [
            os.path.join(REPO_ROOT, "scripts/start-with-jre.sh"),
            os.path.join(DEPLOY_DIR, "scripts/start-with-jre.sh"),
            os.path.join(DEPLOY_DIR, "start-with-jre.sh")
        ]
        for s in scripts:
            self.assertTrue(os.path.exists(s), f"Missing script: {s}")
            res = subprocess.run(["bash", "-n", s], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, f"Syntax error in {s}: {res.stderr}")

    def test_02_compose_jre_yaml_exists_and_valid(self):
        compose_files = [
            os.path.join(REPO_ROOT, "compose.jre.yaml"),
            os.path.join(DEPLOY_DIR, "compose.jre.yaml")
        ]
        for cf in compose_files:
            self.assertTrue(os.path.exists(cf), f"Missing compose file: {cf}")
            with open(cf, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("GMSSL_JRE_IMAGE", content)
            # Both engine and platform must specify user: 10001:10001 matching /work tmpfs and vault-data volume
            self.assertEqual(content.count("user: \"${GMSSL_CONTAINER_USER:-10001:10001}\""), 2, "Both engine and platform must specify container user")
            self.assertIn("/work:mode=0700,uid=10001,gid=10001", content)
            self.assertIn("engine-service-0.1.0-SNAPSHOT.jar", content)
            self.assertIn("platform-service-0.1.0-SNAPSHOT.jar", content)
            self.assertIn("gmssl-runner", content)
            self.assertIn("nginx.conf", content)
            self.assertIn("web-dist", content)
            self.assertIn("vault-data", content)

    def test_03_help_flag(self):
        script = os.path.join(DEPLOY_DIR, "start-with-jre.sh")
        res = subprocess.run(["bash", script, "--help"], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertIn("--jre-image", res.stdout)
        self.assertIn("--nginx-image", res.stdout)
        self.assertIn("JRE_IMAGE", res.stdout)

    def test_04_missing_jre_image_arg_fails_immediately(self):
        script = os.path.join(DEPLOY_DIR, "start-with-jre.sh")
        # Missing argument value
        res1 = subprocess.run(["bash", script, "--jre-image"], capture_output=True, text=True)
        self.assertNotEqual(res1.returncode, 0)
        self.assertIn("Missing value for --jre-image", res1.stderr)

        # No argument and no environment variable
        env = os.environ.copy()
        env.pop("JRE_IMAGE", None)
        env.pop("GMSSL_JRE_IMAGE", None)
        res2 = subprocess.run(["bash", script], env=env, capture_output=True, text=True)
        self.assertNotEqual(res2.returncode, 0)
        self.assertIn("JRE image must be specified", res2.stderr)

    def test_05_mock_docker_captures_correct_compose_call(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mock_bin = os.path.join(tmpdir, "bin")
            log_file = os.path.join(tmpdir, "docker.log")
            os.makedirs(mock_bin)

            mock_docker = os.path.join(mock_bin, "docker")
            with open(mock_docker, "w") as f:
                f.write(f"""#!/bin/sh
echo "$@" >> "{log_file}"
if [ "$1" = "image" ] && [ "$2" = "inspect" ]; then
    exit 0
elif [ "$1" = "run" ]; then
    # mock java -version and openssl version checks
    case "$*" in
        *"java -version"*)
            echo "openjdk version \"21.0.2\"" >&2
            exit 0
            ;;
        *"openssl version"*)
            echo "OpenSSL 3.0.2"
            exit 0
            ;;
    esac
    exit 0
elif [ "$1" = "compose" ]; then
    exit 0
fi
exit 0
""")
            os.chmod(mock_docker, 0o755)

            # Copy deploy dir to tmp test workspace
            test_deploy = os.path.join(tmpdir, "gmssl-gui-linux-amd64")
            shutil.copytree(DEPLOY_DIR, test_deploy)

            # Ensure .env exists in test_deploy
            test_env = os.path.join(test_deploy, ".env")
            with open(test_env, "w") as f:
                f.write("GMSSL_ENGINE_TOKEN=test-token\n"
                        "GMSSL_VAULT_MASTER_KEY=dGVzdC1tYXN0ZXIta2V5LTMyLWJ5dGVzISEhISEhISE=\n"
                        "GMSSL_BOOTSTRAP_USERNAME=admin\n"
                        "GMSSL_BOOTSTRAP_PASSWORD=adminpass123\n"
                        "SPRING_PROFILES_ACTIVE=dm\n"
                        "SPRING_DATASOURCE_URL=jdbc:dm://10.0.0.1:5236?schema=TEST\n"
                        "SPRING_DATASOURCE_USERNAME=test\n"
                        "SPRING_DATASOURCE_PASSWORD=test\n")

            env = os.environ.copy()
            env["PATH"] = f"{mock_bin}:{env.get('PATH', '')}"

            custom_jre = "local.harbor.internal:5000/base/temurin:21.0.2-jre"
            custom_nginx = "local.harbor.internal:5000/base/nginx:1.28-alpine"

            script = os.path.join(test_deploy, "start-with-jre.sh")
            res = subprocess.run(
                ["bash", script, "--jre-image", custom_jre, "--nginx-image", custom_nginx],
                env=env,
                cwd=test_deploy,
                capture_output=True,
                text=True
            )
            self.assertEqual(res.returncode, 0, f"Script failed: {res.stderr}\nOutput: {res.stdout}")

            with open(log_file, "r") as f:
                calls = f.read()

            # Verify image inspect checks
            self.assertIn(f"image inspect {custom_jre}", calls)
            self.assertIn(f"image inspect {custom_nginx}", calls)

            # Verify target container user probe
            self.assertIn("--user 10001:10001", calls)

            # Verify docker compose call flags
            self.assertIn("-f compose.jre.yaml", calls)
            self.assertIn("--pull never", calls)
            self.assertIn("--no-build", calls)
            self.assertIn("--force-recreate", calls)

    def test_06_package_script_includes_start_with_jre(self):
        pkg_script = os.path.join(REPO_ROOT, "scripts/package-linux-amd64.sh")
        with open(pkg_script, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("start-with-jre.sh", content)
        self.assertIn("compose.jre.yaml", content)

    def test_07_rejects_non_10001_user_and_never_starts(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mock_bin = os.path.join(tmpdir, "bin")
            log_file = os.path.join(tmpdir, "docker.log")
            os.makedirs(mock_bin)
            with open(os.path.join(mock_bin, "docker"), "w") as f:
                f.write(f"""#!/bin/sh
echo "$@" >> "{log_file}"
exit 0
""")
            os.chmod(os.path.join(mock_bin, "docker"), 0o755)

            test_deploy = os.path.join(tmpdir, "gmssl-gui-linux-amd64")
            shutil.copytree(DEPLOY_DIR, test_deploy)
            script = os.path.join(test_deploy, "start-with-jre.sh")
            env_base = os.environ.copy()
            env_base["PATH"] = f"{mock_bin}:{env_base.get('PATH', '')}"

            # Test invalid formats: non-10001 UID, non-10001 GID, single number, username root
            invalid_users = ["1000:1000", "10001:0", "10001", "root", "10001:1000"]
            for bad_u in invalid_users:
                with open(os.path.join(test_deploy, ".env"), "w") as f:
                    f.write(f"GMSSL_CONTAINER_USER={bad_u}\n")
                with open(log_file, "w") as f: f.write("")
                res = subprocess.run(["bash", script, "--jre-image", "temurin:21"], cwd=test_deploy, env=env_base, capture_output=True, text=True)
                self.assertNotEqual(res.returncode, 0, f"Expected rejection for {bad_u}")
                self.assertIn("Container user mismatch", res.stderr)
                # Verify that docker compose up was NEVER called on invalid user
                if os.path.exists(log_file):
                    with open(log_file, "r") as f: calls = f.read()
                    self.assertNotIn("compose.jre.yaml", calls, f"docker compose up must not be called when validation fails for {bad_u}")
                    self.assertNotIn("up -d", calls, f"docker compose up must not be called when validation fails for {bad_u}")

    def test_08_shell_env_priority_over_dotenv(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mock_bin = os.path.join(tmpdir, "bin")
            log_file = os.path.join(tmpdir, "docker.log")
            os.makedirs(mock_bin)
            with open(os.path.join(mock_bin, "docker"), "w") as f:
                f.write(f"""#!/bin/sh
echo "$@" >> "{log_file}"
if [ "$1" = "run" ]; then
    echo "openjdk version \"21.0.2\"" >&2
    echo "OpenSSL 3.0.2"
fi
exit 0
""")
            os.chmod(os.path.join(mock_bin, "docker"), 0o755)

            test_deploy = os.path.join(tmpdir, "gmssl-gui-linux-amd64")
            shutil.copytree(DEPLOY_DIR, test_deploy)
            # .env sets invalid user 1000:1000, but shell sets valid 10001:10001
            with open(os.path.join(test_deploy, ".env"), "w") as f:
                f.write("GMSSL_CONTAINER_USER=1000:1000\n")

            env = os.environ.copy()
            env["PATH"] = f"{mock_bin}:{env.get('PATH', '')}"
            env["GMSSL_CONTAINER_USER"] = "10001:10001"

            script = os.path.join(test_deploy, "start-with-jre.sh")
            res = subprocess.run(["bash", script, "--jre-image", "temurin:21"], cwd=test_deploy, env=env, capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, f"Shell priority failed: {res.stderr}\n{res.stdout}")
            with open(log_file, "r") as f: calls = f.read()
            self.assertIn("--user 10001:10001", calls)

    def test_09_dotenv_only_container_user_resolution(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mock_bin = os.path.join(tmpdir, "bin")
            log_file = os.path.join(tmpdir, "docker.log")
            os.makedirs(mock_bin)
            with open(os.path.join(mock_bin, "docker"), "w") as f:
                f.write(f"""#!/bin/sh
echo "$@" >> "{log_file}"
if [ "$1" = "run" ]; then
    echo "openjdk version \"21.0.2\"" >&2
    echo "OpenSSL 3.0.2"
fi
exit 0
""")
            os.chmod(os.path.join(mock_bin, "docker"), 0o755)

            test_deploy = os.path.join(tmpdir, "gmssl-gui-linux-amd64")
            shutil.copytree(DEPLOY_DIR, test_deploy)
            # shell has NO GMSSL_CONTAINER_USER, .env sets 10001:10001
            with open(os.path.join(test_deploy, ".env"), "w") as f:
                f.write("GMSSL_CONTAINER_USER=10001:10001\n")

            env = os.environ.copy()
            env["PATH"] = f"{mock_bin}:{env.get('PATH', '')}"
            env.pop("GMSSL_CONTAINER_USER", None)

            script = os.path.join(test_deploy, "start-with-jre.sh")
            res = subprocess.run(["bash", script, "--jre-image", "temurin:21"], cwd=test_deploy, env=env, capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, f"Dotenv resolution failed: {res.stderr}\n{res.stdout}")
            with open(log_file, "r") as f: calls = f.read()
            self.assertIn("--user 10001:10001", calls)


if __name__ == "__main__":
    unittest.main()
