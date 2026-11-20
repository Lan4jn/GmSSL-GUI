#!/usr/bin/env python3
"""TDD Test Suite for task-59: User-defined Base JRE Image in build-offline-images.sh."""

import os
import stat
import subprocess
import tempfile
import unittest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
DEPLOY_DIR = os.path.join(REPO_ROOT, "deploy/gmssl-gui-linux-amd64")


class TestJreImageSelection(unittest.TestCase):

    def test_01_dockerfiles_have_arg_base_jre_before_from(self):
        dockerfiles = [
            os.path.join(REPO_ROOT, "ops/engine.Dockerfile"),
            os.path.join(REPO_ROOT, "ops/platform.Dockerfile"),
            os.path.join(DEPLOY_DIR, "docker/engine.Dockerfile"),
            os.path.join(DEPLOY_DIR, "docker/platform.Dockerfile")
        ]
        for df in dockerfiles:
            self.assertTrue(os.path.exists(df), f"Missing {df}")
            with open(df, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("ARG BASE_JRE_IMAGE", content, f"Missing ARG BASE_JRE_IMAGE in {df}")
            self.assertIn("FROM " + chr(36) + "{BASE_JRE_IMAGE}", content, f"Missing FROM in {df}")

    def test_02_build_script_help_and_syntax(self):
        script = os.path.join(REPO_ROOT, "scripts/build-offline-images.sh")
        self.assertTrue(os.path.exists(script))

        res_syntax = subprocess.run(["bash", "-n", script], capture_output=True, text=True)
        self.assertEqual(res_syntax.returncode, 0, f"Syntax error: {res_syntax.stderr}")

        res_help = subprocess.run(["bash", script, "--help"], capture_output=True, text=True)
        self.assertEqual(res_help.returncode, 0)
        self.assertIn("--jre-image", res_help.stdout)
        self.assertIn("JRE_IMAGE", res_help.stdout)

    def test_03_mock_docker_captures_explicit_cli_jre_image(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mock_bin_dir = os.path.join(tmpdir, "bin")
            log_file = os.path.join(tmpdir, "docker_calls.log")
            os.makedirs(mock_bin_dir)

            mock_docker = os.path.join(mock_bin_dir, "docker")
            with open(mock_docker, "w") as f:
                f.write("#!/bin/sh\necho \"$@\" >> \"" + log_file + "\"\nif [ \"$1\" = \"build\" ]; then exit 0; elif [ \"$1\" = \"save\" ]; then touch \"$3\"; exit 0; fi\nexit 0\n")
            os.chmod(mock_docker, 0o755)

            env = os.environ.copy()
            env["PATH"] = f"{mock_bin_dir}:{env.get('PATH', '')}"

            custom_image = "my.private.registry:5000/custom-corp/temurin:21.0.2-jre"
            tar_output = os.path.join(tmpdir, "test-images.tar")

            script = os.path.join(REPO_ROOT, "scripts/build-offline-images.sh")
            res = subprocess.run(
                ["bash", script, "--jre-image", custom_image, tar_output],
                env=env,
                capture_output=True,
                text=True
            )
            self.assertEqual(res.returncode, 0, f"Script failed: {res.stderr}")

            with open(log_file, "r") as f:
                calls = f.read()

            self.assertIn(f"--build-arg BASE_JRE_IMAGE={custom_image}", calls)
            self.assertNotIn("eclipse-temurin:21-jre-jammy", calls)

    def test_04_priority_cli_over_env_over_default(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mock_bin_dir = os.path.join(tmpdir, "bin")
            log_file = os.path.join(tmpdir, "docker_calls.log")
            os.makedirs(mock_bin_dir)

            mock_docker = os.path.join(mock_bin_dir, "docker")
            with open(mock_docker, "w") as f:
                f.write("#!/bin/sh\necho \"$@\" >> \"" + log_file + "\"\nif [ \"$1\" = \"build\" ]; then exit 0; elif [ \"$1\" = \"save\" ]; then touch \"$3\"; exit 0; fi\nexit 0\n")
            os.chmod(mock_docker, 0o755)

            env = os.environ.copy()
            env["PATH"] = f"{mock_bin_dir}:{env.get('PATH', '')}"
            env["JRE_IMAGE"] = "env.registry:5000/java:21-env"

            script = os.path.join(REPO_ROOT, "scripts/build-offline-images.sh")
            tar_output = os.path.join(tmpdir, "test-images.tar")

            cli_image = "cli.registry:5000/java:21-cli"
            res_cli = subprocess.run(
                ["bash", script, "--jre-image", cli_image, tar_output],
                env=env,
                capture_output=True,
                text=True
            )
            self.assertEqual(res_cli.returncode, 0)
            with open(log_file, "r") as f:
                calls_a = f.read()
            self.assertIn(f"--build-arg BASE_JRE_IMAGE={cli_image}", calls_a)
            self.assertNotIn("env.registry", calls_a)

            with open(log_file, "w") as f: f.write("")

            res_env = subprocess.run(
                ["bash", script, tar_output],
                env=env,
                capture_output=True,
                text=True
            )
            self.assertEqual(res_env.returncode, 0)
            with open(log_file, "r") as f:
                calls_b = f.read()
            self.assertIn("--build-arg BASE_JRE_IMAGE=env.registry:5000/java:21-env", calls_b)
            self.assertNotIn("eclipse-temurin:21-jre-jammy", calls_b)

    def test_05_error_handling_missing_jre_arg_value(self):
        script = os.path.join(REPO_ROOT, "scripts/build-offline-images.sh")
        res = subprocess.run(["bash", script, "--jre-image"], capture_output=True, text=True)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("Missing value for --jre-image", res.stderr)


if __name__ == "__main__":
    unittest.main()
