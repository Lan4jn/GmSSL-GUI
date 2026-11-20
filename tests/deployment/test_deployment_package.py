#!/usr/bin/env python3
"""Comprehensive deployment verification suite for deploy/gmssl-gui-linux-amd64."""

import hashlib
import json
import os
import stat
import subprocess
import tempfile
import unittest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
DEPLOY_DIR = os.path.join(REPO_ROOT, "deploy/gmssl-gui-linux-amd64")


class TestDeploymentPackage(unittest.TestCase):

    def test_01_runner_elf_architecture(self):
        """Runner must be valid Linux x86_64 ELF and not Mach-O or 32-bit."""
        runner_bin = os.path.join(DEPLOY_DIR, "artifacts/gmssl-runner")
        self.assertTrue(os.path.exists(runner_bin), "gmssl-runner missing from artifacts")

        with open(runner_bin, "rb") as f:
            hdr = f.read(64)

        # Magic: \x7fELF
        self.assertEqual(hdr[:4], b"\x7fELF", "Not an ELF binary")
        # EI_CLASS: 2 = 64-bit
        self.assertEqual(hdr[4], 2, "Not a 64-bit binary")
        # EI_DATA: 1 = LSB (little endian)
        self.assertEqual(hdr[5], 1, "Not little-endian")
        # e_machine: 0x3E (62) = AMD x86-64
        e_machine = int.from_bytes(hdr[18:20], "little")
        self.assertEqual(e_machine, 0x3E, f"Not x86-64 machine type (got {hex(e_machine)})")

    def test_02_zero_secrets_and_clean_package(self):
        """Deploy directory must contain zero .env, zero credentials, zero node_modules, zero source files, zero symlinks."""
        forbidden_extensions = (".java", ".ts", ".vue", ".c", ".h")
        forbidden_names = ("pom.xml", "package.json", "credentials.txt", ".env")

        for root, dirs, files in os.walk(DEPLOY_DIR):
            for d in dirs:
                self.assertNotIn(d, ("node_modules", ".git", ".tools", ".runtime"), f"Forbidden dir: {d}")
                self.assertFalse(os.path.islink(os.path.join(root, d)), f"Symlink dir in release: {d}")
            for f in files:
                full_path = os.path.join(root, f)
                rel = os.path.relpath(full_path, DEPLOY_DIR)
                self.assertFalse(os.path.islink(full_path), f"Symlink file in release: {rel}")
                if f.startswith(".env") and f != ".env.example":
                    self.fail(f"Private env file found: {rel}")
                self.assertNotIn(f, forbidden_names, f"Forbidden file name: {rel}")
                for ext in forbidden_extensions:
                    self.assertFalse(f.endswith(ext), f"Source file in release: {rel}")

    def test_03_zero_file_hash_verification_and_no_sha256sums(self):
        """Release package must NOT contain SHA256SUMS or tar.sha256 per user hard requirement."""
        sha_file = os.path.join(DEPLOY_DIR, "SHA256SUMS")
        outer_sha = os.path.join(REPO_ROOT, "deploy/gmssl-gui-linux-amd64.tar.gz.sha256")
        self.assertFalse(os.path.exists(sha_file), "SHA256SUMS must be removed per user requirement")
        self.assertFalse(os.path.exists(outer_sha), "tar.sha256 must be removed per user requirement")

        # Required offline artifacts must exist directly
        req_artifacts = [
            "artifacts/engine-service-0.1.0-SNAPSHOT.jar",
            "artifacts/platform-service-0.1.0-SNAPSHOT.jar",
            "artifacts/gmssl-runner",
            "artifacts/01_schema_dm8.sql",
            "artifacts/migrations/00_schema_version_and_baseline.sql",
            "artifacts/web-dist/index.html"
        ]
        for rel in req_artifacts:
            self.assertTrue(os.path.exists(os.path.join(DEPLOY_DIR, rel)), f"Missing offline artifact: {rel}")

    def test_04_manifest_schema_and_offline_mode(self):
        """manifest.json must describe artifacts and offline structure verification."""
        manifest_file = os.path.join(DEPLOY_DIR, "manifest.json")
        self.assertTrue(os.path.exists(manifest_file), "manifest.json missing")

        with open(manifest_file, "r") as f:
            data = json.load(f)

        self.assertEqual(data.get("name"), "gmssl-gui-linux-amd64")
        self.assertEqual(data.get("target_architecture"), "linux-amd64")
        self.assertEqual(data.get("verification_mode"), "offline-structure-only")

        artifacts = data.get("artifacts", {})
        self.assertIn("artifacts/engine-service-0.1.0-SNAPSHOT.jar", artifacts)
        self.assertIn("artifacts/platform-service-0.1.0-SNAPSHOT.jar", artifacts)
        self.assertIn("artifacts/gmssl-runner", artifacts)
        self.assertIn("artifacts/web-dist/index.html", artifacts)

    def test_05_dockerfiles_only_copy_precompiled_and_compose_platform(self):
        """Runtime Dockerfiles must only copy, nginx must be 1.28-alpine, compose must set platform: linux/amd64."""
        docker_dir = os.path.join(DEPLOY_DIR, "docker")
        forbidden_commands = ["mvn ", "npm ", "pnpm ", "cmake ", "git clone", "make "]

        for df in os.listdir(docker_dir):
            if df.endswith(".Dockerfile"):
                path = os.path.join(docker_dir, df)
                with open(path, "r") as f:
                    content = f.read()
                for cmd in forbidden_commands:
                    self.assertNotIn(cmd, content, f"Build tool invocation '{cmd}' found in runtime {df}")
                self.assertIn("COPY", content, f"No COPY instruction in {df}")
                if df == "web.Dockerfile":
                    self.assertIn("nginx:1.28-alpine", content)

        # Check compose.yaml
        compose_path = os.path.join(DEPLOY_DIR, "compose.yaml")
        with open(compose_path, "r") as f:
            compose_text = f.read()
        self.assertIn("platform: linux/amd64", compose_text)
        self.assertTrue(os.path.exists(os.path.join(DEPLOY_DIR, "upgrade.sh")))
        self.assertNotIn("down -v", compose_text)

    def test_06_dockerignore_prevents_secret_leak(self):
        """.dockerignore must exist and strictly ignore .env and credentials."""
        di_path = os.path.join(DEPLOY_DIR, ".dockerignore")
        self.assertTrue(os.path.exists(di_path))
        with open(di_path, "r") as f:
            di_text = f.read()
        self.assertTrue(di_text.startswith("*\n") or di_text.startswith("*\r\n") or di_text.startswith("*"))
        self.assertNotIn("!.env", di_text)
        self.assertNotIn("!credentials", di_text)

    def test_07_verify_native_kat_logic(self):
        """verify-native.sh must correctly pass on matching KAT, support paths with spaces, and fail on corrupt/failing runners."""
        verify_script = os.path.join(DEPLOY_DIR, "scripts/verify-native.sh")
        self.assertTrue(os.path.exists(verify_script))