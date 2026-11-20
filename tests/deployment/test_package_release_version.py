#!/usr/bin/env python3
"""Release version argument validation and offline doc label assertions."""
import os
import subprocess
import unittest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
PACKAGE = os.path.join(REPO_ROOT, "scripts/package-linux-amd64.sh")

class TestPackageReleaseVersion(unittest.TestCase):
    def test_help_documents_version_flag(self):
        r = subprocess.run(["bash", PACKAGE, "--help"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("--version <version>", r.stdout)

    def test_missing_version_value_fails(self):
        r = subprocess.run(["bash", PACKAGE, "--version"], capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("Missing value for --version", r.stderr)

    def test_unsafe_and_non_semver_versions_fail_before_packaging(self):
        for version in ("../evil", "0.1.5/path", "latest", "0.1"):
            r = subprocess.run(["bash", PACKAGE, "--version", version, "--skip-tar"], capture_output=True, text=True)
            self.assertNotEqual(r.returncode, 0, f"Expected invalid version rejection for {version}")
            self.assertIn("Invalid release version", r.stderr)

    def test_default_version_is_0_1_5(self):
        with open(PACKAGE, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn('RELEASE_VERSION="${RELEASE_VERSION:-0.1.5}"', content)

    def test_offline_docs_contain_accurate_simple_mode_labels(self):
        doc_files = [
            os.path.join(REPO_ROOT, "docs/离线部署说明.md"),
            os.path.join(REPO_ROOT, "docs/离线更新说明.md")
        ]
        for df in doc_files:
            self.assertTrue(os.path.exists(df), f"Missing {df}")
            with open(df, "r", encoding="utf-8") as f:
                c = f.read()
            self.assertIn("工作台、密钥库、任务历史、项目与成员", c, f"Missing 4-nav in {df}")
            self.assertIn("制作证书", c, f"Missing '制作证书' in {df}")
            self.assertIn("我的材料库", c, f"Missing '我的材料库' in {df}")
            self.assertIn("CSR 与证书双向关联", c, f"Missing CSR association section in {df}")
            self.assertIn("未匹配不等于未签发", c, f"Missing '未匹配不等于未签发' in {df}")
            self.assertIn("gmssl-gui-linux-0.1.5.tar.gz", c, f"Missing 0.1.5 package ref in {df}")
            self.assertNotIn("工作台、密码工具箱、密钥材料库、审计日志", c, f"Obsolete 4-nav in {df}")
            self.assertNotIn("申请/签发证书", c, f"Obsolete card in {df}")

if __name__ == "__main__":
    unittest.main()
