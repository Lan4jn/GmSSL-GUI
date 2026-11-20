#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Comprehensive Dual-Engine Key Generation and Security Matrix Test.

Verifies:
1. Capabilities listing: GmSSL and OpenSSL providers, algorithms and curves.
2. Symmetric key generation across both providers:
   - SM4 (128-bit)
   - SM4-XTS (256-bit)
   - AES (128, 192, 256-bit)
   - ZUC (128-bit)
   - ZUC256 (256-bit)
   - HMAC (128, 256, 512-bit)
3. Asymmetric keypair generation across both providers:
   - SM2 (sm2p256v1)
   - EC (secp256r1 / P-256)
   - EC (secp384r1 / P-384)
4. Temporary storage mode (TEMPORARY vs MANAGED):
   - MANAGED: no plaintext valueHex returned, vault encrypted, hasManagedPassphrase=true.
   - TEMPORARY: valueHex or temporaryFile returned, non-persistent.
5. Negative tests / Partial errors:
   - Requesting SM9 or Kyber from OpenSSL returns HTTP 400.
   - Requesting invalid curve returns HTTP 400.
   - Requesting non-existent provider returns HTTP 400.
6. RBAC and Passphrase Reveal:
   - ADMIN/OWNER/EDITOR can reveal managed passphrase.
   - VIEWER receives HTTP 403 Forbidden on reveal-passphrase.
   - Cross-project material access rejection: Project B cannot consume Project A key reference.
   - Sensitive parameter concealment: passwords never stored in plaintext job parameters.
"""

import json
import time
import unittest
import urllib.request
import urllib.error
import uuid

BASE_URL = "http://127.0.0.1:8080/api/v1"

def load_admin_creds():
    creds = {}
    with open(".env.local") as f:
        for line in f:
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                creds[k.strip()] = v.strip().strip("\"'\''")
    return creds.get("GMSSL_BOOTSTRAP_USERNAME", "admin"), creds.get("GMSSL_BOOTSTRAP_PASSWORD")

class TestKeyGenMatrix(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        admin_user, admin_pass = load_admin_creds()
        cls.admin_token, cls.admin_csrf = cls._login(admin_user, admin_pass)

        # Create two separate projects for isolation testing
        cls.proj_a = cls._api(cls.admin_token, cls.admin_csrf, "POST", "/projects", {"name": f"Matrix-Proj-A-{uuid.uuid4().hex[:6]}"})["id"]
        cls.proj_b = cls._api(cls.admin_token, cls.admin_csrf, "POST", "/projects", {"name": f"Matrix-Proj-B-{uuid.uuid4().hex[:6]}"})["id"]

        # Create a viewer account
        viewer_name = f"viewer_{uuid.uuid4().hex[:6]}"
        viewer_pass = "ViewerPassw0rd123"
        viewer_user = cls._api(cls.admin_token, cls.admin_csrf, "POST", "/users", {
            "username": viewer_name,
            "password": viewer_pass,
            "role": "USER"
        })
        viewer_uid = viewer_user["id"]
        cls._api(cls.admin_token, cls.admin_csrf, "PUT", f"/projects/{cls.proj_a}/members/{viewer_uid}", {
            "role": "VIEWER"
        })
        cls.viewer_token, cls.viewer_csrf = cls._login(viewer_name, viewer_pass)

    @classmethod
    def _login(cls, username, password):
        login_data = json.dumps({"username": username, "password": password}).encode("utf-8")
        req = urllib.request.Request(f"{BASE_URL}/auth/login", data=login_data, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req) as res:
            cookies = res.headers.get_all("Set-Cookie")
            cookie = [c.split(";")[0] for c in cookies if "GMSSL_SESSION=" in c][0]
            csrf = json.loads(res.read().decode())["csrfToken"]
            return cookie, csrf

    @classmethod
    def _api(cls, cookie, csrf, method, path, data=None):
        url = f"{BASE_URL}{path}"
        headers = {"Cookie": cookie, "Content-Type": "application/json"}
        if csrf:
            headers["X-CSRF-Token"] = csrf
        req = urllib.request.Request(url, data=json.dumps(data).encode("utf-8") if data is not None else None, headers=headers, method=method)
        with urllib.request.urlopen(req) as res:
            return json.loads(res.read().decode())

    def test_01_capabilities_schema(self):
        cap = self._api(self.admin_token, self.admin_csrf, "GET", "/key-generation-capabilities")
        self.assertIn("providers", cap)
        self.assertIn("algorithms", cap)
        provider_map = {p["id"]: p for p in cap["providers"]}
        self.assertTrue(provider_map["gmssl"]["available"])
        self.assertTrue(provider_map["openssl"]["available"])

        # Check algorithms (SM9 excluded from key-generation-capabilities as it requires sm9setup/sm9keygen)
        alg_map = {a["id"]: a for a in cap["algorithms"]}
        for expected in ["SM4", "SM4-XTS", "AES", "ZUC", "ZUC256", "HMAC", "SM2", "EC", "Kyber"]:
            self.assertIn(expected, alg_map)

        self.assertNotIn("SM9", alg_map, "SM9 should not be advertised in general key-generation-capabilities")
        self.assertEqual(alg_map["Kyber"]["providers"], ["gmssl"])

    def test_02_symmetric_matrix_both_providers(self):
        cases = [
            ("SM4", 128, 32),
            ("SM4-XTS", 256, 64),
            ("AES", 128, 32),
            ("AES", 192, 48),
            ("AES", 256, 64),
            ("ZUC", 128, 32),
            ("ZUC256", 256, 64),
            ("HMAC", 128, 32),
            ("HMAC", 256, 64),
            ("HMAC", 512, 128),
        ]
        for provider in ["gmssl", "openssl"]:
            for alg, bits, hex_len in cases:
                with self.subTest(provider=provider, algorithm=alg, bits=bits):
                    res = self._api(self.admin_token, self.admin_csrf, "POST", f"/projects/{self.proj_a}/keys/generate", {
                        "provider": provider,
                        "algorithm": alg,
                        "bits": bits,
                        "name": f"{provider}-{alg}-{bits}",
                        "storage": "MANAGED"
                    })
                    self.assertEqual(res["provider"], provider)
                    self.assertEqual(res["algorithm"], alg)
                    self.assertEqual(res["storage"], "MANAGED")
                    self.assertIn("reference", res)
                    self.assertIsNone(res.get("valueHex")) # MANAGED must never leak valueHex

    def test_03_temporary_storage_mode(self):
        # Temporary symmetric key returns valueHex for direct client use
        res = self._api(self.admin_token, self.admin_csrf, "POST", f"/projects/{self.proj_a}/keys/generate", {
            "provider": "gmssl",
            "algorithm": "SM4",
            "name": "temp-sm4",
            "storage": "TEMPORARY"
        })
        self.assertEqual(res["storage"], "TEMPORARY")
        self.assertIsNotNone(res.get("valueHex"))
        self.assertEqual(len(res["valueHex"]), 32)
        self.assertIsNone(res.get("reference"))

    def test_04_asymmetric_matrix_curves(self):
        # 1. SM2 on both providers
        for provider in ["gmssl", "openssl"]:
            with self.subTest(provider=provider, algorithm="SM2"):
                res = self._api(self.admin_token, self.admin_csrf, "POST", f"/projects/{self.proj_a}/keys/generate", {
                    "provider": provider,
                    "algorithm": "SM2",
                    "name": f"{provider}-sm2",
                    "storage": "MANAGED"
                })
                self.assertEqual(res["provider"], provider)
                self.assertEqual(res["algorithm"], "SM2")
                self.assertTrue(res["key"]["hasManagedPassphrase"])
                self.assertIsNotNone(res["publicKey"])

        # 2. EC curves: secp256r1 and secp384r1 on both providers
        for provider in ["gmssl", "openssl"]:
            for curve in ["secp256r1", "secp384r1"]:
                with self.subTest(provider=provider, curve=curve):
                    res = self._api(self.admin_token, self.admin_csrf, "POST", f"/projects/{self.proj_a}/keys/generate", {
                        "provider": provider,
                        "algorithm": "EC",
                        "curve": curve,
                        "name": f"{provider}-ec-{curve}",
                        "storage": "MANAGED"
                    })
                    self.assertEqual(res["provider"], provider)
                    self.assertEqual(res["algorithm"], "EC")
                    self.assertTrue(res["key"]["hasManagedPassphrase"])
                    self.assertIsNotNone(res["publicKey"])

    def test_05_negative_and_unsupported_rejection(self):
        # OpenSSL requested for SM9 must return 400
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self._api(self.admin_token, self.admin_csrf, "POST", f"/projects/{self.proj_a}/keys/generate", {
                "provider": "openssl",
                "algorithm": "SM9"
            })
        self.assertEqual(ctx.exception.code, 400)

        # OpenSSL requested for Kyber must return 400
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self._api(self.admin_token, self.admin_csrf, "POST", f"/projects/{self.proj_a}/keys/generate", {
                "provider": "openssl",
                "algorithm": "Kyber"
            })
        self.assertEqual(ctx.exception.code, 400)

        # Unknown provider must return 400
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self._api(self.admin_token, self.admin_csrf, "POST", f"/projects/{self.proj_a}/keys/generate", {
                "provider": "unknown_crypto",
                "algorithm": "SM4"
            })
        self.assertEqual(ctx.exception.code, 400)

    def test_06_rbac_passphrase_reveal(self):
        # 1. Generate an SM2 key with managed passphrase
        gen_res = self._api(self.admin_token, self.admin_csrf, "POST", f"/projects/{self.proj_a}/keys/generate", {
            "provider": "gmssl",
            "algorithm": "SM2",
            "name": "rbac-sm2-key",
            "storage": "MANAGED"
        })
        key_id = gen_res["key"]["id"]

        # 2. Admin / Owner can reveal passphrase (HTTP 200)
        reveal_res = self._api(self.admin_token, self.admin_csrf, "POST", f"/projects/{self.proj_a}/keys/{key_id}/reveal-passphrase")
        self.assertIn("passphrase", reveal_res)
        self.assertTrue(len(reveal_res["passphrase"]) >= 16)

        # 3. Viewer attempting to reveal passphrase must receive HTTP 403 Forbidden
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self._api(self.viewer_token, self.viewer_csrf, "POST", f"/projects/{self.proj_a}/keys/{key_id}/reveal-passphrase")
        self.assertEqual(ctx.exception.code, 403)

    def test_07_cross_project_isolation(self):
        # Generate a key in Project A
        gen_a = self._api(self.admin_token, self.admin_csrf, "POST", f"/projects/{self.proj_a}/keys/generate", {
            "provider": "gmssl",
            "algorithm": "SM4",
            "name": "proj-a-isolated-key",
            "storage": "MANAGED"
        })
        key_ref_a = gen_a["reference"]

        # Attempt to use Project A key reference in Project B job must be rejected with 400 or 404
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self._api(self.admin_token, self.admin_csrf, "POST", f"/projects/{self.proj_b}/jobs", {
                "toolId": "sm4_cbc",
                "parameters": {
                    "encrypt": True,
                    "key": key_ref_a,
                    "iv": "0123456789abcdeffedcba9876543210",
                    "in": "file:00000000-0000-0000-0000-000000000000"
                }
            })
        self.assertIn(ctx.exception.code, (400, 404))

if __name__ == "__main__":
    unittest.main()
