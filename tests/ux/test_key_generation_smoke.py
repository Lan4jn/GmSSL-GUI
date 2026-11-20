#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Smoke test for Dual-Engine Key Generation and Managed Passphrase Injection.

Verifies:
1. Capabilities endpoint exposure for both gmssl and openssl providers.
2. SM4 symmetric key generation (MANAGED) via gmssl and openssl.
3. SM4 encryption and decryption roundtrip using key references (no raw key in job parameters).
4. SM2 asymmetric keypair generation (MANAGED) via gmssl and openssl.
5. SM2 signing without user-supplied passphrase (automatic passphrase injection by platform).
6. SM2 signature verification using the generated public key.
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

class TestKeyGenSmoke(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        username, password = load_admin_creds()
        login_data = json.dumps({"username": username, "password": password}).encode("utf-8")
        req = urllib.request.Request(f"{BASE_URL}/auth/login", data=login_data, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req) as res:
            cookies = res.headers.get_all("Set-Cookie")
            cls.cookie = [c.split(";")[0] for c in cookies if "GMSSL_SESSION=" in c][0]
            body = json.loads(res.read().decode())
            cls.csrf = body["csrfToken"]

        # Create a test project
        proj_data = json.dumps({"name": f"UX-Smoke-{uuid.uuid4().hex[:8]}"}).encode("utf-8")
        preq = urllib.request.Request(
            f"{BASE_URL}/projects",
            data=proj_data,
            headers={"Content-Type": "application/json", "Cookie": cls.cookie, "X-CSRF-Token": cls.csrf}
        )
        with urllib.request.urlopen(preq) as res:
            pbody = json.loads(res.read().decode())
            cls.project_id = pbody["id"]

    def _api(self, method, path, data=None):
        url = f"{BASE_URL}{path}"
        headers = {"Cookie": self.cookie, "X-CSRF-Token": self.csrf, "Content-Type": "application/json"}
        req = urllib.request.Request(url, data=json.dumps(data).encode("utf-8") if data is not None else None, headers=headers, method=method)
        with urllib.request.urlopen(req) as res:
            return json.loads(res.read().decode())

    def _upload_file(self, filename, content_bytes):
        boundary = "----WebKitFormBoundary" + uuid.uuid4().hex
        body = (
            f"--{boundary}\r\n"
            f"Content-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n"
            f"Content-Type: application/octet-stream\r\n\r\n"
        ).encode("utf-8") + content_bytes + f"\r\n--{boundary}--\r\n".encode("utf-8")

        ureq = urllib.request.Request(
            f"{BASE_URL}/projects/{self.project_id}/files",
            data=body,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}", "Cookie": self.cookie, "X-CSRF-Token": self.csrf}
        )
        with urllib.request.urlopen(ureq) as res:
            return json.loads(res.read().decode())["id"]

    def _download_artifact(self, job_id, artifact_id):
        url = f"{BASE_URL}/projects/{self.project_id}/jobs/{job_id}/artifacts/{artifact_id}/download"
        req = urllib.request.Request(url, headers={"Cookie": self.cookie})
        with urllib.request.urlopen(req) as res:
            return res.read()

    def _poll_job(self, job_id, timeout_sec=10):
        start = time.time()
        while time.time() - start < timeout_sec:
            poll_req = urllib.request.Request(f"{BASE_URL}/projects/{self.project_id}/jobs/{job_id}", headers={"Cookie": self.cookie})
            with urllib.request.urlopen(poll_req) as res:
                job = json.loads(res.read().decode())
                if job["status"] in ("SUCCEEDED", "FAILED"):
                    return job
            time.sleep(0.1)
        raise TimeoutError(f"Job {job_id} did not complete in {timeout_sec}s")

    def test_01_capabilities(self):
        cap = self._api("GET", "/key-generation-capabilities")
        providers = {p["id"]: p for p in cap["providers"]}
        self.assertIn("gmssl", providers)
        self.assertIn("openssl", providers)
        self.assertTrue(providers["gmssl"]["available"])
        self.assertTrue(providers["openssl"]["available"])
        self.assertIn("OpenSSL", providers["openssl"]["version"])

    def test_02_sm4_generate_and_roundtrip_gmssl(self):
        # 1. Generate SM4 with GmSSL provider
        gen_res = self._api("POST", f"/projects/{self.project_id}/keys/generate", {
            "provider": "gmssl",
            "algorithm": "SM4",
            "name": "gmssl-sm4-test",
            "storage": "MANAGED"
        })
        self.assertEqual(gen_res["provider"], "gmssl")
        self.assertEqual(gen_res["algorithm"], "SM4")
        self.assertEqual(gen_res["storage"], "MANAGED")
        self.assertIn("reference", gen_res)
        key_ref = gen_res["reference"]
        self.assertIsNone(gen_res.get("valueHex")) # Must not leak valueHex for MANAGED

        plain_bytes = b"GmSSL Native SM4 Roundtrip Verification Payload!"
        file_id = self._upload_file("plain.txt", plain_bytes)

        # 2. Encrypt using reference in GmSSL engine
        enc_init = self._api("POST", f"/projects/{self.project_id}/jobs", {
            "toolId": "sm4_cbc",
            "parameters": {
                "encrypt": True,
                "key": key_ref,
                "iv": "0123456789abcdeffedcba9876543210",
                "in": f"file:{file_id}",
                "out": "cipher.bin"
            }
        })
        enc_job = self._poll_job(enc_init["id"])
        self.assertEqual(enc_job["status"], "SUCCEEDED")
        self.assertTrue(len(enc_job.get("artifacts", [])) > 0)
        cipher_bytes = self._download_artifact(enc_job["id"], enc_job["artifacts"][0]["id"])
        self.assertNotEqual(cipher_bytes, plain_bytes)

        # 3. Decrypt using reference in GmSSL engine
        cipher_file_id = self._upload_file("cipher.bin", cipher_bytes)
        dec_init = self._api("POST", f"/projects/{self.project_id}/jobs", {
            "toolId": "sm4_cbc",
            "parameters": {
                "decrypt": True,
                "key": key_ref,
                "iv": "0123456789abcdeffedcba9876543210",
                "in": f"file:{cipher_file_id}",
                "out": "decrypted.txt"
            }
        })
        dec_job = self._poll_job(dec_init["id"])
        self.assertEqual(dec_job["status"], "SUCCEEDED")
        decrypted_bytes = self._download_artifact(dec_job["id"], dec_job["artifacts"][0]["id"])
        self.assertEqual(decrypted_bytes, plain_bytes)

    def test_03_sm4_generate_and_roundtrip_openssl(self):
        # 1. Generate SM4 with OpenSSL provider
        gen_res = self._api("POST", f"/projects/{self.project_id}/keys/generate", {
            "provider": "openssl",
            "algorithm": "SM4",
            "name": "openssl-sm4-test",
            "storage": "MANAGED"
        })
        self.assertEqual(gen_res["provider"], "openssl")
        self.assertEqual(gen_res["algorithm"], "SM4")
        self.assertEqual(gen_res["storage"], "MANAGED")
        key_ref = gen_res["reference"]
        self.assertIsNone(gen_res.get("valueHex"))

        plain_bytes = b"OpenSSL Generated SM4 Decrypted by GmSSL Engine!"
        file_id = self._upload_file("plain2.txt", plain_bytes)

        # 2. Encrypt using reference in GmSSL engine
        enc_init = self._api("POST", f"/projects/{self.project_id}/jobs", {
            "toolId": "sm4_cbc",
            "parameters": {
                "encrypt": True,
                "key": key_ref,
                "iv": "fedcba98765432100123456789abcdef",
                "in": f"file:{file_id}",
                "out": "cipher2.bin"
            }
        })
        enc_job = self._poll_job(enc_init["id"])
        self.assertEqual(enc_job["status"], "SUCCEEDED")
        cipher_bytes = self._download_artifact(enc_job["id"], enc_job["artifacts"][0]["id"])
        self.assertNotEqual(cipher_bytes, plain_bytes)

        # 3. Decrypt using reference in GmSSL engine
        cipher_file_id = self._upload_file("cipher2.bin", cipher_bytes)
        dec_init = self._api("POST", f"/projects/{self.project_id}/jobs", {
            "toolId": "sm4_cbc",
            "parameters": {
                "decrypt": True,
                "key": key_ref,
                "iv": "fedcba98765432100123456789abcdef",
                "in": f"file:{cipher_file_id}",
                "out": "decrypted2.txt"
            }
        })
        dec_job = self._poll_job(dec_init["id"])
        self.assertEqual(dec_job["status"], "SUCCEEDED")
        decrypted_bytes = self._download_artifact(dec_job["id"], dec_job["artifacts"][0]["id"])
        self.assertEqual(decrypted_bytes, plain_bytes)

    def test_04_sm2_generate_and_passless_sign_gmssl(self):
        # 1. Generate SM2 keypair with GmSSL provider without password
        gen_res = self._api("POST", f"/projects/{self.project_id}/keys/generate", {
            "provider": "gmssl",
            "algorithm": "SM2",
            "name": "gmssl-sm2-test",
            "storage": "MANAGED"
        })
        self.assertEqual(gen_res["provider"], "gmssl")
        self.assertEqual(gen_res["algorithm"], "SM2")
        priv_key = gen_res["key"]
        pub_key = gen_res["publicKey"]
        self.assertTrue(priv_key.get("hasManagedPassphrase"))
        priv_ref = gen_res["reference"]
        pub_ref = f"key:{pub_key['id']}"

        data_bytes = b"SM2 Passless Sign with GmSSL Provider Key"
        file_id = self._upload_file("data.bin", data_bytes)

        # 2. Sign without providing 'pass' parameter (platform automatically injects managed passphrase)
        sign_init = self._api("POST", f"/projects/{self.project_id}/jobs", {
            "toolId": "sm2sign",
            "parameters": {
                "key": priv_ref,
                "id": "1234567812345678",
                "in": f"file:{file_id}",
                "out": "sig.der"
            }
        })
        sign_job = self._poll_job(sign_init["id"])
        self.assertEqual(sign_job["status"], "SUCCEEDED")
        sig_bytes = self._download_artifact(sign_job["id"], sign_job["artifacts"][0]["id"])
        self.assertTrue(len(sig_bytes) >= 64)

        # 3. Verify signature with public key
        sig_file_id = self._upload_file("sig.der", sig_bytes)
        verify_init = self._api("POST", f"/projects/{self.project_id}/jobs", {
            "toolId": "sm2verify",
            "parameters": {
                "pubkey": pub_ref,
                "id": "1234567812345678",
                "sig": f"file:{sig_file_id}",
                "in": f"file:{file_id}"
            }
        })
        verify_job = self._poll_job(verify_init["id"])
        self.assertEqual(verify_job["status"], "SUCCEEDED")

    def test_05_sm2_generate_and_passless_sign_openssl(self):
        # 1. Generate SM2 keypair with OpenSSL provider without password
        # Bridge translates OpenSSL PKCS#8 into GmSSL-compatible encrypted PEM
        gen_res = self._api("POST", f"/projects/{self.project_id}/keys/generate", {
            "provider": "openssl",
            "algorithm": "SM2",
            "name": "openssl-sm2-test",
            "storage": "MANAGED"
        })
        self.assertEqual(gen_res["provider"], "openssl")
        self.assertEqual(gen_res["algorithm"], "SM2")
        priv_key = gen_res["key"]
        pub_key = gen_res["publicKey"]
        self.assertTrue(priv_key.get("hasManagedPassphrase"))
        priv_ref = gen_res["reference"]
        pub_ref = f"key:{pub_key['id']}"

        data_bytes = b"SM2 Passless Sign with OpenSSL Bridge Key"
        file_id = self._upload_file("data2.bin", data_bytes)

        # 2. Sign in GmSSL without providing 'pass' parameter
        sign_init = self._api("POST", f"/projects/{self.project_id}/jobs", {
            "toolId": "sm2sign",
            "parameters": {
                "key": priv_ref,
                "id": "1234567812345678",
                "in": f"file:{file_id}",
                "out": "sig.der"
            }
        })
        sign_job = self._poll_job(sign_init["id"])
        self.assertEqual(sign_job["status"], "SUCCEEDED")
        sig_bytes = self._download_artifact(sign_job["id"], sign_job["artifacts"][0]["id"])
        self.assertTrue(len(sig_bytes) >= 64)

        # 3. Verify signature in GmSSL with public key
        sig_file_id = self._upload_file("sig2.der", sig_bytes)
        verify_init = self._api("POST", f"/projects/{self.project_id}/jobs", {
            "toolId": "sm2verify",
            "parameters": {
                "pubkey": pub_ref,
                "id": "1234567812345678",
                "sig": f"file:{sig_file_id}",
                "in": f"file:{file_id}"
            }
        })
        verify_job = self._poll_job(verify_init["id"])
        self.assertEqual(verify_job["status"], "SUCCEEDED")

if __name__ == "__main__":
    unittest.main()
