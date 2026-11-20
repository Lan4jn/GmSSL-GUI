#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Independent acceptance probes for keygen, catalog defaults, SAN DER and TLCP credentials."""

import json
import hmac
from tests.toolbox.engine_client import EngineClient
from tests.ux.test_certificate_workflows import OPENSSL_BIN
import subprocess
import time
import unittest
import urllib.request
import urllib.error
import uuid

PLATFORM_URL = "http://127.0.0.1:8080/api/v1"
ENGINE_URL = "http://127.0.0.1:8081/internal/v1"

def load_env():
    env = {}
    with open(".env.local") as f:
        for line in f:
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip().strip("\"'\''")
    return env

class TestDeepInspectionProbe(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.env = load_env()
        admin_u = cls.env["GMSSL_BOOTSTRAP_USERNAME"]
        admin_p = cls.env["GMSSL_BOOTSTRAP_PASSWORD"]
        cls.engine_token = cls.env["GMSSL_ENGINE_TOKEN"]

        # Platform login
        login_data = json.dumps({"username": admin_u, "password": admin_p}).encode("utf-8")
        req = urllib.request.Request(f"{PLATFORM_URL}/auth/login", data=login_data, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req) as res:
            cookies = res.headers.get_all("Set-Cookie")
            cls.cookie = [c.split(";")[0] for c in cookies if "GMSSL_SESSION=" in c][0]
            cls.csrf = json.loads(res.read().decode())["csrfToken"]

        # Project create
        preq = urllib.request.Request(
            f"{PLATFORM_URL}/projects",
            data=json.dumps({"name": f"Deep-Probe-{uuid.uuid4().hex[:6]}"}).encode("utf-8"),
            headers={"Content-Type": "application/json", "Cookie": cls.cookie, "X-CSRF-Token": cls.csrf}
        )
        with urllib.request.urlopen(preq) as res:
            cls.project_id = json.loads(res.read().decode())["id"]

    def _api(self, method, path, data=None):
        url = f"{PLATFORM_URL}{path}"
        headers = {"Cookie": self.cookie, "Content-Type": "application/json", "X-CSRF-Token": self.csrf}
        req = urllib.request.Request(url, data=json.dumps(data).encode("utf-8") if data is not None else None, headers=headers, method=method)
        with urllib.request.urlopen(req) as res:
            return json.loads(res.read().decode())

    def _engine_api(self, method, path, data=None):
        url = f"{ENGINE_URL}{path}"
        headers = {"X-Engine-Token": self.engine_token, "Content-Type": "application/json"}
        req = urllib.request.Request(url, data=json.dumps(data).encode("utf-8") if data is not None else None, headers=headers, method=method)
        with urllib.request.urlopen(req) as res:
            return json.loads(res.read().decode())

    def test_probe_01_sm9_advertised_vs_unsupported_gap(self):
        """Probe task-20: SM9 is excluded from general key-generation-capabilities and rejected by key-generations."""
        cap = self._engine_api("GET", "/key-generation-capabilities")
        alg_ids = [a["id"] for a in cap["algorithms"]]
        # Verified fix: SM9 must NOT be advertised in general keygen capabilities
        self.assertNotIn("SM9", alg_ids, "SM9 should be excluded from general key-generation capabilities")

        # Calling key-generations for SM9 returns 400
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self._engine_api("POST", "/key-generations", {
                "requestId": str(uuid.uuid4()),
                "algorithm": "SM9",
                "provider": "gmssl"
            })
        self.assertEqual(ctx.exception.code, 400)
        err = json.loads(ctx.exception.read().decode())
        self.assertIn(err.get("code"), ("INVALID_PARAMETERS", "UNSUPPORTED_ALGORITHM"))

    def test_probe_02_api_aes_catalog_defaults(self):
        client = EngineClient()
        tool = next(t for t in client.get_capabilities()["tools"] if t["id"] == "api_aes")
        defaults = {p["name"]: p["defaultValue"] for p in tool["parameters"]
                    if p.get("defaultValue") is not None}
        self.assertEqual(defaults.get("mode"), "cbc")
        self.assertNotIn("taglen", defaults)
        plain = b"0123456789abcdef0123456789abcdef"
        parameters = dict(defaults, key="0123456789abcdef0123456789abcdef",
                          iv="fedcba9876543210fedcba9876543210",
                          **{"in": "input:in", "out": "cipher.bin"})
        result = client.execute("api_aes", parameters=parameters, inputs={"in": plain}, timeout_seconds=5)
        self.assertEqual(result.get("status"), "SUCCEEDED")
        self.assertEqual(result.get("exitCode"), 0)
        cipher = EngineClient.get_artifact(result, "cipher.bin")
        self.assertEqual(len(cipher), len(plain))
        negative = client.execute("api_aes", parameters=dict(parameters, taglen=16),
                                  inputs={"in": plain}, timeout_seconds=5)
        self.assertEqual(negative.get("http_code"), 400)
        self.assertEqual(negative["error"]["code"], "INVALID_PARAMETERS")

    def test_probe_03_certificate_and_csr_san_der(self):
        for profile, command, name in [("SELF_SIGNED", "x509", "ip-san-probe"), ("CSR", "req", "csr-san-probe")]:
            with self.subTest(profile=profile):
                res = self._api("POST", f"/projects/{self.project_id}/certificate-workflows", {
                    "profile": profile, "name": name, "subject": {"CN": "san.probe.local", "C": "CN"},
                    "sanDns": ["san.probe.local", "alt.probe.local"],
                    "sanIps": ["192.168.1.100", "2001:db8::100"]
                })
                self.assertEqual(res["status"], "SUCCEEDED")
                file_id = res["files"][0]["id"]
                req = urllib.request.Request(f"{PLATFORM_URL}/projects/{self.project_id}/files/{file_id}/download",
                                             headers={"Cookie": self.cookie})
                with urllib.request.urlopen(req, timeout=15) as response:
                    pem = response.read()
                args = [OPENSSL_BIN, command, "-text", "-noout"]
                if command == "req":
                    args += ["-verify", "-vfyopt", "distid:1234567812345678"]
                parsed = subprocess.run(args, input=pem, capture_output=True, timeout=15)
                self.assertEqual(parsed.returncode, 0, parsed.stderr.decode(errors="replace"))
                text = parsed.stdout.decode()
                for value in ["X509v3 Subject Alternative Name", "DNS:san.probe.local", "DNS:alt.probe.local",
                              "IP Address:192.168.1.100", "IP Address:2001:DB8:0:0:0:0:0:100"]:
                    self.assertIn(value, text)

    def test_probe_04_deep_certificate_content_verification(self):
        """Probe task-24: Deep parse of generated X.509 certificate confirms Subject, Issuer, and SAN DNS."""
        res = self._api("POST", f"/projects/{self.project_id}/certificate-workflows", {
            "profile": "SELF_SIGNED",
            "name": "deep-x509-probe",
            "subject": {"CN": "deep.probe.internal", "C": "CN", "O": "AuditOrg", "OU": "QualityLab"},
            "days": 90,
            "sanDns": ["deep.probe.internal", "mirror.probe.internal"],
            "provider": "gmssl"
        })
        self.assertEqual(res["status"], "SUCCEEDED")
        cert_file_id = res["files"][0]["id"]

        dreq = urllib.request.Request(f"{PLATFORM_URL}/projects/{self.project_id}/files/{cert_file_id}/download", headers={"Cookie": self.cookie})
        with urllib.request.urlopen(dreq) as dres:
            cert_pem = dres.read().decode("utf-8")

        proc = subprocess.run([OPENSSL_BIN, "x509", "-text", "-noout"], input=cert_pem, capture_output=True, text=True, timeout=15, check=True)
        out = proc.stdout
        self.assertIn("CN=deep.probe.internal", out)
        self.assertIn("O=AuditOrg", out)
        self.assertIn("OU=QualityLab", out)
        self.assertIn("C=CN", out)
        self.assertIn("Signature Algorithm: SM2-with-SM3", out)
        self.assertIn("DNS:deep.probe.internal", out)
        self.assertIn("DNS:mirror.probe.internal", out)

    def test_probe_05_tlcp_pair_password_and_encrypted_bundle(self):
        """TLCP distinct keypairs share a managed password and export an encrypted bundle."""
        # 1. Create Root CA
        root = self._api("POST", f"/projects/{self.project_id}/certificate-workflows", {
            "profile": "ROOT_CA",
            "name": "TLCPProbeCA",
            "subject": {"CN": "TLCP Probe CA", "C": "CN"}
        })
        root_cert_ref = f"file:{root['files'][0]['id']}"
        root_key_ref = f"key:{root['keys'][0]['id']}"

        # 2. Create TLCP
        tlcp = self._api("POST", f"/projects/{self.project_id}/certificate-workflows", {
            "profile": "TLCP",
            "name": "TLCPProbePair",
            "subject": {"CN": "localhost", "C": "CN"},
            "issuerCertRef": root_cert_ref,
            "issuerKeyRef": root_key_ref
        })
        self.assertEqual(tlcp["status"], "SUCCEEDED")
        self.assertEqual(len(tlcp["keys"]), 2)

        sign_key_id = [k["id"] for k in tlcp["keys"] if "sign" in k["name"]][0]
        enc_key_id = [k["id"] for k in tlcp["keys"] if "enc" in k["name"]][0]

        # Reveal both passphrases via ADMIN
        sign_pass = self._api("POST", f"/projects/{self.project_id}/keys/{sign_key_id}/reveal-passphrase")["passphrase"]
        enc_pass = self._api("POST", f"/projects/{self.project_id}/keys/{enc_key_id}/reveal-passphrase")["passphrase"]

        self.assertTrue(hmac.compare_digest(sign_pass, enc_pass), "TLCP pair must share one password")
        self.assertGreaterEqual(len(sign_pass), 16)
        bundle = next((f for f in tlcp["files"] if f["name"].endswith("_tlcp_keys.pem")), None)
        self.assertIsNotNone(bundle, "TLCP encrypted private-key bundle is required")
        self.assertTrue(bundle.get("hasManagedPassphrase"))
        req = urllib.request.Request(f"{PLATFORM_URL}/projects/{self.project_id}/files/{bundle['id']}/download",
                                     headers={"Cookie": self.cookie})
        with urllib.request.urlopen(req, timeout=15) as response:
            pem = response.read()
        self.assertEqual(pem.count(b"-----BEGIN ENCRYPTED PRIVATE KEY-----"), 2)
        self.assertNotIn(b"-----BEGIN PRIVATE KEY-----", pem)

if __name__ == "__main__":
    unittest.main()
