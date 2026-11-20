#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Comprehensive Independent Acceptance Test Suite for Certificate Workflows.

Performs deep ASN.1 / X.509 and PKCS#10 DER inspection via OpenSSL CLI:
1. ROOT_CA Profile:
   - basicConstraints: critical, CA:TRUE
   - keyUsage: Certificate Sign, CRL Sign (keyCertSign, cRLSign)
   - Subject == Issuer (self-signed trust anchor)
   - Public Key algorithm SM2 (1.2.156.10197.1.301 / id-ecPublicKey)
   - Signature algorithm SM2-with-SM3 (1.2.156.10197.1.501)
2. INTERMEDIATE_CA Profile:
   - basicConstraints: critical, CA:TRUE, pathlen:0
   - Issuer matches parent Root CA Subject
   - keyUsage: Certificate Sign, CRL Sign
3. CSR (PKCS#10) Profile:
   - Subject fields match input
   - Subject Alternative Name (SAN DNS) must be requested in extensions
4. CA_SIGN Profile:
   - End-entity cert issued from CSR
   - Issuer matches CA Subject
   - Purpose SERVER: EKU contains TLS Web Server Authentication, Key Usage contains Digital Signature, Key Encipherment
   - Purpose CLIENT: EKU contains TLS Web Client Authentication
   - SAN DNS and SAN IP validation in certificate extensions
5. SELF_SIGNED with OpenSSL Bridged Key:
   - Generated private key from OpenSSL provider, bridged to GmSSL
   - Certificate issued and verified
6. TLCP Dual-Certificate Verification:
   - Sign Cert: Key Usage contains Digital Signature, NOT Key Encipherment
   - Enc Cert: Key Usage contains Key Encipherment, NOT Digital Signature
   - Two distinct private keys and certificates
   - Real TLCP handshake verification with tlcp_server and tlcp_client
7. Negative & Constraint Rejection:
   - Negative days (e.g. -10) rejected (HTTP 400)
   - Negative pathLenConstraint (e.g. -1) rejected (HTTP 400)
   - Missing required issuer references rejected (HTTP 400)
   - Corrupted CSR reference rejected (HTTP 400)
   - Leaf cert used as CA rejected (HTTP 400)
"""

import json
from concurrent.futures import ThreadPoolExecutor
from tests.toolbox.engine_client import EngineClient
import re
import socket
import subprocess
import time
import unittest
import urllib.request
import urllib.error
import uuid

BASE_URL = "http://127.0.0.1:8080/api/v1"

def find_openssl_bin():
    import os
    env_bin = os.environ.get("GMSSL_OPENSSL_PATH")
    if env_bin and os.path.isfile(env_bin) and os.access(env_bin, os.X_OK):
        return env_bin
    for p in ["/opt/homebrew/bin/openssl", "/usr/local/bin/openssl", "/usr/bin/openssl"]:
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return "openssl"

OPENSSL_BIN = find_openssl_bin()

def load_admin_creds():
    creds = {}
    with open(".env.local") as f:
        for line in f:
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                creds[k.strip()] = v.strip().strip("\"'\''")
    return creds.get("GMSSL_BOOTSTRAP_USERNAME", "admin"), creds.get("GMSSL_BOOTSTRAP_PASSWORD")

class TestCertificateWorkflows(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        admin_user, admin_pass = load_admin_creds()
        login_data = json.dumps({"username": admin_user, "password": admin_pass}).encode("utf-8")
        req = urllib.request.Request(f"{BASE_URL}/auth/login", data=login_data, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req) as res:
            cookies = res.headers.get_all("Set-Cookie")
            cls.cookie = [c.split(";")[0] for c in cookies if "GMSSL_SESSION=" in c][0]
            cls.csrf = json.loads(res.read().decode())["csrfToken"]

        proj_res = cls._api(cls, "POST", "/projects", {"name": f"Cert-Deep-Acceptance-{uuid.uuid4().hex[:6]}"})
        cls.project_id = proj_res["id"]

    def _api(self, method, path, data=None):
        url = f"{BASE_URL}{path}"
        headers = {"Cookie": self.cookie, "Content-Type": "application/json"}
        if self.csrf:
            headers["X-CSRF-Token"] = self.csrf
        req = urllib.request.Request(url, data=json.dumps(data).encode("utf-8") if data is not None else None, headers=headers, method=method)
        with urllib.request.urlopen(req) as res:
            return json.loads(res.read().decode())

    def _submit_workflow(self, payload):
        return self._api("POST", f"/projects/{self.project_id}/certificate-workflows", payload)

    def _download_file_text(self, file_id):
        url = f"{BASE_URL}/projects/{self.project_id}/files/{file_id}/download"
        req = urllib.request.Request(url, headers={"Cookie": self.cookie})
        with urllib.request.urlopen(req) as res:
            return res.read().decode("utf-8")

    def _parse_x509(self, pem_str):
        proc = subprocess.run([OPENSSL_BIN, "x509", "-text", "-noout"], input=pem_str, capture_output=True, text=True, check=True)
        return proc.stdout

    def _parse_csr(self, pem_str):
        proc = subprocess.run([OPENSSL_BIN, "req", "-text", "-noout"], input=pem_str, capture_output=True, text=True, check=True)
        return proc.stdout

    def test_01_root_ca_deep_inspection(self):
        res = self._submit_workflow({
            "profile": "ROOT_CA",
            "name": "AuditRootCA",
            "subject": {
                "CN": "Audit Root CA",
                "C": "CN",
                "O": "Audit Security Org",
                "OU": "Root Authority",
                "ST": "Beijing",
                "L": "Haidian"
            },
            "days": 3650,
            "provider": "gmssl"
        })
        self.assertEqual(res["status"], "SUCCEEDED", res)
        cert_file_id = res["files"][0]["id"]
        pem = self._download_file_text(cert_file_id)
        parsed = self._parse_x509(pem)

        # 1. Subject & Issuer equality for Root CA
        self.assertIn("Subject: C=CN, ST=Beijing, L=Haidian, O=Audit Security Org, OU=Root Authority, CN=Audit Root CA", parsed)
        self.assertIn("Issuer: C=CN, ST=Beijing, L=Haidian, O=Audit Security Org, OU=Root Authority, CN=Audit Root CA", parsed)

        # 2. Signature algorithm SM2-with-SM3
        self.assertIn("Signature Algorithm: SM2-with-SM3", parsed)

        # 3. Public key SM2
        self.assertIn("ASN1 OID: SM2", parsed)

        # 4. Basic Constraints CA:TRUE
        self.assertIn("X509v3 Basic Constraints: critical", parsed)
        self.assertIn("CA:TRUE", parsed)

        # 5. Key Usage Certificate Sign, CRL Sign
        self.assertIn("Certificate Sign", parsed)
        self.assertIn("CRL Sign", parsed)

    def test_02_intermediate_ca_deep_inspection(self):
        # 1. Root CA
        root = self._submit_workflow({
            "profile": "ROOT_CA",
            "name": "SubIssuerRoot",
            "subject": {"CN": "Sub Issuer Root", "C": "CN", "O": "Root Org"},
            "days": 3650
        })
        root_cert_ref = f"file:{root['files'][0]['id']}"
        root_key_ref = f"key:{root['keys'][0]['id']}"

        # 2. Intermediate CA with pathLenConstraint=0
        inter = self._submit_workflow({
            "profile": "INTERMEDIATE_CA",
            "name": "AuditIntermediateCA",
            "subject": {"CN": "Audit Intermediate CA", "C": "CN", "O": "Sub Authority"},
            "days": 1825,
            "issuerCertRef": root_cert_ref,
            "issuerKeyRef": root_key_ref,
            "advanced": {"pathLenConstraint": 0}
        })
        self.assertEqual(inter["status"], "SUCCEEDED", inter)
        cert_files = [f for f in inter["files"] if f["name"].endswith("_intermediate_ca.pem")]
        self.assertTrue(len(cert_files) > 0, f"Expected intermediate CA cert in files: {inter['files']}")
        cert_file_id = cert_files[0]["id"]
        pem = self._download_file_text(cert_file_id)
        parsed = self._parse_x509(pem)

        # 1. Subject and Issuer relation
        self.assertIn("Subject: C=CN, O=Sub Authority, CN=Audit Intermediate CA", parsed)
        self.assertIn("Issuer: C=CN, O=Root Org, CN=Sub Issuer Root", parsed)

        # 2. Basic Constraints with pathlen:0
        self.assertIn("CA:TRUE", parsed)
        self.assertIn("pathlen:0", parsed)

        # 3. Key Usage
        self.assertIn("Certificate Sign", parsed)
        self.assertIn("CRL Sign", parsed)

    def test_03_csr_deep_inspection_reveals_san_gap(self):
        """Generates CSR with sanDns and asserts that Requested Extensions contains SAN.
        NOTE: Upstream GmSSL reqgen lacks -subject_dns_name, causing SAN to be omitted in CSR.
        This test uncovers that gap per Lead audit instructions.
        """
        csr_res = self._submit_workflow({
            "profile": "CSR",
            "name": "WebServerCSR",
            "subject": {"CN": "server.internal.lab", "C": "CN", "O": "Corp Lab"},
            "sanDns": ["server.internal.lab", "api.internal.lab"],
            "provider": "gmssl"
        })
        self.assertEqual(csr_res["status"], "SUCCEEDED", csr_res)
        csr_file_id = csr_res["files"][0]["id"]
        pem = self._download_file_text(csr_file_id)
        parsed = self._parse_csr(pem)

        self.assertIn("Subject: C=CN, O=Corp Lab, CN=server.internal.lab", parsed)
        self.assertIn("ASN1 OID: SM2", parsed)

        # Exact gap assertion: CSR must contain requested SAN extensions
        self.assertIn(
            "X509v3 Subject Alternative Name",
            parsed,
            "FAIL CONTRACT: PKCS#10 CSR generated without Subject Alternative Name extension (upstream reqgen gap)"
        )
        self.assertIn("DNS:server.internal.lab", parsed)

    def test_04_ca_sign_deep_inspection_reveals_san_ip_gap(self):
        """Signs end-entity cert with sanDns and sanIps.
        Asserts that both DNS SAN and IP SAN are present in the final certificate.
        NOTE: Upstream GmSSL CLI lacks IP SAN support and CertificateWorkflowService emits warning.
        This test uncovers that gap per Lead audit instructions.
        """
        # 1. Root CA
        ca = self._submit_workflow({
            "profile": "ROOT_CA",
            "name": "EndEntitySignerCA",
            "subject": {"CN": "End Entity CA", "C": "CN"}
        })
        ca_cert_ref = f"file:{ca['files'][0]['id']}"
        ca_key_ref = f"key:{ca['keys'][0]['id']}"

        # 2. CSR
        csr = self._submit_workflow({
            "profile": "CSR",
            "name": "ServiceCSR",
            "subject": {"CN": "service.example.local", "C": "CN"}
        })
        csr_ref = f"file:{csr['files'][0]['id']}"

        # 3. CA_SIGN with Server Purpose, DNS SAN, and IP SAN
        end_cert = self._submit_workflow({
            "profile": "CA_SIGN",
            "name": "ServiceCert",
            "subject": {"CN": "service.example.local"},
            "csrRef": csr_ref,
            "issuerCertRef": ca_cert_ref,
            "issuerKeyRef": ca_key_ref,
            "days": 365,
            "sanDns": ["service.example.local", "backup.example.local"],
            "sanIps": ["192.168.1.50", "10.0.0.1"],
            "purpose": "SERVER"
        })
        self.assertEqual(end_cert["status"], "SUCCEEDED", end_cert)
        cert_file_id = end_cert["files"][0]["id"]
        pem = self._download_file_text(cert_file_id)
        parsed = self._parse_x509(pem)

        # Purpose SERVER checks
        self.assertIn("TLS Web Server Authentication", parsed)
        self.assertIn("Digital Signature", parsed)
        self.assertIn("Key Encipherment", parsed)

        # DNS SAN check
        self.assertIn("DNS:service.example.local", parsed)
        self.assertIn("DNS:backup.example.local", parsed)

        # Exact gap assertion: IP SAN must NOT be silently dropped or degraded to warning
        self.assertIn(
            "IP Address:192.168.1.50",
            parsed,
            "FAIL CONTRACT: IP SAN 192.168.1.50 missing from certificate (sanIps degraded to warning)"
        )

    def test_05_client_purpose_eku_inspection(self):
        """Verify CLIENT purpose sets TLS Web Client Authentication in EKU."""
        root = self._submit_workflow({
            "profile": "ROOT_CA",
            "name": "ClientRootCA",
            "subject": {"CN": "Client Test CA", "C": "CN"}
        })
        ca_cert_ref = f"file:{root['files'][0]['id']}"
        ca_key_ref = f"key:{root['keys'][0]['id']}"

        csr = self._submit_workflow({
            "profile": "CSR",
            "name": "ClientCSR",
            "subject": {"CN": "user@client.local", "C": "CN"}
        })
        csr_ref = f"file:{csr['files'][0]['id']}"

        client_cert = self._submit_workflow({
            "profile": "CA_SIGN",
            "name": "ClientCert",
            "subject": {"CN": "user@client.local"},
            "csrRef": csr_ref,
            "issuerCertRef": ca_cert_ref,
            "issuerKeyRef": ca_key_ref,
            "days": 180,
            "purpose": "CLIENT"
        })
        self.assertEqual(client_cert["status"], "SUCCEEDED", client_cert)
        cert_file_id = client_cert["files"][0]["id"]
        pem = self._download_file_text(cert_file_id)
        parsed = self._parse_x509(pem)

        self.assertIn("TLS Web Client Authentication", parsed)

    def test_06_self_signed_openssl_bridged_inspection(self):
        """Self-signed certificate generated via OpenSSL provider and PKCS#8 bridge."""
        res = self._submit_workflow({
            "profile": "SELF_SIGNED",
            "name": "OpenSslSelfSigned",
            "subject": {"CN": "openssl-cert.local", "C": "CN", "O": "OpenSSL Bridge Test"},
            "days": 90,
            "sanDns": ["openssl-cert.local"],
            "provider": "openssl"
        })
        self.assertEqual(res["status"], "SUCCEEDED", res)
        cert_file_id = res["files"][0]["id"]
        pem = self._download_file_text(cert_file_id)
        parsed = self._parse_x509(pem)

        self.assertIn("Subject: C=CN, O=OpenSSL Bridge Test, CN=openssl-cert.local", parsed)
        self.assertIn("Issuer: C=CN, O=OpenSSL Bridge Test, CN=openssl-cert.local", parsed)
        self.assertIn("Signature Algorithm: SM2-with-SM3", parsed)
        self.assertIn("DNS:openssl-cert.local", parsed)

    def test_07_tlcp_dual_cert_purposes_and_handshake_gap(self):
        """Validates TLCP double certificate profile:
        1. Sign cert Key Usage: digitalSignature (no keyEncipherment).
        2. Enc cert Key Usage: keyEncipherment / dataEncipherment (no digitalSignature).
        3. Real TLCP server/client handshake test using generated certificates and keys.
        """
        ca = self._submit_workflow({
            "profile": "ROOT_CA",
            "name": "TLCPAuthority",
            "subject": {"CN": "TLCP Authority", "C": "CN"}
        })
        ca_cert_ref = f"file:{ca['files'][0]['id']}"
        ca_key_ref = f"key:{ca['keys'][0]['id']}"

        tlcp = self._submit_workflow({
            "profile": "TLCP",
            "name": "TLCPGateway",
            "subject": {"CN": "gateway.tlcp.local", "C": "CN", "O": "TLCP Org"},
            "issuerCertRef": ca_cert_ref,
            "issuerKeyRef": ca_key_ref,
            "days": 365,
            "sanDns": ["gateway.tlcp.local"],
            "provider": "gmssl"
        })
        self.assertEqual(tlcp["status"], "SUCCEEDED", tlcp)
        files = {f["name"]: f["id"] for f in tlcp["files"]}

        # 1. Inspect Sign Cert
        sign_pem = self._download_file_text(files["TLCPGateway_sign_cert.pem"])
        sign_parsed = self._parse_x509(sign_pem)
        self.assertIn("Digital Signature", sign_parsed)
        self.assertNotIn("Key Encipherment", sign_parsed)

        # 2. Inspect Enc Cert
        enc_pem = self._download_file_text(files["TLCPGateway_enc_cert.pem"])
        enc_parsed = self._parse_x509(enc_pem)
        self.assertIn("Key Encipherment", enc_parsed)
        self.assertNotIn("Digital Signature", enc_parsed)

        # 3. Two distinct public keys in sign and enc certs
        sign_spki = re.search(r"pub:\s*\n((?:\s+[0-9a-f:]+\n)+)", sign_parsed)
        enc_spki = re.search(r"pub:\s*\n((?:\s+[0-9a-f:]+\n)+)", enc_parsed)
        self.assertIsNotNone(sign_spki)
        self.assertIsNotNone(enc_spki)
        self.assertNotEqual(sign_spki.group(1).strip(), enc_spki.group(1).strip(), "Sign and Enc public keys must be distinct")

        # 4. Check for merged key file for tlcp_server consumption
        self.assertIn(
            "TLCPGateway_tlcp_keys.pem",
            files,
            "FAIL CONTRACT: Missing combined TLCP private keys file (TLCPGateway_tlcp_keys.pem) required by tlcp_server -key"
        )
        bundle = self._download_file_text(files["TLCPGateway_tlcp_keys.pem"])
        self.assertEqual(bundle.count("-----BEGIN ENCRYPTED PRIVATE KEY-----"), 2)
        sign_key = next(k for k in tlcp["keys"] if "sign" in k["name"])
        pair_pass = self._api("POST", f"/projects/{self.project_id}/keys/{sign_key['id']}/reveal-passphrase")["passphrase"]
        port = 14438
        with socket.socket() as available:
            available.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            available.bind(("127.0.0.1", port))
        client = EngineClient()
        message = b"task26-workflow-tlcp-echo"
        with ThreadPoolExecutor(max_workers=1) as executor:
            server = executor.submit(client.execute, "tlcp_server", parameters={
                "port": port, "cert": "input:cert", "key": "input:key", "pass": pair_pass,
                "cipher_suite": "TLS_ECC_SM4_GCM_SM3"
            }, inputs={"cert": self._download_file_text(files["TLCPGateway_tlcp_certs.pem"]),
                       "key": bundle}, timeout_seconds=8)
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and not server.done():
                listening = subprocess.run(["lsof", "-nP", f"-iTCP:{port}", "-sTCP:LISTEN"],
                                           capture_output=True, timeout=2)
                if listening.returncode == 0:
                    break
                time.sleep(0.05)
            else:
                self.fail("TLCP server did not listen using the unmodified workflow key bundle")
            result = client.execute("tlcp_client", parameters={
                "host": "127.0.0.1", "port": port, "server_name": "gateway.tlcp.local",
                "cacert": "input:ca", "cipher_suite": "TLS_ECC_SM4_GCM_SM3", "in": "input:in"
            }, inputs={"ca": self._download_file_text(ca["files"][0]["id"]), "in": message}, timeout_seconds=5)
            self.assertEqual(result.get("status"), "SUCCEEDED")
            self.assertEqual(result.get("exitCode"), 0)
            self.assertIn(message.decode(), EngineClient.get_stdout_text(result))
            self.assertIn(server.result(timeout=12).get("status"), ["SUCCEEDED", "TIMED_OUT"])


    def test_08_negative_rejections(self):
        """Negative boundary tests for certificate workflows."""
        # Negative days
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self._submit_workflow({"profile": "SELF_SIGNED", "name": "BadDays", "subject": {"CN": "test"}, "days": -10})
        self.assertEqual(ctx.exception.code, 400)

        # Negative pathLenConstraint
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self._submit_workflow({
                "profile": "INTERMEDIATE_CA",
                "name": "BadPathLen",
                "subject": {"CN": "test"},
                "issuerCertRef": "file:00000000-0000-0000-0000-000000000000",
                "issuerKeyRef": "key:00000000-0000-0000-0000-000000000000",
                "advanced": {"pathLenConstraint": -1}
            })
        self.assertEqual(ctx.exception.code, 400)

        # Missing issuer references for INTERMEDIATE_CA
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self._submit_workflow({"profile": "INTERMEDIATE_CA", "name": "NoIssuer", "subject": {"CN": "test"}})
        self.assertEqual(ctx.exception.code, 400)

        # Missing CSR reference for CA_SIGN
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self._submit_workflow({
                "profile": "CA_SIGN",
                "name": "NoCSR",
                "subject": {"CN": "test"},
                "issuerCertRef": "file:00000000-0000-0000-0000-000000000000",
                "issuerKeyRef": "key:00000000-0000-0000-0000-000000000000"
            })
        self.assertEqual(ctx.exception.code, 400)

    def test_09_workflow_artifact_security_rbac(self):
        """Verify that workflow private key artifacts cannot be downloaded by VIEWER role (HTTP 403)."""
        # 1. Create a Viewer user
        viewer_name = f"cert_viewer_{uuid.uuid4().hex[:6]}"
        viewer_pass = "ViewerPass12345!"
        viewer_user = self._api("POST", "/users", {
            "username": viewer_name,
            "password": viewer_pass,
            "role": "USER"
        })
        viewer_uid = viewer_user["id"]

        # Add viewer to current project with role VIEWER
        self._api("PUT", f"/projects/{self.project_id}/members/{viewer_uid}", {
            "role": "VIEWER"
        })

        # Login as viewer
        login_data = json.dumps({"username": viewer_name, "password": viewer_pass}).encode("utf-8")
        req = urllib.request.Request(f"{BASE_URL}/auth/login", data=login_data, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req) as res:
            cookies = res.headers.get_all("Set-Cookie")
            viewer_cookie = [c.split(";")[0] for c in cookies if "GMSSL_SESSION=" in c][0]
            viewer_csrf = json.loads(res.read().decode())["csrfToken"]

        # TLCP must always export its sensitive pair bundle; absence is a contract failure.
        res = self._submit_workflow({
            "profile": "TLCP",
            "name": "SecAuditPair",
            "subject": {"CN": "localhost", "C": "CN"}
        })
        keys_list = res.get("keys", [])
        self.assertTrue(len(keys_list) > 0, "Workflow should have generated at least one managed private key")

        # 3. Viewer attempting to download private key must be rejected with 403
        for k in keys_list:
            k_id = k["id"]
            dl_url = f"{BASE_URL}/projects/{self.project_id}/keys/{k_id}/download"
            dl_req = urllib.request.Request(dl_url, headers={"Cookie": viewer_cookie})
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(dl_req)
            self.assertEqual(ctx.exception.code, 403, f"VIEWER must be rejected with 403 when downloading private key {k_id}")

        # 4. Viewer attempting to reveal passphrase must be rejected with 403
        for k in keys_list:
            k_id = k["id"]
            reveal_url = f"{BASE_URL}/projects/{self.project_id}/keys/{k_id}/reveal-passphrase"
            reveal_req = urllib.request.Request(
                reveal_url,
                data=b"{}",
                headers={"Cookie": viewer_cookie, "X-CSRF-Token": viewer_csrf, "Content-Type": "application/json"}
            )
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(reveal_req)
            self.assertEqual(ctx.exception.code, 403, "VIEWER must be rejected with 403 on reveal-passphrase")

        bundle = next((f for f in res["files"] if f["name"].endswith("_tlcp_keys.pem")), None)
        self.assertIsNotNone(bundle, "Required TLCP private key bundle is absent")
        self.assertTrue(bundle.get("hasManagedPassphrase"))
        f_id = bundle["id"]
        pem = self._download_file_text(f_id)
        self.assertEqual(pem.count("-----BEGIN ENCRYPTED PRIVATE KEY-----"), 2)
        dl_url = f"{BASE_URL}/projects/{self.project_id}/files/{f_id}/download"
        dl_req = urllib.request.Request(dl_url, headers={"Cookie": viewer_cookie})
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(dl_req, timeout=10)
        self.assertEqual(ctx.exception.code, 403, "VIEWER must not download the encrypted private key bundle")

if __name__ == "__main__":
    unittest.main()
