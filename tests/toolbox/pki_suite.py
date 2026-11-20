#!/usr/bin/env python3
"""PKI and Digital Envelope Verification Test Suite (task-12).

Verifies all 16 certificate management tools and 5 digital envelope tools
via internal HTTP calls to engine-service on port 8081.

Covered tools (21 total):
- Certificate tools (16):
  1. certgen
  2. certparse
  3. certverify
  4. certrevoke
  5. reqgen
  6. reqparse
  7. reqsign
  8. crlgen
  9. crlparse
  10. crlverify
  11. crlget
  12. ocspreq
  13. ocspget
  14. ocspsign
  15. ocspverify
  16. sctverify

- Digital envelope tools (5):
  17. cmsparse
  18. cmsencrypt
  19. cmsdecrypt
  20. cmssign
  21. cmsverify
"""

import base64
import hashlib
import http.server
import json
import os
from pathlib import Path
import struct
import sys
import threading
import time
import unittest
from datetime import datetime, timezone, timedelta

# Ensure project root is in sys.path
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tests.toolbox.engine_client import EngineClient

RESULTS_DIR = ROOT / "tests" / "toolbox" / "pki-results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)
ALT_RESULTS_DIR = ROOT / "pki-results"
ALT_RESULTS_DIR.mkdir(parents=True, exist_ok=True)


def _parse_tlv(data, offset=0):
    start = offset
    tag = data[offset]
    offset += 1
    length = data[offset]
    offset += 1
    if length & 0x80:
        nbytes = length & 0x7F
        length = int.from_bytes(data[offset : offset + nbytes], "big")
        offset += nbytes
    val = data[offset : offset + length]
    end = offset + length
    return tag, val, start, end


def _encode_tlv(tag, val):
    length = len(val)
    if length < 128:
        len_bytes = bytes([length])
    else:
        lb = length.to_bytes((length.bit_length() + 7) // 8, "big")
        len_bytes = bytes([0x80 | len(lb)]) + lb
    return bytes([tag]) + len_bytes + val


class MockPkiHttpServer:
    """Threaded HTTP/1.1 server on 127.0.0.1:14438 for crlget and ocspget callbacks."""

    def __init__(self, port=14438):
        self.port = port
        self.crl_data = b""
        self.ocsp_resp_data = b""
        self.server = None
        self.thread = None

    def start(self):
        handler_cls = self._make_handler()
        self.server = http.server.HTTPServer(("127.0.0.1", self.port), handler_cls)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        time.sleep(0.2)

    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.server = None

    def _make_handler(outer):
        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self):
                if self.path.startswith("/ca.crl"):
                    self.send_response(200)
                    self.send_header("Content-Type", "application/pkix-crl")
                    self.send_header("Content-Length", str(len(outer.crl_data)))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(outer.crl_data)
                else:
                    self.send_response(404)
                    self.send_header("Content-Length", "0")
                    self.send_header("Connection", "close")
                    self.end_headers()

            def do_POST(self):
                if self.path.startswith("/ocsp"):
                    length = int(self.headers.get("Content-Length", 0))
                    _req_bytes = self.rfile.read(length) if length > 0 else b""
                    self.send_response(200)
                    self.send_header("Content-Type", "application/ocsp-response")
                    self.send_header("Content-Length", str(len(outer.ocsp_resp_data)))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(outer.ocsp_resp_data)
                else:
                    self.send_response(404)
                    self.send_header("Content-Length", "0")
                    self.send_header("Connection", "close")
                    self.end_headers()

            def log_message(self, format, *args):
                pass  # Suppress request logging

        return Handler


class TestPKISuite(unittest.TestCase):
    client = None
    mock_server = None
    records = []

    # Shared test materials
    ca_key = None
    ca_cert = None
    user_key = None
    user_cert = None
    crl_der = None
    ocsp_req_der = None
    ocsp_resp_der = None

    @classmethod
    def setUpClass(cls):
        cls.client = EngineClient()
        cls.mock_server = MockPkiHttpServer(port=14438)
        cls.mock_server.start()
        cls.records = []

    @classmethod
    def tearDownClass(cls):
        if cls.mock_server:
            cls.mock_server.stop()
        cls._dump_results()

    @classmethod
    def _record(cls, test_id, tool, status, exit_code, description, extra=None):
        entry = {
            "test_id": test_id,
            "tool": tool,
            "status": status,
            "exit_code": exit_code,
            "description": description,
            "extra": extra or {},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        cls.records.append(entry)

    @classmethod
    def _dump_results(cls):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        def _sha(rel_path):
            p = ROOT / rel_path
            return hashlib.sha256(p.read_bytes()).hexdigest() if p.exists() else None

        build_metadata = {
            "runner_binary_sha256": _sha("native/.build/bin/gmssl-runner"),
            "manifest_sha256": _sha("native/.build/generated/overlays-manifest.json"),
            "catalog_sha256": _sha("native/catalog.json"),
        }

        summary = {
            "suite": "pki_suite",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_records": len(cls.records),
            "tools_covered": sorted(list({r["tool"] for r in cls.records})),
            "build_metadata": build_metadata,
            "runtime_artifacts": build_metadata,
            "results": cls.records,
        }
        for d in [RESULTS_DIR, ALT_RESULTS_DIR]:
            fpath = d / f"pki_run_{timestamp}.json"
            fpath.write_text(json.dumps(summary, indent=2, ensure_ascii=False))
            latest = d / "latest.json"
            latest.write_text(json.dumps(summary, indent=2, ensure_ascii=False))

    def test_01_root_ca_and_certparse(self):
        """Verify certgen (self-signed Root CA) and certparse."""
        # 1. Generate Root CA Key
        k_res = self.client.execute("sm2keygen", {"pass": "123456", "out": "ca.pem"})
        self.assertEqual(k_res.get("status"), "SUCCEEDED")
        TestPKISuite.ca_key = self.client.get_artifact(k_res, "ca.pem")
        self.assertIsNotNone(TestPKISuite.ca_key)

        # 2. certgen self-signed Root CA
        c_res = self.client.execute(
            "certgen",
            {
                "C": "CN",
                "CN": "RootCA",
                "days": 365,
                "key": "input:key",
                "pass": "123456",
                "ca": True,
                "key_usage": ["keyCertSign", "cRLSign"],
                "out": "ca_cert.pem",
            },
            inputs={"key": TestPKISuite.ca_key},
        )
        self.assertEqual(c_res.get("status"), "SUCCEEDED")
        self.assertEqual(c_res.get("exitCode"), 0)
        TestPKISuite.ca_cert = self.client.get_artifact(c_res, "ca_cert.pem")
        self.assertIsNotNone(TestPKISuite.ca_cert)
        self._record("PKI-01", "certgen", "PASS", 0, "Self-signed Root CA certificate generation")

        # 3. certparse Root CA
        parse_res = self.client.execute("certparse", {"in": "input:cert"}, inputs={"cert": TestPKISuite.ca_cert})
        self.assertEqual(parse_res.get("status"), "SUCCEEDED")
        self.assertEqual(parse_res.get("exitCode"), 0)
        self.assertTrue(len(parse_res.get("stdoutBase64", "")) > 0 or len(parse_res.get("stderr", "")) > 0)
        self._record("PKI-02", "certparse", "PASS", 0, "Parse Root CA certificate ASN.1 structure")

    def test_02_csr_lifecycle_reqgen_reqparse_reqsign(self):
        """Verify reqgen, reqparse, and reqsign for PKCS#10 CSR."""
        # 1. Generate User Key
        u_k = self.client.execute("sm2keygen", {"pass": "654321", "out": "ukey.pem"})
        self.assertEqual(u_k.get("status"), "SUCCEEDED")
        TestPKISuite.user_key = self.client.get_artifact(u_k, "ukey.pem")
        self.assertIsNotNone(TestPKISuite.user_key)

        # 2. reqgen PKCS#10 CSR
        req_res = self.client.execute(
            "reqgen",
            {"C": "CN", "CN": "AliceUser", "key": "input:key", "pass": "654321", "out": "req.pem"},
            inputs={"key": TestPKISuite.user_key},
        )
        self.assertEqual(req_res.get("status"), "SUCCEEDED")
        self.assertEqual(req_res.get("exitCode"), 0)
        req_pem = self.client.get_artifact(req_res, "req.pem")
        self.assertIsNotNone(req_pem)
        self._record("PKI-03", "reqgen", "PASS", 0, "Generate PKCS#10 Certificate Signing Request")

        # 3. reqparse
        parse_res = self.client.execute("reqparse", {"in": "input:req"}, inputs={"req": req_pem})
        self.assertEqual(parse_res.get("status"), "SUCCEEDED")
        self.assertEqual(parse_res.get("exitCode"), 0)
        self._record("PKI-04", "reqparse", "PASS", 0, "Parse PKCS#10 CSR")

        # 4. reqsign CA signs CSR
        sign_res = self.client.execute(
            "reqsign",
            {
                "in": "input:req",
                "cacert": "input:cacert",
                "key": "input:cakey",
                "pass": "123456",
                "days": 30,
                "key_usage": ["digitalSignature"],
                "out": "alice_cert.pem",
            },
            inputs={"req": req_pem, "cacert": TestPKISuite.ca_cert, "cakey": TestPKISuite.ca_key},
        )
        self.assertEqual(sign_res.get("status"), "SUCCEEDED")
        self.assertEqual(sign_res.get("exitCode"), 0)
        TestPKISuite.user_cert = self.client.get_artifact(sign_res, "alice_cert.pem")
        self.assertIsNotNone(TestPKISuite.user_cert)
        self._record("PKI-05", "reqsign", "PASS", 0, "CA signs CSR to issue end-entity certificate")

    def test_03_certverify_positive_and_negative(self):
        """Verify certverify with valid client certificate and untrusted certificate."""
        # 1. Positive verification
        v_res = self.client.execute(
            "certverify",
            {"in": "input:cert", "cacert": "input:cacert", "client": True},
            inputs={"cert": TestPKISuite.user_cert, "cacert": TestPKISuite.ca_cert},
        )
        self.assertEqual(v_res.get("status"), "SUCCEEDED")
        self.assertEqual(v_res.get("exitCode"), 0)
        self._record("PKI-06", "certverify", "PASS", 0, "Verify valid client certificate chain")

        # 2. Negative verification: untrusted independent CA
        fake_k = self.client.execute("sm2keygen", {"pass": "888888", "out": "fake_ca.pem"})
        fake_key = self.client.get_artifact(fake_k, "fake_ca.pem")
        fake_c = self.client.execute(
            "certgen",
            {"C": "CN", "CN": "FakeCA", "days": 30, "key": "input:key", "pass": "888888", "ca": True, "out": "fake_ca.pem"},
            inputs={"key": fake_key},
        )
        fake_cert = self.client.get_artifact(fake_c, "fake_ca.pem")

        v_fail = self.client.execute(
            "certverify",
            {"in": "input:cert", "cacert": "input:cacert", "client": True},
            inputs={"cert": TestPKISuite.user_cert, "cacert": fake_cert},
        )
        self.assertEqual(v_fail.get("status"), "FAILED")
        self.assertNotEqual(v_fail.get("exitCode"), 0)
        self._record("PKI-07", "certverify", "PASS", v_fail.get("exitCode"), "Reject certificate from untrusted CA")

    def test_04_revocation_and_crl_lifecycle(self):
        """Verify certrevoke, crlgen, crlparse, and crlverify closed-loop."""
        # 1. certrevoke
        rev_res = self.client.execute(
            "certrevoke",
            {"in": "input:cert", "reason": "keyCompromise", "out": "rev.der"},
            inputs={"cert": TestPKISuite.user_cert},
        )
        self.assertEqual(rev_res.get("status"), "SUCCEEDED")
        self.assertEqual(rev_res.get("exitCode"), 0)
        rev_der = self.client.get_artifact(rev_res, "rev.der")
        self.assertIsNotNone(rev_der)
        self._record("PKI-08", "certrevoke", "PASS", 0, "Revoke certificate generating RevokedCertificate item")

        # 2. crlgen with explicit next_update (closes crlgen -> crlverify loop via catalog option)
        next_update_str = (datetime.now(timezone.utc) + timedelta(days=30)).strftime("%Y%m%d%H%M%SZ")
        crl_res = self.client.execute(
            "crlgen",
            {
                "in": "input:rev",
                "cacert": "input:cacert",
                "key": "input:cakey",
                "pass": "123456",
                "next_update": next_update_str,
                "out": "crl.der",
            },
            inputs={"rev": rev_der, "cacert": TestPKISuite.ca_cert, "cakey": TestPKISuite.ca_key},
        )
        self.assertEqual(crl_res.get("status"), "SUCCEEDED")
        self.assertEqual(crl_res.get("exitCode"), 0)
        TestPKISuite.crl_der = self.client.get_artifact(crl_res, "crl.der")
        self.assertIsNotNone(TestPKISuite.crl_der)
        self.mock_server.crl_data = TestPKISuite.crl_der
        self._record("PKI-09", "crlgen", "PASS", 0, "Generate signed X.509 CRL with next_update")

        # 3. crlparse
        parse_res = self.client.execute("crlparse", {"in": "input:crl"}, inputs={"crl": TestPKISuite.crl_der})
        self.assertEqual(parse_res.get("status"), "SUCCEEDED")
        self.assertEqual(parse_res.get("exitCode"), 0)
        self._record("PKI-10", "crlparse", "PASS", 0, "Parse X.509 CRL")

        # 4. crlverify directly on crlgen generated output (closed-loop verification)
        vrf_res = self.client.execute(
            "crlverify",
            {"in": "input:crl", "cacert": "input:cacert"},
            inputs={"crl": TestPKISuite.crl_der, "cacert": TestPKISuite.ca_cert},
        )
        self.assertEqual(vrf_res.get("status"), "SUCCEEDED")
        self.assertEqual(vrf_res.get("exitCode"), 0)
        self._record("PKI-11", "crlverify", "PASS", 0, "Verify CRL signature directly from crlgen tool output")

    def test_05_crlget_http_distribution(self):
        """Verify crlget fetching CRL from allowlisted HTTP distribution point."""
        # 1. Generate a certificate carrying CRL distribution points extension pointing to 14438
        k_res = self.client.execute("sm2keygen", {"pass": "654321", "out": "crl_user.pem"})
        u_priv = self.client.get_artifact(k_res, "crl_user.pem")

        c_res = self.client.execute(
            "certgen",
            {
                "C": "CN",
                "CN": "CrlDistributionUser",
                "days": 30,
                "key": "input:key",
                "pass": "654321",
                "crl_http_uri": "http://127.0.0.1:14438/ca.crl",
                "out": "cert_with_crl.pem",
            },
            inputs={"key": u_priv},
        )
        self.assertEqual(c_res.get("status"), "SUCCEEDED")
        cert_with_crl = self.client.get_artifact(c_res, "cert_with_crl.pem")

        # 2. Execute crlget
        get_res = self.client.execute(
            "crlget",
            {"cert": "input:cert", "out": "downloaded.crl"},
            inputs={"cert": cert_with_crl},
        )
        self.assertEqual(get_res.get("status"), "SUCCEEDED")
        self.assertEqual(get_res.get("exitCode"), 0)
        downloaded_crl = self.client.get_artifact(get_res, "downloaded.crl")
        self.assertEqual(downloaded_crl, TestPKISuite.crl_der)
        self._record("PKI-12", "crlget", "PASS", 0, "Fetch and validate CRL from HTTP distribution point")

    def test_06_ocsp_lifecycle_req_sign_verify(self):
        """Verify ocspreq, ocspsign, and ocspverify."""
        # 1. Prepare leaf certificate signed by CA (so issuer matches CA subject)
        chain_pem = TestPKISuite.user_cert.strip() + b"\n" + TestPKISuite.ca_cert.strip() + b"\n"

        # 2. ocspreq
        req_res = self.client.execute("ocspreq", {"in": "input:chain", "out": "req.der"}, inputs={"chain": chain_pem})
        self.assertEqual(req_res.get("status"), "SUCCEEDED")
        self.assertEqual(req_res.get("exitCode"), 0)
        TestPKISuite.ocsp_req_der = self.client.get_artifact(req_res, "req.der")
        self.assertIsNotNone(TestPKISuite.ocsp_req_der)
        self._record("PKI-13", "ocspreq", "PASS", 0, "Generate OCSP request from certificate chain")

        # 3. ocspsign
        sign_res = self.client.execute(
            "ocspsign",
            {
                "reqin": "input:req",
                "cacert": "input:cacert",
                "signer": "input:signer",
                "key": "input:cakey",
                "pass": "123456",
                "status": "good",
                "out": "resp.der",
            },
            inputs={
                "req": TestPKISuite.ocsp_req_der,
                "cacert": TestPKISuite.ca_cert,
                "signer": TestPKISuite.ca_cert,
                "cakey": TestPKISuite.ca_key,
            },
        )
        self.assertEqual(sign_res.get("status"), "SUCCEEDED")
        self.assertEqual(sign_res.get("exitCode"), 0)
        TestPKISuite.ocsp_resp_der = self.client.get_artifact(sign_res, "resp.der")
        self.assertIsNotNone(TestPKISuite.ocsp_resp_der)
        self.mock_server.ocsp_resp_data = TestPKISuite.ocsp_resp_der
        self._record("PKI-14", "ocspsign", "PASS", 0, "CA signs OCSP response with good status")

        # 4. ocspverify
        vrf_res = self.client.execute(
            "ocspverify",
            {"reqin": "input:req", "respin": "input:resp", "cacert": "input:cacert", "signer": "input:signer"},
            inputs={
                "req": TestPKISuite.ocsp_req_der,
                "resp": TestPKISuite.ocsp_resp_der,
                "cacert": TestPKISuite.ca_cert,
                "signer": TestPKISuite.ca_cert,
            },
        )
        self.assertEqual(vrf_res.get("status"), "SUCCEEDED")
        self.assertEqual(vrf_res.get("exitCode"), 0)
        self._record("PKI-15", "ocspverify", "PASS", 0, "Verify signed OCSP response against request")

    def test_07_ocspget_http_responder(self):
        """Verify ocspget querying HTTP OCSP responder."""
        chain_pem = TestPKISuite.user_cert.strip() + b"\n" + TestPKISuite.ca_cert.strip() + b"\n"
        get_res = self.client.execute(
            "ocspget",
            {"cert": "input:chain", "url": "http://127.0.0.1:14438/ocsp", "out": "got_resp.der"},
            inputs={"chain": chain_pem},
        )
        self.assertEqual(get_res.get("status"), "SUCCEEDED")
        self.assertEqual(get_res.get("exitCode"), 0)
        got_resp = self.client.get_artifact(get_res, "got_resp.der")
        self.assertEqual(got_resp, TestPKISuite.ocsp_resp_der)
        self._record("PKI-16", "ocspget", "PASS", 0, "Query OCSP responder via HTTP POST on allowlisted port")

    def test_08_sctverify_rfc6962(self):
        """Verify sctverify using RFC 6962 SCT list fixture with standard layout and negative checks."""
        # 1. CT Log key
        log_key_res = self.client.execute("sm2keygen", {"pass": "123456", "out": "logkey.pem", "pubout": "logpub.pem"})
        self.assertEqual(log_key_res.get("status"), "SUCCEEDED")
        log_priv = self.client.get_artifact(log_key_res, "logkey.pem")
        log_pub = self.client.get_artifact(log_key_res, "logpub.pem")

        # 2. Extract public key DER SPKI and compute standard LogID = SHA256(DER SubjectPublicKeyInfo)
        lines = [l for l in log_pub.decode().splitlines() if not l.startswith("-----")]
        spki_der = base64.b64decode("".join(lines))
        log_id = hashlib.sha256(spki_der).digest()

        # 3. Extract user_cert DER bytes
        cert_lines = [l for l in TestPKISuite.user_cert.decode().splitlines() if not l.startswith("-----")]
        cert_der = base64.b64decode("".join(cert_lines))
        entry_len = len(cert_der)

        # 4. Standard RFC 6962 signed_data layout:
        # Version(1B:0) + SigType(1B:0) + Timestamp(8B uint64) + EntryType(2B:0) + uint24(entry_len) + cert_der + extslen(2B:0)
        timestamp = 1000
        signed_data = (
            struct.pack(">BBQH3s", 0, 0, timestamp, 0, struct.pack(">I", entry_len)[1:])
            + cert_der
            + b"\x00\x00"
        )

        # 5. Sign with SM2 (TLS_sig_sm2sig_sm3 = 0x0708 extension)
        sign_res = self.client.execute(
            "sm2sign",
            {"key": "input:key", "pass": "123456", "in": "input:data", "out": "sig.der"},
            inputs={"key": log_priv, "data": signed_data},
        )
        self.assertEqual(sign_res.get("status"), "SUCCEEDED")
        sig_der = self.client.get_artifact(sign_res, "sig.der")

        # 6. Build standard SCT and SCT list
        # SCT struct: version(1B:0) + log_id(32B) + timestamp(8B) + extslen(2B:0) + sig_alg(2B:0x0708) + siglen(2B) + sig_der
        sct = struct.pack(">B32sQHHH", 0, log_id, timestamp, 0, 0x0708, len(sig_der)) + sig_der
        inner = struct.pack(">H", len(sct)) + sct
        sct_list = struct.pack(">H", len(inner)) + inner

        # 7. Positive verification: sctverify with valid SCT list matching certificate
        vrf_res = self.client.execute(
            "sctverify",
            {"in": "input:sctlist", "cert": "input:cert", "log_key": "input:logkey"},
            inputs={"sctlist": sct_list, "cert": TestPKISuite.user_cert, "logkey": log_pub},
        )
        self.assertEqual(vrf_res.get("status"), "SUCCEEDED")
        self.assertEqual(vrf_res.get("exitCode"), 0)
        self._record("PKI-17", "sctverify", "PASS", 0, "Verify Signed Certificate Timestamp list against leaf certificate")

        # 8. Negative verification A: Tampered timestamp (timestamp altered while signature stays unchanged)
        tampered_timestamp = timestamp + 100
        bad_time_sct = struct.pack(">B32sQHHH", 0, log_id, tampered_timestamp, 0, 0x0708, len(sig_der)) + sig_der
        bad_time_inner = struct.pack(">H", len(bad_time_sct)) + bad_time_sct
        bad_time_sct_list = struct.pack(">H", len(bad_time_inner)) + bad_time_inner

        bad_time_res = self.client.execute(
            "sctverify",
            {"in": "input:sctlist", "cert": "input:cert", "log_key": "input:logkey"},
            inputs={"sctlist": bad_time_sct_list, "cert": TestPKISuite.user_cert, "logkey": log_pub},
        )
        self.assertEqual(bad_time_res.get("status"), "FAILED")
        self.assertNotEqual(bad_time_res.get("exitCode"), 0)
        self._record("PKI-18", "sctverify", "PASS", bad_time_res.get("exitCode"), "Reject SCT list with tampered timestamp")

        # 9. Negative verification B: Tampered Log ID (Log ID does not match log_key)
        bad_log_id = bytes([b ^ 0xFF for b in log_id])
        bad_id_sct = struct.pack(">B32sQHHH", 0, bad_log_id, timestamp, 0, 0x0708, len(sig_der)) + sig_der
        bad_id_inner = struct.pack(">H", len(bad_id_sct)) + bad_id_sct
        bad_id_sct_list = struct.pack(">H", len(bad_id_inner)) + bad_id_inner

        bad_id_res = self.client.execute(
            "sctverify",
            {"in": "input:sctlist", "cert": "input:cert", "log_key": "input:logkey"},
            inputs={"sctlist": bad_id_sct_list, "cert": TestPKISuite.user_cert, "logkey": log_pub},
        )
        self.assertEqual(bad_id_res.get("status"), "FAILED")
        self.assertNotEqual(bad_id_res.get("exitCode"), 0)
        self._record("PKI-19", "sctverify", "PASS", bad_id_res.get("exitCode"), "Reject SCT list with mismatched Log ID")

    def test_09_cms_signed_data_sign_parse_verify(self):
        """Verify cmssign, cmsparse, and cmsverify for PKCS#7 SignedData."""
        msg = b"GmSSL PKI Digital Envelope and Signature Verification Payload 2026"

        # 1. cmssign
        sign_res = self.client.execute(
            "cmssign",
            {"key": "input:key", "pass": "654321", "cert": "input:cert", "in": "input:data", "out": "signed.cms"},
            inputs={"key": TestPKISuite.user_key, "cert": TestPKISuite.user_cert, "data": msg},
        )
        self.assertEqual(sign_res.get("status"), "SUCCEEDED")
        self.assertEqual(sign_res.get("exitCode"), 0)
        cms_signed = self.client.get_artifact(sign_res, "signed.cms")
        self.assertIsNotNone(cms_signed)
        self._record("PKI-20", "cmssign", "PASS", 0, "Generate CMS SignedData with SM2/SM3 signer")

        # 2. cmsparse on SignedData
        parse_res = self.client.execute("cmsparse", {"in": "input:cms"}, inputs={"cms": cms_signed})
        self.assertEqual(parse_res.get("status"), "SUCCEEDED")
        self.assertEqual(parse_res.get("exitCode"), 0)
        self._record("PKI-21", "cmsparse", "PASS", 0, "Parse CMS SignedData ASN.1 structure")

        # 3. cmsverify
        vrf_res = self.client.execute(
            "cmsverify",
            {"in": "input:cms", "out": "extracted.txt"},
            inputs={"cms": cms_signed},
        )
        self.assertEqual(vrf_res.get("status"), "SUCCEEDED")
        self.assertEqual(vrf_res.get("exitCode"), 0)
        extracted = self.client.get_artifact(vrf_res, "extracted.txt")
        self.assertEqual(extracted, msg)
        self._record("PKI-22", "cmsverify", "PASS", 0, "Verify CMS SignedData signature and extract content")

    def test_10_cms_enveloped_data_encrypt_parse_decrypt(self):
        """Verify cmsencrypt, cmsparse, and cmsdecrypt for PKCS#7 EnvelopedData."""
        secret_msg = b"Confidential Digital Envelope Content Protected by SM2/SM4"

        # 1. cmsencrypt
        enc_res = self.client.execute(
            "cmsencrypt",
            {"rcptcert": "input:cert", "in": "input:data", "out": "encrypted.cms"},
            inputs={"cert": TestPKISuite.user_cert, "data": secret_msg},
        )
        self.assertEqual(enc_res.get("status"), "SUCCEEDED")
        self.assertEqual(enc_res.get("exitCode"), 0)
        cms_encrypted = self.client.get_artifact(enc_res, "encrypted.cms")
        self.assertIsNotNone(cms_encrypted)
        self._record("PKI-23", "cmsencrypt", "PASS", 0, "Encrypt message into CMS EnvelopedData for recipient")

        # 2. cmsparse on EnvelopedData
        parse_res = self.client.execute("cmsparse", {"in": "input:cms"}, inputs={"cms": cms_encrypted})
        self.assertEqual(parse_res.get("status"), "SUCCEEDED")
        self.assertEqual(parse_res.get("exitCode"), 0)
        self._record("PKI-24", "cmsparse", "PASS", 0, "Parse CMS EnvelopedData ASN.1 structure")

        # 3. cmsdecrypt
        dec_res = self.client.execute(
            "cmsdecrypt",
            {
                "key": "input:key",
                "pass": "654321",
                "cert": "input:cert",
                "in": "input:cms",
                "out": "decrypted.txt",
            },
            inputs={"key": TestPKISuite.user_key, "cert": TestPKISuite.user_cert, "cms": cms_encrypted},
        )
        self.assertEqual(dec_res.get("status"), "SUCCEEDED")
        self.assertEqual(dec_res.get("exitCode"), 0)
        decrypted = self.client.get_artifact(dec_res, "decrypted.txt")
        self.assertEqual(decrypted, secret_msg)
        self._record("PKI-25", "cmsdecrypt", "PASS", 0, "Decrypt CMS EnvelopedData using recipient private key")


def run_suite():
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestPKISuite)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(run_suite())
