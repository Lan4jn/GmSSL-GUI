#!/usr/bin/env python3
"""GmSSL Engine Protocol Pair Integration and Verification Suite.

Validates TLCP, TLS 1.2, TLS 1.3, and QUIC server/client paired handshakes,
mutual authentication, parameter verification, and network policy enforcement
via the real Engine HTTP service.
"""

import base64
import json
import os
import pathlib
import sys
import threading
import time
from datetime import datetime, timezone

# Adjust import path
ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from tests.toolbox.engine_client import EngineClient

BUILD_DIR = pathlib.Path("/tmp/gmssl-review.V5gpYG/build")
RESULTS_DIR = ROOT / "tests/toolbox" / "protocol-results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)


def load_fixtures():
    """Load test certificates and keys generated during upstream build."""
    fixtures = {}
    files = {
        "sm2_root_ca": "sm2_root_ca_cert.pem",
        "sm2_tlcp_server_certs": "sm2_tlcp_server_certs.pem",
        "sm2_tlcp_server_keys": "sm2_tlcp_server_keys.pem",
        "sm2_tlcp_client_certs": "sm2_tlcp_client_certs.pem",
        "sm2_tlcp_client_keys": "sm2_tlcp_client_keys.pem",
        "sm2_tls_server_certs": "sm2_tls_server_certs.pem",
        "sm2_tls_server_key": "sm2_tls_server_key.pem",
        "sm2_tls_client_certs": "sm2_tls_client_certs.pem",
        "sm2_tls_client_key": "sm2_tls_client_key.pem",
        "p256_root_ca": "p256_root_ca_cert.pem",
        "p256_tls_server_certs": "p256_tls_server_certs.pem",
        "p256_tls_server_key": "p256_tls_server_key.pem",
        "p256_tls_client_certs": "p256_tls_client_certs.pem",
        "p256_tls_client_key": "p256_tls_client_key.pem",
    }
    for key, fname in files.items():
        p = BUILD_DIR / fname
        if not p.exists():
            raise FileNotFoundError(f"Fixture file missing: {p}")
        fixtures[key] = p.read_bytes()
    return fixtures


class ProtocolTestSuite:
    def __init__(self):
        self.client = EngineClient()
        self.fixtures = load_fixtures()
        self.results = []
        self.log_lines = []

    def log(self, msg):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        line = f"[{timestamp}] {msg}"
        print(line)
        self.log_lines.append(line)

    def record_test(self, test_id, name, protocol, server_tool, client_tool, status, details):
        item = {
            "test_id": test_id,
            "name": name,
            "protocol": protocol,
            "server_tool": server_tool,
            "client_tool": client_tool,
            "status": status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "details": details,
        }
        self.results.append(item)
        status_str = "PASS" if status == "PASSED" else "FAIL"
        self.log(f"[{status_str}] {test_id}: {name}")

    def run_pair(self, test_id, name, protocol, server_tool, server_params, server_inputs,
                 client_tool, client_params, client_inputs,
                 server_timeout=6, client_timeout=5,
                 expect_client_exit=0, expect_client_out=None,
                 expect_server_exit=None, client_must_succeed=True):
        """Run a paired server-client execution using background threads."""
        self.log(f"Starting test pair {test_id} ({name}) on port {server_params.get('port')}")
        server_res = {}
        client_res = {}

        def _server():
            server_res["res"] = self.client.execute(
                server_tool,
                parameters=server_params,
                inputs=server_inputs,
                timeout_seconds=server_timeout
            )

        def _client():
            client_res["res"] = self.client.execute(
                client_tool,
                parameters=client_params,
                inputs=client_inputs,
                timeout_seconds=client_timeout
            )

        t_srv = threading.Thread(target=_server, name=f"srv-{test_id}")
        t_srv.start()
        # Give server 1.0s to bind and listen
        time.sleep(1.0)

        t_cli = threading.Thread(target=_client, name=f"cli-{test_id}")
        t_cli.start()

        t_cli.join()
        t_srv.join()

        cli = client_res.get("res", {})
        srv = server_res.get("res", {})

        cli_status = cli.get("status")
        cli_exit = cli.get("exitCode")
        cli_stdout = EngineClient.get_stdout_text(cli)

        srv_status = srv.get("status")
        srv_exit = srv.get("exitCode")
        srv_stdout = EngineClient.get_stdout_text(srv)

        # Evaluate pass criteria
        passed = True
        reasons = []

        if client_must_succeed:
            if cli_status != "SUCCEEDED" or cli_exit != expect_client_exit:
                passed = False
                reasons.append(f"Client expected exit {expect_client_exit} SUCCEEDED, got {cli_status} (exit {cli_exit})")
            if expect_client_out and expect_client_out not in cli_stdout:
                passed = False
                reasons.append(f"Client stdout missing expected token: {expect_client_out}")
        else:
            if cli_status == "SUCCEEDED" and cli_exit == 0:
                passed = False
                reasons.append("Client was expected to fail, but succeeded")

        if expect_server_exit is not None:
            if srv_exit != expect_server_exit:
                passed = False
                reasons.append(f"Server expected exit {expect_server_exit}, got {srv_exit}")
        else:
            # Server either completes clean (SUCCEEDED 0) or times out and is cleanly killed (TIMED_OUT, 143)
            # Long-running listener servers (TLCP/TLS12) exit with TIMED_OUT (143) after client finishes
            if srv_status not in ("SUCCEEDED", "TIMED_OUT"):
                passed = False
                reasons.append(f"Server abnormal state: {srv_status}")

        details = {
            "client_status": cli_status,
            "client_exit": cli_exit,
            "client_stdout_snippet": cli_stdout[:200],
            "client_stderr_snippet": cli.get("stderr", "")[:200],
            "server_status": srv_status,
            "server_exit": srv_exit,
            "server_stdout_snippet": srv_stdout[:200],
            "server_stderr_snippet": srv.get("stderr", "")[:200],
            "reasons": reasons,
        }

        self.record_test(test_id, name, protocol, server_tool, client_tool, "PASSED" if passed else "FAILED", details)
        return passed

    def run_all(self):
        self.log("=== Phase 1: Network Policy and Input Validation Tests ===")

        # 1. Invalid Port (Security policy: port < 1024 or not in allowlist)
        p1 = self.client.execute("tlcp_server", parameters={"port": 80})
        is_p1_rejected = (p1.get("http_code") == 400 or p1.get("status") == "FAILED")
        self.record_test("PROTO-SEC-01", "Port < 1024 blocked by NetworkPolicy", "TLCP", "tlcp_server", None,
                         "PASSED" if is_p1_rejected else "FAILED",
                         {"response": p1})

        p2 = self.client.execute("tls12_client", parameters={"host": "127.0.0.1", "port": 9999})
        is_p2_rejected = (p2.get("http_code") == 400 or p2.get("status") == "FAILED")
        self.record_test("PROTO-SEC-02", "Unallowed port 9999 blocked by NetworkPolicy", "TLS12", None, "tls12_client",
                         "PASSED" if is_p2_rejected else "FAILED",
                         {"response": p2})

        # 2. Invalid Host (Non-allowlisted external IP)
        p3 = self.client.execute("tls13_client", parameters={"host": "8.8.8.8", "port": 14433})
        is_p3_rejected = (p3.get("http_code") == 400 or p3.get("status") == "FAILED")
        self.record_test("PROTO-SEC-03", "Non-allowlisted IP blocked by NetworkPolicy", "TLS13", None, "tls13_client",
                         "PASSED" if is_p3_rejected else "FAILED",
                         {"response": p3})

        # 3. Parameter Validation: Missing -host on client
        p4 = self.client.execute("quic_client", parameters={"port": 14436})
        is_p4_rejected = (p4.get("status") == "FAILED" or p4.get("http_code") == 400)
        self.record_test("PROTO-VAL-01", "Missing required -host rejected", "QUIC", None, "quic_client",
                         "PASSED" if is_p4_rejected else "FAILED",
                         {"response": p4})

        # 4. Parameter Validation: Invalid cipher suite
        p5 = self.client.execute("tls12_server", parameters={
            "port": 14434, "cipher_suite": "INVALID_CIPHER", "cert": "input:cert", "key": "input:key", "pass": "P@ssw0rd"
        }, inputs={"cert": self.fixtures["sm2_tls_server_certs"], "key": self.fixtures["sm2_tls_server_key"]})
        is_p5_rejected = (p5.get("status") == "FAILED" or p5.get("http_code") == 400)
        self.record_test("PROTO-VAL-02", "Invalid cipher suite rejected", "TLS12", "tls12_server", None,
                         "PASSED" if is_p5_rejected else "FAILED",
                         {"response": p5})

        self.log("=== Phase 2: Real Protocol Pair Handshake Tests ===")

        # Test 1: TLCP Standard Handshake (SM4-GCM, Server Double Certificate)
        self.run_pair(
            test_id="PROTO-TLCP-01",
            name="TLCP SM4-GCM Handshake with SM2 Double Certificate",
            protocol="TLCP (GB/T 38636)",
            server_tool="tlcp_server",
            server_params={
                "port": 14435,
                "cipher_suite": "TLS_ECC_SM4_GCM_SM3",
                "cert": "input:cert",
                "key": "input:key",
                "pass": "P@ssw0rd"
            },
            server_inputs={
                "cert": self.fixtures["sm2_tlcp_server_certs"],
                "key": self.fixtures["sm2_tlcp_server_keys"]
            },
            client_tool="tlcp_client",
            client_params={
                "host": "127.0.0.1",
                "port": 14435,
                "server_name": "localhost",
                "cacert": "input:cacert",
                "cipher_suite": "TLS_ECC_SM4_GCM_SM3",
                "in": "input:in"
            },
            client_inputs={
                "cacert": self.fixtures["sm2_root_ca"],
                "in": b"GET /tlcp_test HTTP/1.1\r\nHost: localhost\r\n\r\n"
            },
            expect_client_out="GET /tlcp_test HTTP/1.1"
        )

        # Test 2: TLCP Mutual Authentication (Client Certificate)
        self.run_pair(
            test_id="PROTO-TLCP-02",
            name="TLCP SM4-GCM Mutual Authentication (Client Cert)",
            protocol="TLCP (GB/T 38636)",
            server_tool="tlcp_server",
            server_params={
                "port": 14435,
                "cipher_suite": "TLS_ECC_SM4_GCM_SM3",
                "cert": "input:cert",
                "key": "input:key",
                "pass": "P@ssw0rd",
                "cacert": "input:cacert",
                "cert_request": True
            },
            server_inputs={
                "cert": self.fixtures["sm2_tlcp_server_certs"],
                "key": self.fixtures["sm2_tlcp_server_keys"],
                "cacert": self.fixtures["sm2_root_ca"]
            },
            client_tool="tlcp_client",
            client_params={
                "host": "127.0.0.1",
                "port": 14435,
                "server_name": "localhost",
                "cacert": "input:cacert",
                "cipher_suite": "TLS_ECC_SM4_GCM_SM3",
                "cert": "input:cert",
                "key": "input:key",
                "pass": "P@ssw0rd",
                "in": "input:in"
            },
            client_inputs={
                "cacert": self.fixtures["sm2_root_ca"],
                "cert": self.fixtures["sm2_tls_client_certs"],
                "key": self.fixtures["sm2_tls_client_key"],
                "in": b"GET /auth_test HTTP/1.1\r\n\r\n"
            },
            expect_client_out="GET /auth_test HTTP/1.1"
        )

        # Test 3: TLS 1.2 SM4-GCM Handshake (GmSSL SM2/SM4)
        self.run_pair(
            test_id="PROTO-TLS12-01",
            name="TLS 1.2 SM4-GCM Handshake (SM2 Key & Cert)",
            protocol="TLS 1.2",
            server_tool="tls12_server",
            server_params={
                "port": 14434,
                "cipher_suite": "TLS_ECDHE_SM4_GCM_SM3",
                "supported_group": "sm2p256v1",
                "sig_alg": "sm2sig_sm3",
                "cert": "input:cert",
                "key": "input:key",
                "pass": "P@ssw0rd"
            },
            server_inputs={
                "cert": self.fixtures["sm2_tls_server_certs"],
                "key": self.fixtures["sm2_tls_server_key"]
            },
            client_tool="tls12_client",
            client_params={
                "host": "127.0.0.1",
                "port": 14434,
                "server_name": "localhost",
                "cacert": "input:cacert",
                "cipher_suite": "TLS_ECDHE_SM4_GCM_SM3",
                "supported_group": "sm2p256v1",
                "sig_alg": "sm2sig_sm3",
                "in": "input:in"
            },
            client_inputs={
                "cacert": self.fixtures["sm2_root_ca"],
                "in": b"Hello GmSSL TLS 1.2 SM4-GCM\n"
            },
            expect_client_out="Hello GmSSL TLS 1.2 SM4-GCM"
        )

        # Test 4: TLS 1.2 SM4-CBC Handshake
        self.run_pair(
            test_id="PROTO-TLS12-02",
            name="TLS 1.2 SM4-CBC Handshake (SM2 Key & Cert)",
            protocol="TLS 1.2",
            server_tool="tls12_server",
            server_params={
                "port": 14437,
                "cipher_suite": "TLS_ECDHE_SM4_CBC_SM3",
                "supported_group": "sm2p256v1",
                "sig_alg": "sm2sig_sm3",
                "cert": "input:cert",
                "key": "input:key",
                "pass": "P@ssw0rd"
            },
            server_inputs={
                "cert": self.fixtures["sm2_tls_server_certs"],
                "key": self.fixtures["sm2_tls_server_key"]
            },
            client_tool="tls12_client",
            client_params={
                "host": "127.0.0.1",
                "port": 14437,
                "server_name": "localhost",
                "cacert": "input:cacert",
                "cipher_suite": "TLS_ECDHE_SM4_CBC_SM3",
                "supported_group": "sm2p256v1",
                "sig_alg": "sm2sig_sm3",
                "in": "input:in"
            },
            client_inputs={
                "cacert": self.fixtures["sm2_root_ca"],
                "in": b"Hello GmSSL TLS 1.2 SM4-CBC\n"
            },
            expect_client_out="Hello GmSSL TLS 1.2 SM4-CBC"
        )

        # Test 5: TLS 1.3 SM4-GCM Handshake (RFC 8998)
        self.run_pair(
            test_id="PROTO-TLS13-01",
            name="TLS 1.3 SM4-GCM Handshake (RFC 8998)",
            protocol="TLS 1.3",
            server_tool="tls13_server",
            server_params={
                "port": 14433,
                "cipher_suite": "TLS_SM4_GCM_SM3",
                "supported_group": "sm2p256v1",
                "sig_alg": "sm2sig_sm3",
                "cert": "input:cert",
                "key": "input:key",
                "pass": "P@ssw0rd"
            },
            server_inputs={
                "cert": self.fixtures["sm2_tls_server_certs"],
                "key": self.fixtures["sm2_tls_server_key"]
            },
            client_tool="tls13_client",
            client_params={
                "host": "127.0.0.1",
                "port": 14433,
                "server_name": "localhost",
                "cacert": "input:cacert",
                "cipher_suite": "TLS_SM4_GCM_SM3",
                "supported_group": "sm2p256v1",
                "sig_alg": "sm2sig_sm3",
                "in": "input:in"
            },
            client_inputs={
                "cacert": self.fixtures["sm2_root_ca"],
                "in": b"Hello GmSSL TLS 1.3\n"
            },
            expect_client_out="Hello GmSSL TLS 1.3"
        )

        # Test 6: TLS 1.3 Mutual Authentication
        self.run_pair(
            test_id="PROTO-TLS13-02",
            name="TLS 1.3 SM4-GCM Mutual Authentication",
            protocol="TLS 1.3",
            server_tool="tls13_server",
            server_params={
                "port": 14438,
                "cipher_suite": "TLS_SM4_GCM_SM3",
                "supported_group": "sm2p256v1",
                "sig_alg": "sm2sig_sm3",
                "cert": "input:cert",
                "key": "input:key",
                "pass": "P@ssw0rd",
                "cacert": "input:cacert",
                "cert_request": True
            },
            server_inputs={
                "cert": self.fixtures["sm2_tls_server_certs"],
                "key": self.fixtures["sm2_tls_server_key"],
                "cacert": self.fixtures["sm2_root_ca"]
            },
            client_tool="tls13_client",
            client_params={
                "host": "127.0.0.1",
                "port": 14438,
                "server_name": "localhost",
                "cacert": "input:cacert",
                "cipher_suite": "TLS_SM4_GCM_SM3",
                "supported_group": "sm2p256v1",
                "sig_alg": "sm2sig_sm3",
                "cert": "input:cert",
                "key": "input:key",
                "pass": "P@ssw0rd",
                "in": "input:in"
            },
            client_inputs={
                "cacert": self.fixtures["sm2_root_ca"],
                "cert": self.fixtures["sm2_tls_client_certs"],
                "key": self.fixtures["sm2_tls_client_key"],
                "in": b"Hello TLS 1.3 Mutual Auth\n"
            },
            expect_client_out="Hello TLS 1.3 Mutual Auth"
        )

        # Test 7: QUIC Handshake & HTTP/3 1-RTT Response (UDP)
        self.run_pair(
            test_id="PROTO-QUIC-01",
            name="QUIC UDP Initial Probe and 1-RTT HTTP/3 Response",
            protocol="QUIC (RFC 9000/9001 experimental subset)",
            server_tool="quic_server",
            server_params={
                "port": 14436,
                "cipher_suite": "TLS_AES_128_GCM_SHA256",
                "supported_group": "prime256v1",
                "sig_alg": "ecdsa_secp256r1_sha256",
                "cert": "input:cert",
                "key": "input:key",
                "pass": "P@ssw0rd"
            },
            server_inputs={
                "cert": self.fixtures["p256_tls_server_certs"],
                "key": self.fixtures["p256_tls_server_key"]
            },
            client_tool="quic_client",
            client_params={
                "host": "127.0.0.1",
                "port": 14436,
                "server_name": "localhost",
                "cipher_suite": "TLS_AES_128_GCM_SHA256",
                "supported_group": "prime256v1",
                "sig_alg": "ecdsa_secp256r1_sha256"
            },
            client_inputs={},
            expect_client_out="hello from gmssl quic server"
        )

        self.log("=== Phase 3: Negative Handshake and Boundary Tests ===")

        # Test 8: TLCP Client Fails when CA Certificate does not verify Server
        self.run_pair(
            test_id="PROTO-NEG-01",
            name="TLCP Untrusted CA Certificate Rejection",
            protocol="TLCP",
            server_tool="tlcp_server",
            server_params={
                "port": 14435,
                "cipher_suite": "TLS_ECC_SM4_GCM_SM3",
                "cert": "input:cert",
                "key": "input:key",
                "pass": "P@ssw0rd"
            },
            server_inputs={
                "cert": self.fixtures["sm2_tlcp_server_certs"],
                "key": self.fixtures["sm2_tlcp_server_keys"]
            },
            client_tool="tlcp_client",
            client_params={
                "host": "127.0.0.1",
                "port": 14435,
                "server_name": "localhost",
                "cacert": "input:cacert",
                "cipher_suite": "TLS_ECC_SM4_GCM_SM3",
                "in": "input:in"
            },
            client_inputs={
                "cacert": self.fixtures["p256_root_ca"],  # Wrong CA (P256 root instead of SM2 root)
                "in": b"GET /untrusted HTTP/1.1\r\n\r\n"
            },
            client_must_succeed=False
        )

        # Test 9: TLS 1.2 Client Fails on Incompatible Curve Group
        self.run_pair(
            test_id="PROTO-NEG-02",
            name="TLS 1.2 Incompatible Curve Group Mismatch",
            protocol="TLS 1.2",
            server_tool="tls12_server",
            server_params={
                "port": 14434,
                "cipher_suite": "TLS_ECDHE_SM4_GCM_SM3",
                "supported_group": "sm2p256v1",
                "sig_alg": "sm2sig_sm3",
                "cert": "input:cert",
                "key": "input:key",
                "pass": "P@ssw0rd"
            },
            server_inputs={
                "cert": self.fixtures["sm2_tls_server_certs"],
                "key": self.fixtures["sm2_tls_server_key"]
            },
            client_tool="tls12_client",
            client_params={
                "host": "127.0.0.1",
                "port": 14434,
                "server_name": "localhost",
                "cacert": "input:cacert",
                "cipher_suite": "TLS_ECDHE_SM4_GCM_SM3",
                "supported_group": "secp256r1",  # Incompatible curve group with sm2 key
                "sig_alg": "sm2sig_sm3",
                "in": "input:in"
            },
            client_inputs={
                "cacert": self.fixtures["sm2_root_ca"],
                "in": b"Hello Group Mismatch\n"
            },
            client_must_succeed=False
        )

        # Save summary
        self.save_summary()

    def save_summary(self):
        total = len(self.results)
        passed = sum(1 for r in self.results if r["status"] == "PASSED")
        failed = sum(1 for r in self.results if r["status"] == "FAILED")

        import hashlib

        runner_bin = ROOT / "native/.build/bin/gmssl-runner"
        runner_sha = hashlib.sha256(runner_bin.read_bytes()).hexdigest() if runner_bin.exists() else "unknown"
        catalog_file = ROOT / "native/catalog.json"
        catalog_sha = hashlib.sha256(catalog_file.read_bytes()).hexdigest() if catalog_file.exists() else "unknown"

        summary = {
            "title": "GmSSL Protocol Pair Integration Verification Report",
            "executed_at": datetime.now(timezone.utc).isoformat(),
            "runner_sha256": runner_sha,
            "catalog_sha256": catalog_sha,
            "total_tests": total,
            "passed": passed,
            "failed": failed,
            "pass_rate": f"{(passed / total) * 100:.1f}%" if total > 0 else "0%",
            "results": self.results,
        }

        # Save to protocol-results/
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        run_file = RESULTS_DIR / f"protocol_run_{stamp}.json"
        latest_file = RESULTS_DIR / "latest.json"
        log_file = RESULTS_DIR / "protocol_test.log"

        with open(run_file, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)
        with open(latest_file, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)
        with open(log_file, "w", encoding="utf-8") as f:
            f.write("\n".join(self.log_lines) + "\n")

        self.log(f"Test suite finished: {passed}/{total} PASSED ({failed} FAILED).")
        self.log(f"Saved artifacts to {run_file} and {latest_file}.")

        if failed > 0:
            sys.exit(1)


if __name__ == "__main__":
    suite = ProtocolTestSuite()
    suite.run_all()
