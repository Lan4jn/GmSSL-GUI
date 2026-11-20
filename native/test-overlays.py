#!/usr/bin/env python3
"""Verification suite for RFC 6962 SCT verification (P256 & SM2) and CRL generation/verification with overlays.

Tests:
1. Standard RFC 6962 SCT verify with secp256r1 + SHA256 (OpenSSL CLI used for test fixture generation only):
   - Valid SCT: version(1B=0), log_id = SHA256(DER SubjectPublicKeyInfo), timestamp(8B uint64 big-endian),
     extensions(2B=0), ECDSA secp256r1 signature over:
     sct_version(1B=0) + entry_type(1B=0) + timestamp(8B) + cert_len(3B) + cert_der + exts_len(2B=0).
   - Tampered timestamp SCT: same signature, 1 byte flipped in timestamp -> fails verification.
   - Tampered log_id SCT: 1 byte flipped in log_id -> fails verification.
2. CRL generation -> verification roundtrip:
   - Generate CA private key and CA certificate.
   - Run crlgen without -next_update -> verify crlverify passes without uninitialized stack corruption.
   - Run crlgen with -next_update 20380101000000Z -> verify crlverify passes.
"""

import hashlib
import os
import struct
import subprocess
import sys
import tempfile


def run_runner(runner_bin, args, stdin_data=b""):
    frame = bytearray(b"GMRUN001")
    count = len(args)
    total_len = sum(len(a.encode("utf-8")) for a in args)
    frame += struct.pack(">II", count, total_len)
    for a in args:
        b = a.encode("utf-8")
        frame += struct.pack(">I", len(b)) + b
    frame += stdin_data
    p = subprocess.run([runner_bin], input=frame, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return p.returncode, p.stdout, p.stderr


def test_standard_p256_sct(runner_bin, workdir):
    print("[TEST] RFC 6962 standard P256 + SHA256 SCT verify...")
    log_key_pem = os.path.join(workdir, "ctlog_p256.pem")
    log_priv_pem = os.path.join(workdir, "ctlog_p256_priv.pem")
    cert_pem = os.path.join(workdir, "cert_p256.pem")
    cert_der = os.path.join(workdir, "cert_p256.der")
    log_pub_der = os.path.join(workdir, "ctlog_p256_pub.der")

    # 1. Generate Log keypair using OpenSSL
    subprocess.run(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", log_priv_pem], check=True)
    subprocess.run(["openssl", "ec", "-in", log_priv_pem, "-pubout", "-out", log_key_pem], check=True, capture_output=True)
    subprocess.run(["openssl", "ec", "-in", log_priv_pem, "-pubout", "-outform", "DER", "-out", log_pub_der], check=True, capture_output=True)

    with open(log_pub_der, "rb") as f:
        spki_der = f.read()
    log_id = hashlib.sha256(spki_der).digest()
    assert len(log_id) == 32

    # 2. Generate a test certificate using OpenSSL
    cert_priv_pem = os.path.join(workdir, "cert_priv.pem")
    subprocess.run(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", cert_priv_pem], check=True)
    subprocess.run([
        "openssl", "req", "-new", "-x509", "-key", cert_priv_pem, "-out", cert_pem,
        "-days", "30", "-subj", "/CN=sct-standard.example.com"
    ], check=True, capture_output=True)
    subprocess.run(["openssl", "x509", "-in", cert_pem, "-outform", "DER", "-out", cert_der], check=True, capture_output=True)

    with open(cert_der, "rb") as f:
        cert_bytes = f.read()

    # 3. Construct RFC 6962 Signed Data
    timestamp_ms = 1750000000000
    signed_data = bytearray()
    signed_data.append(0) # sct_version = 0 (v1)
    signed_data.append(0) # signature_type = 0 (certificate_timestamp)
    signed_data += struct.pack(">Q", timestamp_ms) # timestamp uint64
    signed_data += struct.pack(">H", 0) # entry_type = 0 (x509_entry)
    signed_data += struct.pack(">I", len(cert_bytes))[1:] # 3 bytes cert len
    signed_data += cert_bytes
    signed_data += struct.pack(">H", 0) # sct extensions len = 0

    signed_data_file = os.path.join(workdir, "signed_data.bin")
    with open(signed_data_file, "wb") as f:
        f.write(signed_data)

    # Sign using openssl dgst -sha256 -sign
    sig_file = os.path.join(workdir, "sig.der")
    subprocess.run(["openssl", "dgst", "-sha256", "-sign", log_priv_pem, "-out", sig_file, signed_data_file], check=True)
    with open(sig_file, "rb") as f:
        sig_der = f.read()

    # Construct single SCT:
    # version(1B=0) + log_id(32B) + timestamp(8B) + exts_len(2B=0) + sig_alg(2B=0x0403) + sig_len(2B) + sig_der
    single_sct = bytearray()
    single_sct.append(0) # version
    single_sct += log_id # 32 bytes (SPKI SHA256)
    single_sct += struct.pack(">Q", timestamp_ms)
    single_sct += struct.pack(">H", 0) # exts len = 0
    single_sct += bytes([0x04, 0x03]) # ecdsa_secp256r1_sha256 in TLS
    single_sct += struct.pack(">H", len(sig_der))
    single_sct += sig_der

    # Construct SCT list:
    sct_list = bytearray()
    inner_len = 2 + len(single_sct)
    sct_list += struct.pack(">H", inner_len)
    sct_list += struct.pack(">H", len(single_sct))
    sct_list += single_sct

    sct_path = os.path.join(workdir, "sctlist.bin")
    with open(sct_path, "wb") as f:
        f.write(sct_list)

    # 1A. Verify valid standard SCT
    rc, stdout, stderr = run_runner(runner_bin, [
        "sctverify", "-in", sct_path, "-cert", cert_pem, "-log_key", log_key_pem, "-at_least", "1"
    ])
    if rc != 0:
        print(f"FAILED: valid sctverify failed: rc={rc}, stderr={stderr.decode('utf-8', 'replace')}")
        sys.exit(1)
    print("  -> [PASS] Valid RFC 6962 P256+SHA256 SCT verified successfully!")

    # 1B. Tamper timestamp in SCT
    tampered_single = bytearray(single_sct)
    tampered_single[33 + 7] ^= 0x01 # flip lowest bit of timestamp
    tampered_list = bytearray()
    tampered_list += struct.pack(">H", inner_len)
    tampered_list += struct.pack(">H", len(tampered_single))
    tampered_list += tampered_single
    tampered_path = os.path.join(workdir, "sct_tampered_time.bin")
    with open(tampered_path, "wb") as f:
        f.write(tampered_list)

    rc_t, _, _ = run_runner(runner_bin, [
        "sctverify", "-in", tampered_path, "-cert", cert_pem, "-log_key", log_key_pem, "-at_least", "1"
    ])
    if rc_t == 0:
        print("FAILED: tampered timestamp SCT unexpectedly PASSED verification!")
        sys.exit(1)
    print("  -> [PASS] Tampered timestamp SCT correctly REJECTED!")

    # 1C. Tamper log_id in SCT
    tampered_log_single = bytearray(single_sct)
    tampered_log_single[1] ^= 0x01 # flip 1 byte of log_id
    tampered_log_list = bytearray()
    tampered_log_list += struct.pack(">H", inner_len)
    tampered_log_list += struct.pack(">H", len(tampered_log_single))
    tampered_log_list += tampered_log_single
    tampered_log_path = os.path.join(workdir, "sct_tampered_logid.bin")
    with open(tampered_log_path, "wb") as f:
        f.write(tampered_log_list)

    rc_l, _, _ = run_runner(runner_bin, [
        "sctverify", "-in", tampered_log_path, "-cert", cert_pem, "-log_key", log_key_pem, "-at_least", "1"
    ])
    if rc_l == 0:
        print("FAILED: tampered log_id SCT unexpectedly PASSED verification!")
        sys.exit(1)
    print("  -> [PASS] Tampered log_id SCT correctly REJECTED!")


def test_crl_flow(runner_bin, workdir):
    print("[TEST] CRL generation -> crlverify roundtrip...")
    cakey = os.path.join(workdir, "cakey.pem")
    cacert = os.path.join(workdir, "cacert.pem")
    revoked = os.path.join(workdir, "revoked.der")
    crl_default = os.path.join(workdir, "crl_default.der")
    crl_next = os.path.join(workdir, "crl_next.der")

    # 1. Generate CA key
    rc, _, err = run_runner(runner_bin, ["sm2keygen", "-pass", "123456", "-out", cakey])
    assert rc == 0, f"sm2keygen failed: {err.decode()}"

    # 2. Generate CA cert
    rc, _, err = run_runner(runner_bin, [
        "certgen", "-C", "CN", "-O", "Test", "-CN", "RootCA",
        "-days", "365", "-key", cakey, "-pass", "123456",
        "-key_usage", "keyCertSign", "-key_usage", "cRLSign",
        "-out", cacert
    ])
    assert rc == 0, f"certgen failed: {err.decode()}"

    # 3. Create a revoked cert dummy entry
    with open(revoked, "wb") as f:
        f.write(bytes([
            0x30, 0x12,
            0x02, 0x01, 0x01,
            0x17, 0x0D, ord('2'), ord('3'), ord('0'), ord('1'), ord('0'), ord('1'),
            ord('0'), ord('0'), ord('0'), ord('0'), ord('0'), ord('0'), ord('Z')
        ]))

    # Test 2A: crlgen without -next_update
    rc, _, err = run_runner(runner_bin, [
        "crlgen", "-in", revoked, "-cacert", cacert, "-key", cakey, "-pass", "123456",
        "-crl_num", "1", "-out", crl_default
    ])
    assert rc == 0, f"crlgen without next_update failed: {err.decode()}"

    # Verify crl_default with crlverify
    rc, out, err = run_runner(runner_bin, [
        "crlverify", "-in", crl_default, "-cacert", cacert
    ])
    if rc != 0:
        print(f"FAILED: crlverify on CRL without next_update failed: rc={rc}, stderr={err.decode('utf-8', 'replace')}")
        sys.exit(1)
    assert b"Verification success" in out, f"Expected success in output: {out.decode()}"
    print("  -> [PASS] crlgen (no next_update) -> crlverify verified successfully!")

    # Test 2B: crlgen with -next_update
    rc, _, err = run_runner(runner_bin, [
        "crlgen", "-in", revoked, "-cacert", cacert, "-key", cakey, "-pass", "123456",
        "-crl_num", "2", "-next_update", "20380101000000Z", "-out", crl_next
    ])
    assert rc == 0, f"crlgen with next_update failed: {err.decode()}"

    # Verify crl_next with crlverify
    rc, out, err = run_runner(runner_bin, [
        "crlverify", "-in", crl_next, "-cacert", cacert
    ])
    if rc != 0:
        print(f"FAILED: crlverify on CRL with next_update failed: rc={rc}, stderr={err.decode('utf-8', 'replace')}")
        sys.exit(1)
    assert b"Verification success" in out, f"Expected success in output: {out.decode()}"
    print("  -> [PASS] crlgen (with next_update) -> crlverify verified successfully!")


def main():
    runner_bin = os.path.abspath("native/.build/bin/gmssl-runner")
    if not os.path.exists(runner_bin):
        print(f"ERROR: runner binary not found at {runner_bin}", file=sys.stderr)
        sys.exit(1)

    with tempfile.TemporaryDirectory() as td:
        test_standard_p256_sct(runner_bin, td)
        test_crl_flow(runner_bin, td)

    print("\n[ALL PASS] All SCT and CRL overlay verification tests PASSED 100%!")


if __name__ == "__main__":
    main()
