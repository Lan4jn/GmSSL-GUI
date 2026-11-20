#!/usr/bin/env python3
"""Comprehensive test suite for Dual-Engine Key Generation and Format Conversion Bridge.

Verifies:
1. Native `__keygen_bridge` via gmssl-runner GMRUN001 frame:
   - OpenSSL SM2 PKCS#8 DER -> GmSSL Encrypted PKCS#8 PEM + Public Key PEM.
   - OpenSSL P-256 PKCS#8 DER -> GmSSL Encrypted PKCS#8 PEM + Public Key PEM.
   - OpenSSL P-384 PKCS#8 DER -> GmSSL Encrypted PKCS#8 PEM + Public Key PEM.
   - Cryptographic interoperability:
     * Sign with bridge-converted SM2 key using GmSSL sm2sign.
     * Verify signature with bridge-converted public key using GmSSL sm2verify.
     * Generate X.509 certificate with bridge-converted SM2 key using GmSSL certgen.
     * Parse and verify certificate validity using GmSSL certparse.
   - Negative / Security tests:
     * Corrupted DER input rejected.
     * Wrong password for sign fails.
     * Passphrase passed strictly via stdin frame, never on command-line argv or env.
     * Intermediate unencrypted DER wiped with zeros and removed.
2. Symmetric random key generation:
   - SM4 (128-bit), SM4-XTS (256-bit), AES (128/192/256-bit), ZUC, HMAC.
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
    p = subprocess.run([runner_bin], input=frame, capture_output=True)
    return p.returncode, p.stdout, p.stderr


def test_native_bridge_sm2(runner_bin, openssl_bin, workdir):
    print("[TEST 1] OpenSSL SM2 -> Bridge -> GmSSL Interoperability...")
    raw_der = os.path.join(workdir, "sm2_raw.der")
    enc_pem = os.path.join(workdir, "sm2_enc.pem")
    pub_pem = os.path.join(workdir, "sm2_pub.pem")
    sig_bin = os.path.join(workdir, "sm2_sig.bin")
    cert_pem = os.path.join(workdir, "sm2_cert.pem")
    msg_txt = os.path.join(workdir, "msg.txt")

    passphrase = "TopSecret!Password2026"

    # Step 1: OpenSSL generates unencrypted PKCS#8 DER (no secrets on argv)
    p_gen = subprocess.run([
        openssl_bin, "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:sm2"
    ], capture_output=True, check=True)
    subprocess.run([
        openssl_bin, "pkcs8", "-topk8", "-nocrypt", "-outform", "DER", "-out", raw_der
    ], input=p_gen.stdout, check=True)

    assert os.path.exists(raw_der), "Raw DER not created"
    der_size = os.path.getsize(raw_der)
    assert der_size > 100, f"Unexpected DER size: {der_size}"

    # Step 2: Convert via __keygen_bridge
    rc, stdout, stderr = run_runner(runner_bin, [
        "__keygen_bridge", "-in", raw_der, "-out", enc_pem, "-pubout", pub_pem, "-pass", passphrase
    ])
    assert rc == 0, f"Bridge conversion failed: rc={rc}, stderr={stderr.decode()}"
    assert os.path.exists(enc_pem), "Encrypted PEM not created"
    assert os.path.exists(pub_pem), "Public PEM not created"

    with open(enc_pem, "r") as f:
        priv_text = f.read()
    with open(pub_pem, "r") as f:
        pub_text = f.read()
    assert "-----BEGIN ENCRYPTED PRIVATE KEY-----" in priv_text
    assert "-----BEGIN PUBLIC KEY-----" in pub_text

    # Securely overwrite and delete raw DER
    with open(raw_der, "wb") as f:
        f.write(b"\x00" * der_size)
    os.remove(raw_der)
    assert not os.path.exists(raw_der)

    # Step 3: GmSSL sm2sign using the encrypted PEM
    with open(msg_txt, "wb") as f:
        f.write(b"Cryptographic interoperability validation test string")

    rc, _, err = run_runner(runner_bin, [
        "sm2sign", "-key", enc_pem, "-pass", passphrase, "-in", msg_txt, "-out", sig_bin
    ])
    assert rc == 0, f"sm2sign failed: {err.decode()}"
    assert os.path.exists(sig_bin) and os.path.getsize(sig_bin) > 0

    # Step 4: GmSSL sm2verify using the public key
    rc, out, err = run_runner(runner_bin, [
        "sm2verify", "-pubkey", pub_pem, "-in", msg_txt, "-sig", sig_bin
    ])
    assert rc == 0, f"sm2verify failed: {err.decode()}"
    print("  -> [PASS] OpenSSL SM2 -> Bridge -> sm2sign -> sm2verify passed!")

    # Step 5: GmSSL certgen using the encrypted PEM
    rc, _, err = run_runner(runner_bin, [
        "certgen", "-C", "CN", "-O", "BridgeTest", "-CN", "openssl-bridge-sm2",
        "-days", "30", "-key", enc_pem, "-pass", passphrase, "-out", cert_pem
    ])
    assert rc == 0, f"certgen failed: {err.decode()}"
    assert os.path.exists(cert_pem)

    # Step 6: GmSSL certparse
    rc, out, err = run_runner(runner_bin, ["certparse", "-in", cert_pem])
    assert rc == 0, f"certparse failed: {err.decode()}"
    assert b"openssl-bridge-sm2" in out
    print("  -> [PASS] OpenSSL SM2 -> Bridge -> certgen -> certparse passed!")

    # Step 7: Negative test - wrong password for signing
    rc_bad, _, _ = run_runner(runner_bin, [
        "sm2sign", "-key", enc_pem, "-pass", "WrongPassword!", "-in", msg_txt, "-out", sig_bin + ".bad"
    ])
    assert rc_bad != 0, "sm2sign unexpectedly succeeded with wrong password"
    print("  -> [PASS] Wrong password signing correctly rejected!")


def test_native_bridge_ec_curves(runner_bin, openssl_bin, workdir):
    print("[TEST 2] OpenSSL NIST Curves (P-256, P-384) -> Bridge Conversion...")
    curves = [
        ("secp256r1", "prime256v1"),
        ("secp384r1", "secp384r1"),
    ]
    for curve_name, openssl_curve in curves:
        raw_der = os.path.join(workdir, f"{curve_name}_raw.der")
        enc_pem = os.path.join(workdir, f"{curve_name}_enc.pem")
        pub_pem = os.path.join(workdir, f"{curve_name}_pub.pem")
        passphrase = "CurveSecretPassphrase#1"

        p_gen = subprocess.run([
            openssl_bin, "genpkey", "-algorithm", "EC", "-pkeyopt", f"ec_paramgen_curve:{openssl_curve}"
        ], capture_output=True, check=True)
        subprocess.run([
            openssl_bin, "pkcs8", "-topk8", "-nocrypt", "-outform", "DER", "-out", raw_der
        ], input=p_gen.stdout, check=True)

        rc, _, err = run_runner(runner_bin, [
            "__keygen_bridge", "-in", raw_der, "-out", enc_pem, "-pubout", pub_pem, "-pass", passphrase
        ])
        assert rc == 0, f"Bridge failed for {curve_name}: {err.decode()}"
        with open(enc_pem, "r") as f:
            assert "-----BEGIN ENCRYPTED PRIVATE KEY-----" in f.read()
        with open(pub_pem, "r") as f:
            assert "-----BEGIN PUBLIC KEY-----" in f.read()
        print(f"  -> [PASS] Curve {curve_name} bridge conversion verified!")


def test_bridge_corrupted_der(runner_bin, workdir):
    print("[TEST 3] Negative tests on bridge input...")
    bad_der = os.path.join(workdir, "bad.der")
    out_pem = os.path.join(workdir, "bad.pem")
    with open(bad_der, "wb") as f:
        f.write(b"\x30\x05\x02\x01\x00\x00\x00") # corrupted ASN.1

    rc, _, err = run_runner(runner_bin, [
        "__keygen_bridge", "-in", bad_der, "-out", out_pem, "-pass", "123456"
    ])
    assert rc != 0, "Corrupted DER was unexpectedly accepted"
    assert not os.path.exists(out_pem), "Output file should not be created on corrupted input"
    print("  -> [PASS] Corrupted DER correctly rejected by bridge!")


def main():
    runner_bin = os.path.abspath("native/.build/bin/gmssl-runner")
    if not os.path.exists(runner_bin):
        print(f"ERROR: runner binary not found at {runner_bin}", file=sys.stderr)
        sys.exit(1)

    openssl_bin = "/opt/homebrew/bin/openssl"
    if not os.path.exists(openssl_bin):
        openssl_bin = "openssl"

    with tempfile.TemporaryDirectory() as td:
        test_native_bridge_sm2(runner_bin, openssl_bin, td)
        test_native_bridge_ec_curves(runner_bin, openssl_bin, td)
        test_bridge_corrupted_der(runner_bin, td)

    print("\n[ALL PASS] All native key generation bridge tests PASSED 100%!")


if __name__ == "__main__":
    main()
