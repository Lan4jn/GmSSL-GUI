"""Asymmetric and Key Management toolbox test suite.

Covers 14 catalog tools:
- Key generation & management: sm2keygen, eckeygen, sm9setup, sm9keygen
- Asymmetric encryption, signing, exchange:
  sm2sign, sm2verify, sm2encrypt, sm2decrypt, sm2exch,
  sm9sign, sm9verify, sm9encrypt, sm9decrypt, sm9exch
"""

import unittest
from .engine_client import EngineClient


class TestAsymmetricSuite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = EngineClient()
        cls.passphrase = "P@ssw0rd123!"
        cls.user_pass = "UserP@ss123!"
        cls.msg = b"GmSSL Asymmetric Test Message - 2026 Verification"

    def test_01_sm2_keygen_and_crypto(self):
        """Tools: sm2keygen, sm2sign, sm2verify, sm2encrypt, sm2decrypt"""
        # Keygen
        r_gen = self.client.execute("sm2keygen", {"pass": self.passphrase, "out": "sm2.pem", "pubout": "sm2pub.pem"})
        self.assertEqual(r_gen.get("status"), "SUCCEEDED", f"tool=sm2keygen status={r_gen.get('status')} exitCode={r_gen.get('exitCode')}")
        sm2_key = self.client.get_artifact(r_gen, "sm2.pem")
        sm2_pub = self.client.get_artifact(r_gen, "sm2pub.pem")
        self.assertTrue(sm2_key and sm2_pub)

        # Sign & Verify
        r_sig = self.client.execute(
            "sm2sign",
            {"key": "input:key", "pass": self.passphrase, "in": "input:msg", "out": "sm2.sig"},
            inputs={"key": sm2_key, "msg": self.msg},
        )
        self.assertEqual(r_sig.get("status"), "SUCCEEDED", f"tool=sm2sign status={r_sig.get('status')} exitCode={r_sig.get('exitCode')}")
        sig = self.client.get_artifact(r_sig, "sm2.sig")

        r_vrf = self.client.execute(
            "sm2verify",
            {"pubkey": "input:pub", "in": "input:msg", "sig": "input:sig"},
            inputs={"pub": sm2_pub, "msg": self.msg, "sig": sig},
        )
        self.assertEqual(r_vrf.get("status"), "SUCCEEDED", f"tool=sm2verify status={r_vrf.get('status')} exitCode={r_vrf.get('exitCode')}")

        # Encrypt & Decrypt
        r_enc = self.client.execute(
            "sm2encrypt",
            {"pubkey": "input:pub", "in": "input:msg", "out": "sm2.der"},
            inputs={"pub": sm2_pub, "msg": self.msg},
        )
        self.assertEqual(r_enc.get("status"), "SUCCEEDED", f"tool=sm2encrypt status={r_enc.get('status')} exitCode={r_enc.get('exitCode')}")
        cipher = self.client.get_artifact(r_enc, "sm2.der")

        r_dec = self.client.execute(
            "sm2decrypt",
            {"key": "input:key", "pass": self.passphrase, "in": "input:der", "out": "dec.txt"},
            inputs={"key": sm2_key, "der": cipher},
        )
        self.assertEqual(r_dec.get("status"), "SUCCEEDED", f"tool=sm2decrypt status={r_dec.get('status')} exitCode={r_dec.get('exitCode')}")
        self.assertEqual(self.client.get_artifact(r_dec, "dec.txt"), self.msg)

    def test_02_eckeygen(self):
        """Tool: eckeygen (secp256r1)"""
        r_gen = self.client.execute("eckeygen", {"curve": "secp256r1", "pass": self.passphrase, "out": "ec.pem", "pubout": "ecpub.pem"})
        self.assertEqual(r_gen.get("status"), "SUCCEEDED", f"tool=eckeygen status={r_gen.get('status')} exitCode={r_gen.get('exitCode')}")
        ec_key = self.client.get_artifact(r_gen, "ec.pem")
        ec_pub = self.client.get_artifact(r_gen, "ecpub.pem")
        self.assertIn(b"ENCRYPTED PRIVATE KEY", ec_key)
        self.assertIn(b"PUBLIC KEY", ec_pub)

    def test_03_sm2exch_four_stages(self):
        """Tool: sm2exch (init -> respond -> confirm -> finish full 4-stage agreement)"""
        # Alice key
        r_a = self.client.execute("sm2keygen", {"pass": self.passphrase, "out": "a.pem", "pubout": "a_pub.pem"})
        a_key = self.client.get_artifact(r_a, "a.pem")
        a_pub = self.client.get_artifact(r_a, "a_pub.pem")

        # Bob key
        r_b = self.client.execute("sm2keygen", {"pass": self.passphrase, "out": "b.pem", "pubout": "b_pub.pem"})
        b_key = self.client.get_artifact(r_b, "b.pem")
        b_pub = self.client.get_artifact(r_b, "b_pub.pem")

        # Stage 1: Alice Init
        r_init = self.client.execute(
            "sm2exch",
            {"stage": "init", "exch_keyout": "alice_ra.pem", "exch_pass": self.passphrase, "out": "ra.bin"},
        )
        self.assertEqual(r_init.get("status"), "SUCCEEDED", f"tool=sm2exch init status={r_init.get('status')} exitCode={r_init.get('exitCode')}")
        alice_ra = self.client.get_artifact(r_init, "alice_ra.pem")
        ra_bin = self.client.get_artifact(r_init, "ra.bin")

        # Stage 2: Bob Respond
        r_resp = self.client.execute(
            "sm2exch",
            {
                "stage": "respond",
                "id": "Bob",
                "peer_id": "Alice",
                "key": "input:b_key",
                "pass": self.passphrase,
                "peer_pubkey": "input:a_pub",
                "in": "input:ra_bin",
                "exch_keyout": "bob_rb.pem",
                "exch_pass": self.passphrase,
                "secret_state_out": "bob_state.bin",
                "out": "rb_sb.bin",
            },
            inputs={"b_key": b_key, "a_pub": a_pub, "ra_bin": ra_bin},
        )
        self.assertEqual(r_resp.get("status"), "SUCCEEDED", f"tool=sm2exch resp status={r_resp.get('status')} exitCode={r_resp.get('exitCode')}")
        bob_rb = self.client.get_artifact(r_resp, "bob_rb.pem")
        bob_state = self.client.get_artifact(r_resp, "bob_state.bin")
        rb_sb = self.client.get_artifact(r_resp, "rb_sb.bin")

        # Stage 3: Alice Confirm
        r_conf = self.client.execute(
            "sm2exch",
            {
                "stage": "confirm",
                "id": "Alice",
                "peer_id": "Bob",
                "key": "input:a_key",
                "pass": self.passphrase,
                "peer_pubkey": "input:b_pub",
                "exch_key": "input:alice_ra",
                "exch_pass": self.passphrase,
                "in": "input:rb_sb",
                "keylen": 48,
                "keyout": "alice_key.bin",
                "secret_state_out": "alice_state.bin",
                "out": "sa.bin",
            },
            inputs={"a_key": a_key, "b_pub": b_pub, "alice_ra": alice_ra, "rb_sb": rb_sb},
        )
        self.assertEqual(r_conf.get("status"), "SUCCEEDED", f"tool=sm2exch conf status={r_conf.get('status')} exitCode={r_conf.get('exitCode')}")
        alice_key_bin = self.client.get_artifact(r_conf, "alice_key.bin")
        alice_state = self.client.get_artifact(r_conf, "alice_state.bin")
        sa_bin = self.client.get_artifact(r_conf, "sa.bin")

        # Stage 4: Bob Finish
        r_fin = self.client.execute(
            "sm2exch",
            {
                "stage": "finish",
                "id": "Bob",
                "peer_id": "Alice",
                "key": "input:b_key",
                "pass": self.passphrase,
                "peer_pubkey": "input:a_pub",
                "exch_key": "input:bob_rb",
                "exch_pass": self.passphrase,
                "secret_state": "input:bob_state",
                "in": "input:sa_bin",
                "keylen": 48,
                "keyout": "bob_key.bin",
            },
            inputs={"b_key": b_key, "a_pub": a_pub, "bob_rb": bob_rb, "bob_state": bob_state, "sa_bin": sa_bin},
        )
        self.assertEqual(r_fin.get("status"), "SUCCEEDED", f"tool=sm2exch fin status={r_fin.get('status')} exitCode={r_fin.get('exitCode')}")
        bob_key_bin = self.client.get_artifact(r_fin, "bob_key.bin")

        self.assertEqual(alice_key_bin, bob_key_bin)
        self.assertEqual(alice_state, bob_state)
        self.assertEqual(len(alice_key_bin), 96)

    def test_04_sm9_sign_and_encrypt_workflows(self):
        """Tools: sm9setup, sm9keygen, sm9sign, sm9verify, sm9encrypt, sm9decrypt"""
        # 1. Sign workflow
        r_setup_s = self.client.execute("sm9setup", {"alg": "sm9sign", "pass": self.passphrase, "out": "sm9_s_msk.pem", "pubout": "sm9_s_mpk.pem"})
        self.assertEqual(r_setup_s.get("status"), "SUCCEEDED", f"tool=sm9setup sign status={r_setup_s.get('status')} exitCode={r_setup_s.get('exitCode')}")
        s_msk = self.client.get_artifact(r_setup_s, "sm9_s_msk.pem")
        s_mpk = self.client.get_artifact(r_setup_s, "sm9_s_mpk.pem")

        r_key_s = self.client.execute(
            "sm9keygen",
            {"alg": "sm9sign", "in": "input:msk", "inpass": self.passphrase, "id": "Alice", "out": "sm9_s_key.pem", "outpass": self.user_pass},
            inputs={"msk": s_msk},
        )
        self.assertEqual(r_key_s.get("status"), "SUCCEEDED", f"tool=sm9keygen sign status={r_key_s.get('status')} exitCode={r_key_s.get('exitCode')}")
        s_key = self.client.get_artifact(r_key_s, "sm9_s_key.pem")

        r_sign = self.client.execute(
            "sm9sign",
            {"key": "input:key", "pass": self.user_pass, "in": "input:msg", "out": "sm9.sig"},
            inputs={"key": s_key, "msg": self.msg},
        )
        self.assertEqual(r_sign.get("status"), "SUCCEEDED", f"tool=sm9sign status={r_sign.get('status')} exitCode={r_sign.get('exitCode')}")
        sig = self.client.get_artifact(r_sign, "sm9.sig")

        r_vrf = self.client.execute(
            "sm9verify",
            {"pubmaster": "input:mpk", "id": "Alice", "in": "input:msg", "sig": "input:sig"},
            inputs={"mpk": s_mpk, "msg": self.msg, "sig": sig},
        )
        self.assertEqual(r_vrf.get("status"), "SUCCEEDED", f"tool=sm9verify status={r_vrf.get('status')} exitCode={r_vrf.get('exitCode')}")

        # 2. Encrypt workflow
        r_setup_e = self.client.execute("sm9setup", {"alg": "sm9encrypt", "pass": self.passphrase, "out": "sm9_e_msk.pem", "pubout": "sm9_e_mpk.pem"})
        self.assertEqual(r_setup_e.get("status"), "SUCCEEDED", f"tool=sm9setup enc status={r_setup_e.get('status')} exitCode={r_setup_e.get('exitCode')}")
        e_msk = self.client.get_artifact(r_setup_e, "sm9_e_msk.pem")
        e_mpk = self.client.get_artifact(r_setup_e, "sm9_e_mpk.pem")

        r_key_e = self.client.execute(
            "sm9keygen",
            {"alg": "sm9encrypt", "in": "input:msk", "inpass": self.passphrase, "id": "Bob", "out": "sm9_e_key.pem", "outpass": self.user_pass},
            inputs={"msk": e_msk},
        )
        self.assertEqual(r_key_e.get("status"), "SUCCEEDED", f"tool=sm9keygen enc status={r_key_e.get('status')} exitCode={r_key_e.get('exitCode')}")
        e_key = self.client.get_artifact(r_key_e, "sm9_e_key.pem")

        r_enc = self.client.execute(
            "sm9encrypt",
            {"pubmaster": "input:mpk", "id": "Bob", "in": "input:msg", "out": "sm9.der"},
            inputs={"mpk": e_mpk, "msg": self.msg},
        )
        self.assertEqual(r_enc.get("status"), "SUCCEEDED", f"tool=sm9encrypt status={r_enc.get('status')} exitCode={r_enc.get('exitCode')}")
        cipher = self.client.get_artifact(r_enc, "sm9.der")

        r_dec = self.client.execute(
            "sm9decrypt",
            {"key": "input:key", "pass": self.user_pass, "id": "Bob", "in": "input:cipher", "out": "dec.txt"},
            inputs={"key": e_key, "cipher": cipher},
        )
        self.assertEqual(r_dec.get("status"), "SUCCEEDED", f"tool=sm9decrypt status={r_dec.get('status')} exitCode={r_dec.get('exitCode')}")
        self.assertEqual(self.client.get_artifact(r_dec, "dec.txt"), self.msg)

    def test_05_sm9exch_execution(self):
        """Tool: sm9exch full 4-stage key agreement (init -> respond -> confirm -> finish) and negative tests"""
        # Master encryption keypair (used for sm9keyagreement)
        r_setup_e = self.client.execute("sm9setup", {"alg": "sm9encrypt", "pass": self.passphrase, "out": "sm9_e_msk.pem", "pubout": "sm9_e_mpk.pem"})
        self.assertEqual(r_setup_e.get("status"), "SUCCEEDED", f"tool=sm9setup status={r_setup_e.get('status')} exitCode={r_setup_e.get('exitCode')}")
        e_msk = self.client.get_artifact(r_setup_e, "sm9_e_msk.pem")
        e_mpk = self.client.get_artifact(r_setup_e, "sm9_e_mpk.pem")

        # Alice user key for key agreement
        r_key_a = self.client.execute(
            "sm9keygen",
            {"alg": "sm9keyagreement", "in": "input:msk", "inpass": self.passphrase, "id": "Alice", "out": "sm9_a_key.pem", "outpass": self.user_pass},
            inputs={"msk": e_msk},
        )
        self.assertEqual(r_key_a.get("status"), "SUCCEEDED", f"tool=sm9keygen alice status={r_key_a.get('status')} exitCode={r_key_a.get('exitCode')}")
        alice_key = self.client.get_artifact(r_key_a, "sm9_a_key.pem")

        # Bob user key for key agreement
        r_key_b = self.client.execute(
            "sm9keygen",
            {"alg": "sm9keyagreement", "in": "input:msk", "inpass": self.passphrase, "id": "Bob", "out": "sm9_b_key.pem", "outpass": self.user_pass},
            inputs={"msk": e_msk},
        )
        self.assertEqual(r_key_b.get("status"), "SUCCEEDED", f"tool=sm9keygen bob status={r_key_b.get('status')} exitCode={r_key_b.get('exitCode')}")
        bob_key = self.client.get_artifact(r_key_b, "sm9_b_key.pem")

        # Stage 1: Alice Init
        r_init = self.client.execute(
            "sm9exch",
            {
                "stage": "init",
                "pubmaster": "input:mpk",
                "peer_id": "Bob",
                "exch_keyout": "alice_ra.pem",
                "out": "ra.hex",
            },
            inputs={"mpk": e_mpk},
        )
        self.assertEqual(r_init.get("status"), "SUCCEEDED", f"tool=sm9exch init status={r_init.get('status')} exitCode={r_init.get('exitCode')}")
        alice_ra = self.client.get_artifact(r_init, "alice_ra.pem")
        ra_hex = self.client.get_artifact(r_init, "ra.hex")
        self.assertTrue(alice_ra and ra_hex)

        # Stage 2: Bob Respond
        r_resp = self.client.execute(
            "sm9exch",
            {
                "stage": "respond",
                "pubmaster": "input:mpk",
                "key": "input:bob_key",
                "pass": self.user_pass,
                "id": "Bob",
                "peer_id": "Alice",
                "in": "input:ra_hex",
                "exch_keyout": "bob_rb.pem",
                "out": "rb_sb.hex",
                "keylen": 48,
            },
            inputs={"mpk": e_mpk, "bob_key": bob_key, "ra_hex": ra_hex},
        )
        self.assertEqual(r_resp.get("status"), "SUCCEEDED", f"tool=sm9exch respond status={r_resp.get('status')} exitCode={r_resp.get('exitCode')}")
        bob_rb = self.client.get_artifact(r_resp, "bob_rb.pem")
        rb_sb_hex = self.client.get_artifact(r_resp, "rb_sb.hex")
        self.assertTrue(bob_rb and rb_sb_hex)

        # Stage 3: Alice Confirm
        r_conf = self.client.execute(
            "sm9exch",
            {
                "stage": "confirm",
                "pubmaster": "input:mpk",
                "key": "input:alice_key",
                "pass": self.user_pass,
                "id": "Alice",
                "peer_id": "Bob",
                "exch_key": "input:alice_ra",
                "in": "input:rb_sb_hex",
                "keylen": 48,
                "keyout": "alice_key.hex",
                "out": "sa.hex",
            },
            inputs={"mpk": e_mpk, "alice_key": alice_key, "alice_ra": alice_ra, "rb_sb_hex": rb_sb_hex},
        )
        self.assertEqual(r_conf.get("status"), "SUCCEEDED", f"tool=sm9exch confirm status={r_conf.get('status')} exitCode={r_conf.get('exitCode')}")
        alice_shared_key = self.client.get_artifact(r_conf, "alice_key.hex")
        sa_hex = self.client.get_artifact(r_conf, "sa.hex")
        self.assertTrue(alice_shared_key and sa_hex)

        # Stage 4: Bob Finish
        r_fin = self.client.execute(
            "sm9exch",
            {
                "stage": "finish",
                "pubmaster": "input:mpk",
                "key": "input:bob_key",
                "pass": self.user_pass,
                "id": "Bob",
                "peer_id": "Alice",
                "exch_key": "input:bob_rb",
                "in": "input:sa_hex",
                "keylen": 48,
                "keyout": "bob_key.hex",
            },
            inputs={"mpk": e_mpk, "bob_key": bob_key, "bob_rb": bob_rb, "sa_hex": sa_hex},
        )
        self.assertEqual(r_fin.get("status"), "SUCCEEDED", f"tool=sm9exch finish status={r_fin.get('status')} exitCode={r_fin.get('exitCode')}")
        bob_shared_key = self.client.get_artifact(r_fin, "bob_key.hex")
        self.assertTrue(bob_shared_key)

        # Key Agreement Parity
        self.assertEqual(alice_shared_key, bob_shared_key, "Alice and Bob negotiated shared keys must match")
        self.assertEqual(len(alice_shared_key), 96, "Shared key must be 48 bytes (96 hex characters)")

        # Negative Test 1: Stage Confirm with wrong peer identity
        r_conf_bad_id = self.client.execute(
            "sm9exch",
            {
                "stage": "confirm",
                "pubmaster": "input:mpk",
                "key": "input:alice_key",
                "pass": self.user_pass,
                "id": "Alice",
                "peer_id": "Eve",
                "exch_key": "input:alice_ra",
                "in": "input:rb_sb_hex",
                "keylen": 48,
                "keyout": "alice_bad.hex",
                "out": "sa_bad.hex",
            },
            inputs={"mpk": e_mpk, "alice_key": alice_key, "alice_ra": alice_ra, "rb_sb_hex": rb_sb_hex},
        )
        self.assertTrue(
            r_conf_bad_id.get("status") == "FAILED" or r_conf_bad_id.get("exitCode") != 0,
            f"Stage confirm with wrong peer ID must fail, got: {r_conf_bad_id.get('status')}",
        )

        # Negative Test 2: Stage Finish with tampered confirmation tag (SA)
        tampered_sa = bytearray(sa_hex)
        tampered_sa[0] = ord(b'0' if tampered_sa[0] != ord(b'0') else b'1')
        r_fin_tampered = self.client.execute(
            "sm9exch",
            {
                "stage": "finish",
                "pubmaster": "input:mpk",
                "key": "input:bob_key",
                "pass": self.user_pass,
                "id": "Bob",
                "peer_id": "Alice",
                "exch_key": "input:bob_rb",
                "in": "input:tampered_sa",
                "keylen": 48,
                "keyout": "bob_bad.hex",
            },
            inputs={"mpk": e_mpk, "bob_key": bob_key, "bob_rb": bob_rb, "tampered_sa": bytes(tampered_sa)},
        )
        self.assertTrue(
            r_fin_tampered.get("status") == "FAILED" or r_fin_tampered.get("exitCode") != 0,
            f"Stage finish with tampered confirmation token must fail, got: {r_fin_tampered.get('status')}",
        )


if __name__ == "__main__":
    unittest.main()
