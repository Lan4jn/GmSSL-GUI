"""Post-Quantum Cryptography (PQC) toolbox test suite.

Covers 18 catalog tools across 6 algorithm families:
- LMS: lmskeygen, lmssign, lmsverify
- HSS: hsskeygen, hsssign, hssverify
- XMSS: xmsskeygen, xmsssign, xmssverify
- XMSS^MT: xmssmtkeygen, xmssmtsign, xmssmtverify
- SPHINCS+: sphincskeygen, sphincssign, sphincsverify
- Kyber (ML-KEM): kyberkeygen, kyberencap, kyberdecap
"""

import unittest
from .engine_client import EngineClient


class TestPQCSuite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = EngineClient()
        cls.msg = b"PQC authentication test message - GmSSL GUI 2026"

    def test_01_lms_workflow(self):
        """Tools: lmskeygen, lmssign, lmsverify"""
        # Keygen
        r_gen = self.client.execute("lmskeygen", {"lms_type": "LMS_SM3_M32_H5", "out": "lms.pem", "pubout": "lmspub.pem"})
        self.assertEqual(r_gen.get("status"), "SUCCEEDED", f"tool=lmskeygen status={r_gen.get('status')} exitCode={r_gen.get('exitCode')}")
        lms_key = self.client.get_artifact(r_gen, "lms.pem")
        lms_pub = self.client.get_artifact(r_gen, "lmspub.pem")
        self.assertTrue(lms_key and lms_pub)

        # Sign (stateful private key gets updated)
        r_sig = self.client.execute(
            "lmssign",
            {"key": "input:key", "in": "input:msg", "out": "lms.sig"},
            inputs={"key": lms_key, "msg": self.msg},
        )
        self.assertEqual(r_sig.get("status"), "SUCCEEDED", f"tool=lmssign status={r_sig.get('status')} exitCode={r_sig.get('exitCode')}")
        sig = self.client.get_artifact(r_sig, "lms.sig")
        updated_key = self.client.get_updated_input(r_sig, "key")
        self.assertIsNotNone(updated_key, "Stateful LMS key must return updated input")

        # Verify
        r_vrf = self.client.execute(
            "lmsverify",
            {"pubkey": "input:pub", "in": "input:msg", "sig": "input:sig"},
            inputs={"pub": lms_pub, "msg": self.msg, "sig": sig},
        )
        self.assertEqual(r_vrf.get("status"), "SUCCEEDED", f"tool=lmsverify status={r_vrf.get('status')} exitCode={r_vrf.get('exitCode')}")

    def test_02_hss_workflow(self):
        """Tools: hsskeygen, hsssign, hssverify"""
        # Keygen
        r_gen = self.client.execute("hsskeygen", {"lms_types": "LMS_SM3_M32_H5:LMS_SM3_M32_H5", "out": "hss.pem", "pubout": "hsspub.pem"})
        self.assertEqual(r_gen.get("status"), "SUCCEEDED", f"tool=hsskeygen status={r_gen.get('status')} exitCode={r_gen.get('exitCode')}")
        hss_key = self.client.get_artifact(r_gen, "hss.pem")
        hss_pub = self.client.get_artifact(r_gen, "hsspub.pem")

        # Sign
        r_sig = self.client.execute(
            "hsssign",
            {"key": "input:key", "in": "input:msg", "out": "hss.sig"},
            inputs={"key": hss_key, "msg": self.msg},
        )
        self.assertEqual(r_sig.get("status"), "SUCCEEDED", f"tool=hsssign status={r_sig.get('status')} exitCode={r_sig.get('exitCode')}")
        sig = self.client.get_artifact(r_sig, "hss.sig")

        # Verify
        r_vrf = self.client.execute(
            "hssverify",
            {"pubkey": "input:pub", "in": "input:msg", "sig": "input:sig"},
            inputs={"pub": hss_pub, "msg": self.msg, "sig": sig},
        )
        self.assertEqual(r_vrf.get("status"), "SUCCEEDED", f"tool=hssverify status={r_vrf.get('status')} exitCode={r_vrf.get('exitCode')}")

    def test_03_xmss_workflow(self):
        """Tools: xmsskeygen, xmsssign, xmssverify"""
        # Keygen
        r_gen = self.client.execute("xmsskeygen", {"xmss_type": "XMSS_SM3_10_256", "out": "xmss.pem", "pubout": "xmsspub.pem"})
        self.assertEqual(r_gen.get("status"), "SUCCEEDED", f"tool=xmsskeygen status={r_gen.get('status')} exitCode={r_gen.get('exitCode')}")
        xmss_key = self.client.get_artifact(r_gen, "xmss.pem")
        xmss_pub = self.client.get_artifact(r_gen, "xmsspub.pem")

        # Sign
        r_sig = self.client.execute(
            "xmsssign",
            {"key": "input:key", "in": "input:msg", "out": "xmss.sig"},
            inputs={"key": xmss_key, "msg": self.msg},
        )
        self.assertEqual(r_sig.get("status"), "SUCCEEDED", f"tool=xmsssign status={r_sig.get('status')} exitCode={r_sig.get('exitCode')}")
        sig = self.client.get_artifact(r_sig, "xmss.sig")

        # Verify
        r_vrf = self.client.execute(
            "xmssverify",
            {"pubkey": "input:pub", "in": "input:msg", "sig": "input:sig"},
            inputs={"pub": xmss_pub, "msg": self.msg, "sig": sig},
        )
        self.assertEqual(r_vrf.get("status"), "SUCCEEDED", f"tool=xmssverify status={r_vrf.get('status')} exitCode={r_vrf.get('exitCode')}")

    def test_04_xmssmt_workflow(self):
        """Tools: xmssmtkeygen, xmssmtsign, xmssmtverify"""
        # Keygen
        r_gen = self.client.execute("xmssmtkeygen", {"xmssmt_type": "XMSSMT_SM3_20_2_256", "out": "xmssmt.pem", "pubout": "xmssmtpub.pem"})
        self.assertEqual(r_gen.get("status"), "SUCCEEDED", f"tool=xmssmtkeygen status={r_gen.get('status')} exitCode={r_gen.get('exitCode')}")
        xmssmt_key = self.client.get_artifact(r_gen, "xmssmt.pem")
        xmssmt_pub = self.client.get_artifact(r_gen, "xmssmtpub.pem")

        # Sign
        r_sig = self.client.execute(
            "xmssmtsign",
            {"key": "input:key", "in": "input:msg", "out": "xmssmt.sig"},
            inputs={"key": xmssmt_key, "msg": self.msg},
        )
        self.assertEqual(r_sig.get("status"), "SUCCEEDED", f"tool=xmssmtsign status={r_sig.get('status')} exitCode={r_sig.get('exitCode')}")
        sig = self.client.get_artifact(r_sig, "xmssmt.sig")

        # Verify
        r_vrf = self.client.execute(
            "xmssmtverify",
            {"pubkey": "input:pub", "in": "input:msg", "sig": "input:sig"},
            inputs={"pub": xmssmt_pub, "msg": self.msg, "sig": sig},
        )
        self.assertEqual(r_vrf.get("status"), "SUCCEEDED", f"tool=xmssmtverify status={r_vrf.get('status')} exitCode={r_vrf.get('exitCode')}")

    def test_05_sphincs_workflow(self):
        """Tools: sphincskeygen, sphincssign, sphincsverify"""
        # Keygen
        r_gen = self.client.execute("sphincskeygen", {"out": "sphincs.pem", "pubout": "sphincspub.pem"})
        self.assertEqual(r_gen.get("status"), "SUCCEEDED", f"tool=sphincskeygen status={r_gen.get('status')} exitCode={r_gen.get('exitCode')}")
        sphincs_key = self.client.get_artifact(r_gen, "sphincs.pem")
        sphincs_pub = self.client.get_artifact(r_gen, "sphincspub.pem")

        # Sign
        r_sig = self.client.execute(
            "sphincssign",
            {"key": "input:key", "in": "input:msg", "out": "sphincs.sig"},
            inputs={"key": sphincs_key, "msg": self.msg},
        )
        self.assertEqual(r_sig.get("status"), "SUCCEEDED", f"tool=sphincssign status={r_sig.get('status')} exitCode={r_sig.get('exitCode')}")
        sig = self.client.get_artifact(r_sig, "sphincs.sig")

        # Verify
        r_vrf = self.client.execute(
            "sphincsverify",
            {"pubkey": "input:pub", "in": "input:msg", "sig": "input:sig"},
            inputs={"pub": sphincs_pub, "msg": self.msg, "sig": sig},
        )
        self.assertEqual(r_vrf.get("status"), "SUCCEEDED", f"tool=sphincsverify status={r_vrf.get('status')} exitCode={r_vrf.get('exitCode')}")

    def test_06_kyber_workflow(self):
        """Tools: kyberkeygen, kyberencap, kyberdecap"""
        # Keygen
        r_gen = self.client.execute("kyberkeygen", {"out": "kyber.pem", "pubout": "kyberpub.pem"})
        self.assertEqual(r_gen.get("status"), "SUCCEEDED", f"tool=kyberkeygen status={r_gen.get('status')} exitCode={r_gen.get('exitCode')}")
        kyber_key = self.client.get_artifact(r_gen, "kyber.pem")
        kyber_pub = self.client.get_artifact(r_gen, "kyberpub.pem")

        # Encap
        r_enc = self.client.execute(
            "kyberencap",
            {"pubkey": "input:pub", "out": "cipher.bin", "outkey": "secret.bin"},
            inputs={"pub": kyber_pub},
        )
        self.assertEqual(r_enc.get("status"), "SUCCEEDED", f"tool=kyberencap status={r_enc.get('status')} exitCode={r_enc.get('exitCode')}")
        cipher = self.client.get_artifact(r_enc, "cipher.bin")
        secret = self.client.get_artifact(r_enc, "secret.bin")
        self.assertTrue(cipher and secret)

        # Decap
        r_dec = self.client.execute(
            "kyberdecap",
            {"key": "input:key", "in": "input:cipher", "out": "dec_secret.bin"},
            inputs={"key": kyber_key, "cipher": cipher},
        )
        self.assertEqual(r_dec.get("status"), "SUCCEEDED", f"tool=kyberdecap status={r_dec.get('status')} exitCode={r_dec.get('exitCode')}")
        dec_secret = self.client.get_artifact(r_dec, "dec_secret.bin")
        self.assertEqual(secret, dec_secret)


if __name__ == "__main__":
    unittest.main()
