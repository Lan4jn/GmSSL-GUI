"""Basic cryptographic toolbox test suite: Random, Digest, MAC, KDF, Symmetric Ciphers.

Covers 19 catalog tools:
- random: rand
- digest: sm3
- mac: sm3_hmac, ghash, sm4_cbc_mac, zuc_128_eia3
- kdf: sm3_pbkdf2
- symmetric: sm4_ecb, sm4_cbc, sm4_ctr, sm4_cfb, sm4_ofb, sm4_ccm, sm4_gcm, sm4_xts, sm4_ff1, zuc, zuc256, zuc_128_eea3
"""

import binascii
import sys
import unittest
from .engine_client import EngineClient


class TestBasicCryptoSuite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = EngineClient()
        cls.plain = b"GmSSL GUI 2026 test vector payload! 0123456789abcdef"
        cls.key16 = "0123456789abcdeffedcba9876543210"
        cls.iv16 = "00112233445566778899aabbccddeeff"

    def test_01_rand(self):
        """[Integrity] Tool: rand (Output Length & Non-Zero Randomness)"""
        res = self.client.execute("rand", {"outlen": 32, "out": "rand.bin"})
        self.assertEqual(res.get("status"), "SUCCEEDED", f"tool=rand status={res.get('status')} exitCode={res.get('exitCode')}")
        blob = self.client.get_artifact(res, "rand.bin")
        self.assertEqual(len(blob), 32)
        self.assertTrue(any(b != 0 for b in blob), "Generated random bytes must not be all zeros")

    def test_02_sm3(self):
        """[KAT] Tool: sm3 (GB/T 32905-2016 / GM/T 0004-2012 standard hash test vector for 'abc')"""
        res = self.client.execute("sm3", {"in_str": "abc"})
        self.assertEqual(res.get("status"), "SUCCEEDED", f"tool=sm3 status={res.get('status')} exitCode={res.get('exitCode')}")
        out = self.client.get_stdout_text(res).strip()
        self.assertIn("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0", out)

    def test_03_sm3_hmac(self):
        """[KAT] Tool: sm3_hmac (Wycheproof / GM/T 0004-2012 HMAC-SM3 standard test vectors)"""
        # Vector 1: empty message
        key1 = "1e225cafb90339bba1b24076d4206c3e79c355805d851682bc818baa4f5a7779"
        res1 = self.client.execute("sm3_hmac", {"key": key1, "in_str": ""})
        self.assertEqual(res1.get("status"), "SUCCEEDED", f"tool=sm3_hmac v1 status={res1.get('status')} exitCode={res1.get('exitCode')}")
        out1 = self.client.get_stdout_text(res1).strip()
        self.assertIn("f9938b1b2515117f25dcd636c9a6a0e7f00bccaf5347e0e0df435cfca736cfc1", out1)

        # Vector 2: 1-byte message 0x77
        key2 = "8159fd15133cd964c9a6964c94f0ea269a806fd9f43f0da58b6cd1b33d189b2a"
        res2 = self.client.execute("sm3_hmac", {"key": key2, "in": "input:msg"}, inputs={"msg": b"\x77"})
        self.assertEqual(res2.get("status"), "SUCCEEDED", f"tool=sm3_hmac v2 status={res2.get('status')} exitCode={res2.get('exitCode')}")
        out2 = self.client.get_stdout_text(res2).strip()
        self.assertIn("51aaf64843b6d2fc7a244ab9cda9b7b57164ce6a865f9808c01931b46195411d", out2)

    def test_04_ghash(self):
        """[KAT] Tool: ghash (NIST SP 800-38D GHASH standard test vector 2)"""
        H = "66e94bd4ef8a2c3b884cfa59ca342b2e"
        C = binascii.unhexlify("0388dace60b6a392f328c2b971b2fe78")
        res = self.client.execute("ghash", {"h": H, "in": "input:c"}, inputs={"c": C})
        self.assertEqual(res.get("status"), "SUCCEEDED", f"tool=ghash status={res.get('status')} exitCode={res.get('exitCode')}")
        out = self.client.get_stdout_text(res).strip()
        self.assertIn("f38cbb1ad69223dcc3457ae5b6b0f885", out)

    def test_05_sm4_cbc_mac(self):
        """[KAT] Tool: sm4_cbc_mac (GB/T 32907-2016 CBC-MAC standard test vector)"""
        res = self.client.execute("sm4_cbc_mac", {"key": self.key16, "in_str": "abc"})
        self.assertEqual(res.get("status"), "SUCCEEDED", f"tool=sm4_cbc_mac status={res.get('status')} exitCode={res.get('exitCode')}")
        out = self.client.get_stdout_text(res).strip()
        self.assertIn("9054fccff72871fdad5202c821dbea05", out)

    def test_06_zuc_128_eia3(self):
        """[KAT] Tool: zuc_128_eia3 (3GPP TS 35.221 / GM/T 0001.2-2012 EIA3 MAC standard test vector)"""
        res = self.client.execute(
            "zuc_128_eia3",
            parameters={
                "key": "00" * 16,
                "count": "00000000",
                "bearer": 0,
                "direction": 0,
                "in": "input:plain",
            },
            inputs={"plain": b"0123456789abcdef"},
        )
        self.assertEqual(res.get("status"), "SUCCEEDED", f"tool=zuc_128_eia3 status={res.get('status')} exitCode={res.get('exitCode')}")
        out = self.client.get_stdout_text(res).strip()
        self.assertIn("b0361765", out)

    def test_07_sm3_pbkdf2(self):
        """[KAT] Tool: sm3_pbkdf2 (RFC 8018 / RFC 2898 PBKDF2 with SM3 standard test vector)"""
        res = self.client.execute(
            "sm3_pbkdf2",
            {
                "pass": "password",
                "salt": "0011223344556677",
                "iter": 10000,
                "outlen": 16,
                "bin": True,
                "out": "kdf.bin",
            },
        )
        self.assertEqual(res.get("status"), "SUCCEEDED", f"tool=sm3_pbkdf2 status={res.get('status')} exitCode={res.get('exitCode')}")
        blob = self.client.get_artifact(res, "kdf.bin")
        self.assertEqual(blob.hex(), "df6b713d38d5a35df6861959e529ed22")

    def test_08_sm4_ecb(self):
        """[Roundtrip] Tool: sm4_ecb (Symmetric Cipher Encrypt + Decrypt full plaintext round-trip)"""
        p = self.plain[:32]
        r1 = self.client.execute("sm4_ecb", {"encrypt": True, "key": self.key16, "in": "input:p", "out": "c.bin"}, inputs={"p": p})
        self.assertEqual(r1.get("status"), "SUCCEEDED", f"tool=sm4_ecb enc status={r1.get('status')} exitCode={r1.get('exitCode')}")
        c = self.client.get_artifact(r1, "c.bin")
        r2 = self.client.execute("sm4_ecb", {"decrypt": True, "key": self.key16, "in": "input:c", "out": "p.bin"}, inputs={"c": c})
        self.assertEqual(r2.get("status"), "SUCCEEDED", f"tool=sm4_ecb dec status={r2.get('status')} exitCode={r2.get('exitCode')}")
        self.assertEqual(self.client.get_artifact(r2, "p.bin"), p)

    def test_09_sm4_cbc(self):
        """[Roundtrip] Tool: sm4_cbc (Symmetric Cipher Encrypt + Decrypt full plaintext round-trip)"""
        p = self.plain[:32]
        r1 = self.client.execute("sm4_cbc", {"encrypt": True, "key": self.key16, "iv": self.iv16, "in": "input:p", "out": "c.bin"}, inputs={"p": p})
        self.assertEqual(r1.get("status"), "SUCCEEDED", f"tool=sm4_cbc enc status={r1.get('status')} exitCode={r1.get('exitCode')}")
        c = self.client.get_artifact(r1, "c.bin")
        r2 = self.client.execute("sm4_cbc", {"decrypt": True, "key": self.key16, "iv": self.iv16, "in": "input:c", "out": "p.bin"}, inputs={"c": c})
        self.assertEqual(r2.get("status"), "SUCCEEDED", f"tool=sm4_cbc dec status={r2.get('status')} exitCode={r2.get('exitCode')}")
        self.assertEqual(self.client.get_artifact(r2, "p.bin"), p)

    def test_10_sm4_ctr(self):
        """[Roundtrip] Tool: sm4_ctr (Symmetric Cipher Encrypt + Decrypt full plaintext round-trip)"""
        p = self.plain[:32]
        r1 = self.client.execute("sm4_ctr", {"encrypt": True, "key": self.key16, "iv": self.iv16, "in": "input:p", "out": "c.bin"}, inputs={"p": p})
        self.assertEqual(r1.get("status"), "SUCCEEDED", f"tool=sm4_ctr enc status={r1.get('status')} exitCode={r1.get('exitCode')}")
        c = self.client.get_artifact(r1, "c.bin")
        r2 = self.client.execute("sm4_ctr", {"decrypt": True, "key": self.key16, "iv": self.iv16, "in": "input:c", "out": "p.bin"}, inputs={"c": c})
        self.assertEqual(r2.get("status"), "SUCCEEDED", f"tool=sm4_ctr dec status={r2.get('status')} exitCode={r2.get('exitCode')}")
        self.assertEqual(self.client.get_artifact(r2, "p.bin"), p)

    def test_11_sm4_cfb(self):
        """[Roundtrip] Tool: sm4_cfb (Symmetric Cipher Encrypt + Decrypt full plaintext round-trip)"""
        p = self.plain[:32]
        r1 = self.client.execute("sm4_cfb", {"encrypt": True, "key": self.key16, "iv": self.iv16, "sbytes": 16, "in": "input:p", "out": "c.bin"}, inputs={"p": p})
        self.assertEqual(r1.get("status"), "SUCCEEDED", f"tool=sm4_cfb enc status={r1.get('status')} exitCode={r1.get('exitCode')}")
        c = self.client.get_artifact(r1, "c.bin")
        r2 = self.client.execute("sm4_cfb", {"decrypt": True, "key": self.key16, "iv": self.iv16, "sbytes": 16, "in": "input:c", "out": "p.bin"}, inputs={"c": c})
        self.assertEqual(r2.get("status"), "SUCCEEDED", f"tool=sm4_cfb dec status={r2.get('status')} exitCode={r2.get('exitCode')}")
        self.assertEqual(self.client.get_artifact(r2, "p.bin"), p)

    def test_12_sm4_ofb(self):
        """[Roundtrip] Tool: sm4_ofb (Symmetric Cipher Encrypt + Decrypt full plaintext round-trip)"""
        p = self.plain[:32]
        r1 = self.client.execute("sm4_ofb", {"encrypt": True, "key": self.key16, "iv": self.iv16, "in": "input:p", "out": "c.bin"}, inputs={"p": p})
        self.assertEqual(r1.get("status"), "SUCCEEDED", f"tool=sm4_ofb enc status={r1.get('status')} exitCode={r1.get('exitCode')}")
        c = self.client.get_artifact(r1, "c.bin")
        r2 = self.client.execute("sm4_ofb", {"decrypt": True, "key": self.key16, "iv": self.iv16, "in": "input:c", "out": "p.bin"}, inputs={"c": c})
        self.assertEqual(r2.get("status"), "SUCCEEDED", f"tool=sm4_ofb dec status={r2.get('status')} exitCode={r2.get('exitCode')}")
        self.assertEqual(self.client.get_artifact(r2, "p.bin"), p)

    def test_13_sm4_ccm(self):
        """[Roundtrip] Tool: sm4_ccm (Symmetric AEAD Encrypt + Decrypt full plaintext round-trip)"""
        p = self.plain[:32]
        iv = "00" * 12
        r1 = self.client.execute("sm4_ccm", {"encrypt": True, "key": self.key16, "iv": iv, "aad_hex": "001122", "taglen": 16, "in": "input:p", "out": "c.bin"}, inputs={"p": p})
        self.assertEqual(r1.get("status"), "SUCCEEDED", f"tool=sm4_ccm enc status={r1.get('status')} exitCode={r1.get('exitCode')}")
        c = self.client.get_artifact(r1, "c.bin")
        r2 = self.client.execute("sm4_ccm", {"decrypt": True, "key": self.key16, "iv": iv, "aad_hex": "001122", "taglen": 16, "in": "input:c", "out": "p.bin"}, inputs={"c": c})
        self.assertEqual(r2.get("status"), "SUCCEEDED", f"tool=sm4_ccm dec status={r2.get('status')} exitCode={r2.get('exitCode')}")
        self.assertEqual(self.client.get_artifact(r2, "p.bin"), p)

    def test_14_sm4_gcm(self):
        """[Roundtrip] Tool: sm4_gcm (Symmetric AEAD Encrypt + Decrypt full plaintext round-trip)"""
        p = self.plain[:32]
        iv = "00" * 12
        r1 = self.client.execute("sm4_gcm", {"encrypt": True, "key": self.key16, "iv": iv, "aad_hex": "001122", "taglen": 16, "in": "input:p", "out": "c.bin"}, inputs={"p": p})
        self.assertEqual(r1.get("status"), "SUCCEEDED", f"tool=sm4_gcm enc status={r1.get('status')} exitCode={r1.get('exitCode')}")
        c = self.client.get_artifact(r1, "c.bin")
        r2 = self.client.execute("sm4_gcm", {"decrypt": True, "key": self.key16, "iv": iv, "aad_hex": "001122", "taglen": 16, "in": "input:c", "out": "p.bin"}, inputs={"c": c})
        self.assertEqual(r2.get("status"), "SUCCEEDED", f"tool=sm4_gcm dec status={r2.get('status')} exitCode={r2.get('exitCode')}")
        self.assertEqual(self.client.get_artifact(r2, "p.bin"), p)

    def test_15_sm4_xts(self):
        """[Roundtrip] Tool: sm4_xts (Symmetric XTS Encrypt + Decrypt full plaintext round-trip)"""
        p = self.plain[:32]
        key32 = "0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff"
        r1 = self.client.execute("sm4_xts", {"encrypt": True, "key": key32, "iv": self.iv16, "data_unit_size": 32, "in": "input:p", "out": "c.bin"}, inputs={"p": p})
        self.assertEqual(r1.get("status"), "SUCCEEDED", f"tool=sm4_xts enc status={r1.get('status')} exitCode={r1.get('exitCode')}")
        c = self.client.get_artifact(r1, "c.bin")
        r2 = self.client.execute("sm4_xts", {"decrypt": True, "key": key32, "iv": self.iv16, "data_unit_size": 32, "in": "input:c", "out": "p.bin"}, inputs={"c": c})
        self.assertEqual(r2.get("status"), "SUCCEEDED", f"tool=sm4_xts dec status={r2.get('status')} exitCode={r2.get('exitCode')}")
        self.assertEqual(self.client.get_artifact(r2, "p.bin"), p)

    def test_16_sm4_ff1(self):
        """[KAT] Tool: sm4_ff1 (NIST SP 800-38G FF1 Format-Preserving Encryption standard test vector)"""
        ff1_key = "2b7e151628aed2a6abf7158809cf4f3c"
        tweak = "39383736353433323130"
        digits = "6226090102675688"
        r1 = self.client.execute("sm4_ff1", {"encrypt": True, "key": ff1_key, "tweak": tweak, "digits": digits})
        self.assertEqual(r1.get("status"), "SUCCEEDED", f"tool=sm4_ff1 enc status={r1.get('status')} exitCode={r1.get('exitCode')}")
        c_digits = self.client.get_stdout_text(r1).strip()
        self.assertIn("2326982895499381", c_digits)

        r2 = self.client.execute("sm4_ff1", {"decrypt": True, "key": ff1_key, "tweak": tweak, "digits": "2326982895499381"})
        self.assertEqual(r2.get("status"), "SUCCEEDED", f"tool=sm4_ff1 dec status={r2.get('status')} exitCode={r2.get('exitCode')}")
        p_digits = self.client.get_stdout_text(r2).strip()
        self.assertIn("6226090102675688", p_digits)

    def test_17_zuc(self):
        """[KAT & Roundtrip] Tool: zuc (GM/T 0001.1-2012 Appendix A.1 Test Vector & Stream Round-Trip)"""
        zero8 = b"\x00" * 8
        key = "00" * 16
        iv = "00" * 16
        r1 = self.client.execute("zuc", {"key": key, "iv": iv, "in": "input:p", "out": "c.bin"}, inputs={"p": zero8})
        self.assertEqual(r1.get("status"), "SUCCEEDED", f"tool=zuc enc status={r1.get('status')} exitCode={r1.get('exitCode')}")
        c = self.client.get_artifact(r1, "c.bin")
        self.assertEqual(c.hex(), "27bede74018082da")

        r2 = self.client.execute("zuc", {"key": key, "iv": iv, "in": "input:c", "out": "p.bin"}, inputs={"c": c})
        self.assertEqual(r2.get("status"), "SUCCEEDED", f"tool=zuc dec status={r2.get('status')} exitCode={r2.get('exitCode')}")
        self.assertEqual(self.client.get_artifact(r2, "p.bin"), zero8)

    def test_18_zuc256(self):
        """[Roundtrip] Tool: zuc256 (ZUC-256 stream cipher round-trip)"""
        p = self.plain[:16]
        key = "00" * 32
        iv = "00" * 23
        r1 = self.client.execute("zuc256", {"key": key, "iv": iv, "in": "input:p", "out": "c.bin"}, inputs={"p": p})
        self.assertEqual(r1.get("status"), "SUCCEEDED", f"tool=zuc256 enc status={r1.get('status')} exitCode={r1.get('exitCode')}")
        c = self.client.get_artifact(r1, "c.bin")
        self.assertEqual(len(c), 16)

        r2 = self.client.execute("zuc256", {"key": key, "iv": iv, "in": "input:c", "out": "p.bin"}, inputs={"c": c})
        self.assertEqual(r2.get("status"), "SUCCEEDED", f"tool=zuc256 dec status={r2.get('status')} exitCode={r2.get('exitCode')}")
        self.assertEqual(self.client.get_artifact(r2, "p.bin"), p)

    def test_19_zuc_128_eea3(self):
        """[Roundtrip] Tool: zuc_128_eea3 (3GPP TS 35.221 / GM/T 0001.2-2012 EEA3 encryption round-trip)"""
        p = self.plain[:16]
        params = {
            "key": "173d14ba5003731d7a60049470f00a29",
            "count": "66035492",
            "bearer": 15,
            "direction": 0,
            "in": "input:p",
            "out": "c.bin",
        }
        r1 = self.client.execute("zuc_128_eea3", params, inputs={"p": p})
        self.assertEqual(r1.get("status"), "SUCCEEDED", f"tool=zuc_128_eea3 enc status={r1.get('status')} exitCode={r1.get('exitCode')}")
        c = self.client.get_artifact(r1, "c.bin")

        p2_params = dict(params)
        p2_params["in"] = "input:c"
        p2_params["out"] = "p.bin"
        r2 = self.client.execute("zuc_128_eea3", p2_params, inputs={"c": c})
        self.assertEqual(r2.get("status"), "SUCCEEDED", f"tool=zuc_128_eea3 dec status={r2.get('status')} exitCode={r2.get('exitCode')}")
        self.assertEqual(self.client.get_artifact(r2, "p.bin"), p)


if __name__ == "__main__":
    unittest.main()
