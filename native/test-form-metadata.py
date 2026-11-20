#!/usr/bin/env python3
"""Regression test suite for catalog UX metadata, default values, enums, and credential bindings."""
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
CATALOG_PATH = ROOT / "native/catalog.json"
EXT_PATH = ROOT / "native/extensions-catalog.json"
FORM_META_PATH = ROOT / "native/form-metadata.json"


def test_catalogs():
    print("=== Testing Catalog and Form Metadata Integrity ===")
    assert CATALOG_PATH.exists(), f"Missing {CATALOG_PATH}"
    assert EXT_PATH.exists(), f"Missing {EXT_PATH}"
    assert FORM_META_PATH.exists(), f"Missing {FORM_META_PATH}"

    with open(CATALOG_PATH) as f:
        cat = json.load(f)
    with open(EXT_PATH) as f:
        ext = json.load(f)
    with open(FORM_META_PATH) as f:
        meta = json.load(f)

    tools_cat = cat.get("tools", [])
    tools_ext = ext.get("tools", [])
    all_tools = tools_cat + tools_ext

    print(f"Loaded {len(tools_cat)} base tools + {len(tools_ext)} extension tools = {len(all_tools)} total tools.")
    assert len(tools_cat) == 80, f"Expected 80 upstream tools, got {len(tools_cat)}"
    assert len(tools_ext) == 14, f"Expected 14 extension tools, got {len(tools_ext)}"
    assert len(all_tools) == 94, f"Expected 94 total business tools, got {len(all_tools)}"
    assert meta.get("totalTools") == 94, f"Expected form-metadata to record 94 tools, got {meta.get('totalTools')}"

    expected = {(t['id'], p['name']): p for t in all_tools for p in t['parameters']}
    actual = {(t['id'], p['name']): p for t in meta['tools'] for p in t['parameters']}
    assert actual.keys() == expected.keys(), 'Review matrix inventory drift'
    for key, row in actual.items():
        for field, value in row.items():
            if field != 'classification':
                assert value == expected[key].get(field), (key, field)

    # 1. Security Check: Never assign constant zero IV or nonce as defaultValue
    print("Checking security rule: No static zero IV or nonce defaults...")
    for t in all_tools:
        for p in t.get("parameters", []):
            name = p.get("name", "")
            if name in ("iv", "nonce"):
                assert p.get("defaultValue") is None, (
                    f"Security violation in {t['id']}: parameter {name} has static defaultValue: {p.get('defaultValue')}"
                )
    print(" -> PASSED: No static zero IV/nonce defaults found.")

    # 2. Visibility Check: Mandatory parameters without defaultValue MUST NOT be hidden in advanced
    print("Checking UX rule: Mandatory parameters without default value cannot be advanced...")
    for t in all_tools:
        for p in t.get("parameters", []):
            if p.get("required") and p.get("defaultValue") is None:
                assert not p.get("advanced"), (
                    f"UX violation in {t['id']}: mandatory parameter '{p['name']}' has no default but is marked advanced=True!"
                )
                assert p.get("preferred") is True, (
                    f"UX violation in {t['id']}: mandatory parameter '{p['name']}' should have preferred=True"
                )
    print(" -> PASSED: All mandatory un-defaulted parameters remain visible in quick view.")

    # 3. Credential Key Parameter Binding Check
    print("Checking credential key parameter bindings...")
    secret_key_bindings = {
        "certgen": ("pass", "key"),
        "reqgen": ("pass", "key"),
        "reqsign": ("pass", "key"),
        "crlgen": ("pass", "key"),
        "ocspsign": ("pass", "key"),
        "sm2sign": ("pass", "key"),
        "sm2decrypt": ("pass", "key"),
        "cmsdecrypt": ("pass", "key"),
        "cmssign": ("pass", "key"),
        "sm9sign": ("pass", "key"),
        "sm9decrypt": ("pass", "key"),
        "tlcp_client": ("pass", "key"),
        "tlcp_server": ("pass", "key"),
        "tls12_client": ("pass", "key"),
        "tls12_server": ("pass", "key"),
        "tls13_client": ("pass", "key"),
        "tls13_server": ("pass", "key"),
        "quic_server": ("pass", "key"),
        "api_sm9_kem": ("pass", "key"),
    }
    for tool_id, (pass_name, key_name) in secret_key_bindings.items():
        found_tool = next((x for x in all_tools if x["id"] == tool_id), None)
        assert found_tool is not None, f"Tool {tool_id} not found!"
        pass_param = next((p for p in found_tool["parameters"] if p["name"] == pass_name), None)
        assert pass_param is not None, f"Parameter {pass_name} not found in {tool_id}!"
        assert pass_param.get("credentialKeyParameter") == key_name, (
            f"Binding mismatch in {tool_id}: {pass_name} -> {pass_param.get('credentialKeyParameter')}, expected {key_name}"
        )
    print(" -> PASSED: Verified all required credentialKeyParameter bindings.")

    # 4. Check keygen tools DO NOT mistakenly bind credentialKeyParameter to output files
    print("Checking keygen tools output pass is not misbound to credentialKeyParameter...")
    for t in all_tools:
        if t["id"].endswith("keygen") or t["id"] in ("sm9setup", "rand"):
            for p in t.get("parameters", []):
                if p.get("type") == "SECRET" and p.get("name") in ("pass", "outpass"):
                    assert p.get("credentialKeyParameter") is None, (
                        f"Misbound credentialKeyParameter in keygen tool {t['id']}.{p['name']} -> {p.get('credentialKeyParameter')}"
                    )
    print(" -> PASSED: Keygen tools output passwords are appropriately unbound.")

    # 5. Check Chinese labels quality & context sensitivity
    print("Checking localized labels presence and context sensitivity...")
    labeled_count = 0
    total_params = 0
    for t in all_tools:
        for p in t.get("parameters", []):
            total_params += 1
            lbl = p.get("label")
            assert lbl, f"Missing label in {t['id']}.{p['name']}"
            labeled_count += 1
            # Accurate label check for key
            if p.get("name") == "key":
                if p.get("type") == "HEX":
                    assert "私钥文件" not in lbl, (
                        f"Label error in {t['id']}.key: HEX key labeled as '{lbl}', should be 对称密钥/MAC密钥/私钥标量"
                    )
                elif p.get("type") == "INPUT_FILE":
                    if t["id"] in ("lmssign", "hsssign", "xmsssign", "xmssmtsign"):
                        assert lbl == "有状态私钥文件", f"Expected 有状态私钥文件 in {t['id']}.key, got {lbl}"
                    else:
                        assert "私钥" in lbl or "密钥" in lbl
    assert labeled_count == total_params, f"Only {labeled_count}/{total_params} parameters have labels!"
    print(f" -> PASSED: 100% of {total_params} parameters across 94 tools have valid context-sensitive labels.")

    # 6. Verify evidence-based enums and defaultValue consistency
    print("Checking evidence-based enums and defaultValue consistency...")
    for t in all_tools:
        for p in t.get("parameters", []):
            dv = p.get("defaultValue")
            opts = p.get("options")
            if dv is not None and opts is not None:
                assert dv in opts, (
                    f"Enum default mismatch in {t['id']}.{p['name']}: defaultValue '{dv}' not found in options {opts}"
                )
    print(" -> PASSED: 100% of parameters with default values and options are mutually consistent.")

    eckeygen = next(x for x in all_tools if x["id"] == "eckeygen")
    curve_p = next(p for p in eckeygen["parameters"] if p["name"] == "curve")
    assert curve_p.get("options") == ["secp256r1", "secp384r1"]
    assert curve_p.get("defaultValue") == "secp256r1"

    tlcp_s = next(x for x in all_tools if x["id"] == "tlcp_server")
    cipher_p = next(p for p in tlcp_s["parameters"] if p["name"] == "cipher_suite")
    assert "TLS_ECC_SM4_GCM_SM3" in cipher_p.get("options", [])
    assert cipher_p.get("defaultValue") == "TLS_ECC_SM4_GCM_SM3"

    tls13_c = next(x for x in all_tools if x["id"] == "tls13_client")
    sig_p = next(p for p in tls13_c["parameters"] if p["name"] == "sig_alg")
    assert "sm2sig_sm3" in sig_p.get("options", [])
    assert sig_p.get("defaultValue") == "sm2sig_sm3"

    certgen = next(x for x in all_tools if x["id"] == "certgen")
    sig_p = next(p for p in certgen["parameters"] if p["name"] == "sig_alg")
    assert "sm2sign-with-sm3" in sig_p.get("options", [])
    assert sig_p.get("defaultValue") == "sm2sign-with-sm3"

    for tool_id, expected_algorithms in (
        ('sm9setup', ['sm9sign', 'sm9encrypt']),
        ('sm9keygen', ['sm9sign', 'sm9encrypt', 'sm9keyagreement'])):
        tool = next(t for t in all_tools if t['id'] == tool_id)
        parameter = next(p for p in tool['parameters'] if p['name'] == 'alg')
        assert parameter['options'] == expected_algorithms, (tool_id, parameter['options'])
    print(' -> PASSED: SM9 setup retains two master-key algorithms; keygen retains all three operations.')

    sm9_exchange = next(t for t in all_tools if t['id'] == 'sm9exch')
    assert {p['name'] for p in sm9_exchange['parameters'] if p['required']} == {'stage'}, 'SM9 init must not require a private key or local identity'
    for tool in all_tools:
        for parameter in tool['parameters']:
            if tool['id'].startswith('sm9') and parameter['name'] in ('id', 'peer_id'):
                assert parameter.get('defaultValue') is None, f"{tool['id']}.{parameter['name']} must use the actual SM9 user identity"
    sm2_sign = next(t for t in all_tools if t['id'] == 'sm2sign')
    assert next(p for p in sm2_sign['parameters'] if p['name'] == 'id')['defaultValue'] == '1234567812345678'

    for tool in all_tools:
        if tool['id'].startswith(('quic', 'tls12', 'tls13')):
            group = next(p for p in tool['parameters'] if p['name'] == 'supported_group')
            assert 'prime256v1' in group['options'] and 'secp256r1' not in group['options'], tool['id']
            if tool['id'].startswith('quic'):
                assert group['defaultValue'] == 'prime256v1', tool['id']

    # Full enabled signing families must remain selectable, not just recommendations.
    expected_signatures = {'sm2sign-with-sm3', 'ecdsa-with-sha256', 'ecdsa-with-sha384',
        'ecdsa-with-sha512', 'lms-hashsig', 'hss-lms-hashsig', 'xmss-hashsig',
        'xmssmt-hashsig', 'sphincs-hashsig'}
    for tool in all_tools:
        if tool['id'] in ('certgen', 'reqgen', 'reqsign', 'crlgen', 'ocspsign'):
            parameter = next(p for p in tool['parameters'] if p['name'] == 'sig_alg')
            assert set(parameter['options']) == expected_signatures, tool['id']
        if tool['id'].startswith('tls12'):
            parameter = next(p for p in tool['parameters'] if p['name'] == 'cipher_suite')
            assert 'TLS_ECDHE_ECDSA_WITH_AES_128_CCM' in parameter['options']
        if tool['id'].startswith('tls13'):
            parameter = next(p for p in tool['parameters'] if p['name'] == 'cipher_suite')
            assert {'TLS_SM4_CCM_SM3', 'TLS_AES_128_CCM_SHA256'} <= set(parameter['options'])
        if tool['id'] in ('certgen', 'reqgen', 'reqsign'):
            names = ('subject_ip', 'subject_dns_name')
            for name in names:
                parameter = next(p for p in tool['parameters'] if p['name'] == name)
                assert parameter['type'] == 'STRING' and parameter['repeatable']
                assert parameter.get('defaultValue') is None
    print(' -> PASSED: Full signing/protocol choices and typed SAN metadata remain available.')

    # 7. End-to-End Engine Validation Emulation for Defaults
    print("Checking catalog default smoke with a Python subset of engine cross-field rules...")
    
    def simulate_engine_validation(tool, supplied):
        c = tool["id"]
        v = dict(supplied)
        for p in tool["parameters"]:
            name = p["name"]
            typ = p["type"]
            val = v.get(name)
            if val is None:
                if p.get("required"):
                    raise ValueError(f"Required parameter missing: {name}")
                continue
            # Type and constraints check
            if typ == "INTEGER":
                n = int(val)
                if p.get("min") is not None and n < p["min"]:
                    raise ValueError(f"{name} < min {p['min']}")
                if p.get("max") is not None and n > p["max"]:
                    raise ValueError(f"{name} > max {p['max']}")
            elif typ == "HEX":
                if not isinstance(val, str) or len(val) % 2 != 0:
                    raise ValueError(f"{name} invalid hex: {val}")
            elif typ == "ENUM":
                opts = p.get("options", [])
                if opts and val not in opts and val != p.get("defaultValue"):
                    raise ValueError(f"{name} invalid enum: {val} not in {opts}")
        
        # Cross-field validations mirroring EngineValidator.java
        def exclusive(*names):
            present = [k for k in names if k in v]
            if len(present) > 1:
                raise ValueError(f"Mutually exclusive: {present}")

        exclusive("hex", "bin")
        exclusive("id", "id_hex")
        exclusive("sm2_id", "sm2_id_hex")
        exclusive("in", "in_str")
        exclusive("peer_id", "peer_id_hex")

        if c.startswith("sm4_") and c != "sm4_cbc_mac":
            exclusive("encrypt", "decrypt")
            if "encrypt" not in v and "decrypt" not in v:
                raise ValueError(f"{c}: must specify encrypt or decrypt")

        if c == "api_digest":
            alg = v.get("alg", "")
            if alg.startswith("SHAKE"):
                if "outlen" not in v:
                    raise ValueError("api_digest: SHAKE requires outlen")
            elif "outlen" in v:
                raise ValueError("api_digest: non-SHAKE forbids outlen")

        if c == "api_aes":
            mode = v.get("mode", "")
            if mode.upper() not in ("GCM", "CCM"):
                if "aad" in v or "taglen" in v:
                    raise ValueError(f"api_aes: mode {mode} forbids aad and taglen")
            if mode.upper() == "ECB" and "iv" in v:
                raise ValueError("api_aes: ECB forbids iv")

        if c == "api_sm9_kem":
            op = v.get("op", "")
            if op == "encrypt":
                if "pubmaster" not in v or "cipherout" not in v:
                    raise ValueError("api_sm9_kem encrypt requires pubmaster and cipherout")
            elif op == "decrypt":
                if "key" not in v or "pass" not in v:
                    raise ValueError("api_sm9_kem decrypt requires key and pass")

    # Verify that default parameters for every tool pass engine validation
    for t in all_tools:
        cid = t["id"]
        payload = {}
        for p in t["parameters"]:
            if p.get("defaultValue") is not None:
                payload[p["name"]] = p["defaultValue"]
            elif p.get("required"):
                # Mock required value appropriate to type
                pt = p.get("type")
                pn = p.get("name")
                if pt == "INPUT_FILE":
                    payload[pn] = "input:mock_file"
                elif pt == "OUTPUT_FILE":
                    payload[pn] = f"{cid}_{pn}.bin"
                elif pt == "HEX":
                    payload[pn] = "0123456789abcdef0123456789abcdef"
                elif pt == "SECRET":
                    payload[pn] = "mock_secret_123"
                elif pt == "INTEGER":
                    payload[pn] = p.get("min", 1)
                elif pt == "STRING":
                    payload[pn] = "mock_string"
                elif pt == "ENUM":
                    payload[pn] = p.get("options", ["opt1"])[0]
                elif pt == "BOOLEAN":
                    payload[pn] = True

        # Tool-specific required adjustments for valid mock execution
        if cid == "api_sm9_kem" and payload.get("op") == "encrypt":
            payload["pubmaster"] = "input:pubmaster"
            payload["cipherout"] = "cipherout.bin"

        try:
            simulate_engine_validation(t, payload)
        except Exception as e:
            raise AssertionError(f"Default execution simulation failed for {cid}: {e}")

    # Negative / Specific regression checks:
    # 1. api_aes CBC mode with taglen must FAIL
    try:
        simulate_engine_validation(
            next(t for t in all_tools if t["id"] == "api_aes"),
            {"mode": "cbc", "op": "encrypt", "key": "0123456789abcdef0123456789abcdef", "iv": "0123456789abcdef0123456789abcdef", "taglen": 16}
        )
        raise AssertionError("Expected api_aes with mode=cbc and taglen=16 to fail!")
    except ValueError:
        pass  # Expected failure!

    # 2. api_digest SM3 with outlen must FAIL
    try:
        simulate_engine_validation(
            next(t for t in all_tools if t["id"] == "api_digest"),
            {"alg": "sm3", "outlen": 32}
        )
        raise AssertionError("Expected api_digest with alg=sm3 and outlen=32 to fail!")
    except ValueError:
        pass  # Expected failure!

    # 3. sm4_cbc with both encrypt and decrypt must FAIL
    try:
        simulate_engine_validation(
            next(t for t in all_tools if t["id"] == "sm4_cbc"),
            {"encrypt": True, "decrypt": True, "key": "0123456789abcdef0123456789abcdef", "iv": "0123456789abcdef0123456789abcdef"}
        )
        raise AssertionError("Expected sm4_cbc with both encrypt and decrypt to fail!")
    except ValueError:
        pass  # Expected failure!

    print(" -> PASSED: 94 catalog default payloads passed the Python subset; live Java validation is a separate acceptance.")
    print("\nALL 94 TOOLS METADATA AND CONTRACT TESTS PASSED!")


if __name__ == "__main__":
    test_catalogs()
