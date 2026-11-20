#!/usr/bin/env python3
"""Apply minimal, explicit source overlays to GmSSL build directory.

Preserves the pristine upstream checkout unmodified.
Computes sha256 of originals, verifies unique replacement anchors, writes
derived files into build/generated/, and emits a machine-readable manifest and diff.
"""

import difflib
import hashlib
import json
import os
import pathlib
import sys

OVERLAYS = [
    {
        "id": "TLS_UINT64_TO_BYTES_POINTER_ADVANCE",
        "description": "Fix missing *out += 8 in tls_uint64_to_bytes() which corrupted serialized SCT timestamp and signed data (RFC 6962)",
        "source_rel": "src/tls.c",
        "expected_sha256": "6ef89c7a12c8661c7c8beb1c07c9e0dd26e5d4ded878d556fa3ad836e6b9f6b0",
        "replacements": [
            (
                "void tls_uint64_to_bytes(uint64_t a, uint8_t **out, size_t *outlen)\n{\n\tif (out && *out) {\n\t\tPUTU64(*out, a);\n\t}\n\t(*outlen) += 8;\n}",
                "void tls_uint64_to_bytes(uint64_t a, uint8_t **out, size_t *outlen)\n{\n\tif (out && *out) {\n\t\tPUTU64(*out, a);\n\t\t*out += 8;\n\t}\n\t(*outlen) += 8;\n}"
            )
        ]
    },
    {
        "id": "X509_TIME_FROM_DER_DEFAULT_SENTINEL",
        "description": "Set *tv = -1 on unrecognized/optional tag in x509_time_from_der to avoid uninitialized stack garbage in callers",
        "source_rel": "src/x509_cer.c",
        "expected_sha256": "b3fa70bf38c47c8666822d64faae721907237f9f874261434243127e98ca7ae7",
        "replacements": [
            (
                "\tdefault:\n\t\treturn 0;\n\t}\n\treturn 1;\n}",
                "\tdefault:\n\t\tif (tv) *tv = -1;\n\t\treturn 0;\n\t}\n\treturn 1;\n}"
            )
        ]
    },
    {
        "id": "X509_CRL_GET_DETAILS_INIT_SENTINELS",
        "description": "Initialize tbs structure with -1 / NULL / 0 sentinels in x509_crl_get_details so missing optional next_update is not uninitialized stack garbage",
        "source_rel": "src/x509_crl.c",
        "expected_sha256": "53f8cb3c44ac501448f8d871ebe8d3e6d8bc217688813dcda2212ce3438c23be",
        "replacements": [
            (
                "\tstruct {\n\t\tint version;\n\t\tint sig_alg;\n\t\tconst uint8_t *issuer; size_t issuer_len;\n\t\ttime_t this_update; time_t next_update;\n\t\tconst uint8_t *revoked_certs; size_t revoked_certs_len;\n\t\tconst uint8_t *exts; size_t exts_len;\n\t} tbs;\n",
                "\tstruct {\n\t\tint version;\n\t\tint sig_alg;\n\t\tconst uint8_t *issuer; size_t issuer_len;\n\t\ttime_t this_update; time_t next_update;\n\t\tconst uint8_t *revoked_certs; size_t revoked_certs_len;\n\t\tconst uint8_t *exts; size_t exts_len;\n\t} tbs = {\n\t\t.version = -1,\n\t\t.sig_alg = -1,\n\t\t.issuer = NULL, .issuer_len = 0,\n\t\t.this_update = -1, .next_update = -1,\n\t\t.revoked_certs = NULL, .revoked_certs_len = 0,\n\t\t.exts = NULL, .exts_len = 0\n\t};\n"
            )
        ]
    },
    {
        "id": "SCT_LOG_ID_SPKI_DER_HASH",
        "description": "Compute SCT log_id as SHA256 of DER SubjectPublicKeyInfo per RFC 6962 Section 3.2 (fixed to SHA256 regardless of signature digest)",
        "source_rel": "src/sct.c",
        "expected_sha256": "d63994ccbe1f888f436be740b552b4c86a41bce14e8a75a03991d79f764b636c",
        "replacements": [
            (
                "\tif (x509_public_key_digest_ex(key, digest, dgst, &dgstlen) != 1\n\t\t|| dgstlen != SCT_LOG_ID_SIZE) {\n\t\terror_print();\n\t\treturn -1;\n\t}",
                "\tuint8_t spki_buf[X509_PUBLIC_KEY_INFO_MAX_SIZE];\n\tuint8_t *p_spki = spki_buf;\n\tsize_t spki_len = 0;\n\tDIGEST_CTX dgst_ctx;\n\tif (x509_public_key_info_to_der(key, &p_spki, &spki_len) != 1\n\t\t|| digest_init(&dgst_ctx, DIGEST_sha256()) != 1\n\t\t|| digest_update(&dgst_ctx, spki_buf, spki_len) != 1\n\t\t|| digest_finish(&dgst_ctx, dgst, &dgstlen) != 1\n\t\t|| dgstlen != SCT_LOG_ID_SIZE) {\n\t\terror_print();\n\t\treturn -1;\n\t}"
            )
        ]
    },
    {
        "id": "SCTVERIFY_LOG_ID_SPKI_DER_HASH",
        "description": "Compute CT log_id as SHA256 of DER SubjectPublicKeyInfo in sctverify CLI per RFC 6962 Section 3.2 (fixed to SHA256 regardless of -digest)",
        "source_rel": "tools/sctverify.c",
        "expected_sha256": "db50f4e8a96c8d6e1244f0cfbd069f34811589580478a514de71d5c5f5db84ba",
        "replacements": [
            (
                "\t\tif (x509_public_key_digest_ex(&ct_logs[i].log_key, digest,\n\t\t\tct_logs[i].log_id, &dgstlen) != 1\n\t\t\t|| dgstlen != SCT_LOG_ID_SIZE) {\n\t\t\tfprintf(stderr, \"%s: compute CT log id failure\\n\", prog);\n\t\t\tgoto end;\n\t\t}",
                "\t\tuint8_t spki_buf[X509_PUBLIC_KEY_INFO_MAX_SIZE];\n\t\tuint8_t *p_spki = spki_buf;\n\t\tsize_t spki_len = 0;\n\t\tDIGEST_CTX dgst_ctx;\n\t\tif (x509_public_key_info_to_der(&ct_logs[i].log_key, &p_spki, &spki_len) != 1\n\t\t\t|| digest_init(&dgst_ctx, DIGEST_sha256()) != 1\n\t\t\t|| digest_update(&dgst_ctx, spki_buf, spki_len) != 1\n\t\t\t|| digest_finish(&dgst_ctx, ct_logs[i].log_id, &dgstlen) != 1\n\t\t\t|| dgstlen != SCT_LOG_ID_SIZE) {\n\t\t\tfprintf(stderr, \"%s: compute CT log id failure\\n\", prog);\n\t\t\tgoto end;\n\t\t}"
            )
        ]
    }
]


SAN_HELPERS = r'''
#include <arpa/inet.h>
#include <gmssl/asn1.h>
#include <gmssl/x509_ext.h>

#define TOOL_SAN_MAX_COUNT 64
static int tool_san_add(uint8_t *out, size_t *outlen, size_t maxlen,
    size_t *count, int choice, const uint8_t *data, size_t len)
{
    size_t i;
    if (*count >= TOOL_SAN_MAX_COUNT) return -1;
    if (choice == X509_gn_dns_name) {
        if (!len || len > 253) return -1;
        for (i = 0; i < len; i++) {
            if (!((data[i] >= 'a' && data[i] <= 'z')
                || (data[i] >= 'A' && data[i] <= 'Z')
                || (data[i] >= '0' && data[i] <= '9')
                || data[i] == '-' || data[i] == '.' || data[i] == '*')) return -1;
        }
    } else if (choice != X509_gn_ip_address || (len != 4 && len != 16)) return -1;
    if (x509_general_names_add_general_name(out, outlen, maxlen, choice, data, len) != 1) return -1;
    (*count)++;
    return 1;
}

static int tool_san_ip(uint8_t *out, size_t *outlen, size_t maxlen,
    size_t *count, const char *literal)
{
    uint8_t ip[16];
    size_t len;
    if (!*literal || strspn(literal, "0123456789abcdefABCDEF:.") != strlen(literal)) return -1;
    if (inet_pton(AF_INET, literal, ip) == 1) len = 4;
    else if (inet_pton(AF_INET6, literal, ip) == 1) len = 16;
    else return -1;
    return tool_san_add(out, outlen, maxlen, count, X509_gn_ip_address, ip, len);
}
'''

CSR_ENCODE = r'''
static int tool_san_attrs(uint8_t *attrs, size_t *attrslen, size_t maxlen,
    const uint8_t *san, size_t sanlen)
{
    static const uint32_t oid[] = {1,2,840,113549,1,9,14};
    uint8_t exts[2112];
    uint8_t *p = attrs;
    size_t extslen = 0, seq_len = 0, set_len = 0, oid_len = 0, total = 0;
    if (x509_exts_add_subject_alt_name(exts, &extslen, sizeof(exts), -1, san, sanlen) != 1
        || asn1_sequence_to_der(exts, extslen, NULL, &seq_len) != 1
        || asn1_set_header_to_der(seq_len, NULL, &set_len) != 1
        || asn1_object_identifier_to_der(oid, 7, NULL, &oid_len) != 1) return -1;
    set_len += seq_len;
    if (asn1_sequence_header_to_der(oid_len + set_len, NULL, &total) != 1) return -1;
    total += oid_len + set_len;
    if (total > maxlen) return -1;
    *attrslen = 0;
    if (asn1_sequence_header_to_der(oid_len + set_len, &p, attrslen) != 1
        || asn1_object_identifier_to_der(oid, 7, &p, attrslen) != 1
        || asn1_set_header_to_der(seq_len, &p, attrslen) != 1
        || asn1_sequence_to_der(exts, extslen, &p, attrslen) != 1) return -1;
    return 1;
}
'''

CSR_DECODE = r'''
static int tool_csr_san(const uint8_t *attrs, size_t attrslen,
    uint8_t *san, size_t *sanlen, size_t maxlen)
{
    static const uint32_t oid[] = {1,2,840,113549,1,9,14};
    const uint8_t *a, *values, *exts, *val, *names, *name;
    size_t alen, valueslen, extslen, vlen, nameslen, namelen, count = 0, nodescnt;
    uint32_t nodes[32];
    int found_request = 0, found_san = 0, ext_id, critical, choice;
    while (attrslen) {
        if (asn1_sequence_from_der(&a, &alen, &attrs, &attrslen) != 1
            || asn1_object_identifier_from_der(nodes, &nodescnt, &a, &alen) != 1
            || asn1_set_from_der(&values, &valueslen, &a, &alen) != 1 || alen) return -1;
        if (nodescnt != 7 || memcmp(nodes, oid, sizeof(oid))) continue;
        if (found_request++) return -1;
        if (asn1_sequence_from_der(&exts, &extslen, &values, &valueslen) != 1 || valueslen) return -1;
        while (extslen) {
            if (x509_ext_from_der(&ext_id, nodes, &nodescnt, &critical, &val, &vlen,
                &exts, &extslen) != 1) return -1;
            /* Only reviewed DNS/IP SAN is inherited; never copy CA or key usages. */
            if (ext_id != OID_ce_subject_alt_name) continue;
            if (found_san++) return -1;
            if (asn1_sequence_from_der(&names, &nameslen, &val, &vlen) != 1 || vlen || !nameslen) return -1;
            while (nameslen) {
                if (x509_general_name_from_der(&choice, &name, &namelen, &names, &nameslen) != 1
                    || tool_san_add(san, sanlen, maxlen, &count, choice, name, namelen) != 1) return -1;
            }
        }
    }
    return 1;
}
'''

SAN_BRANCH = r'''		} else if (!strcmp(*argv, "-subject_ip")) {
			if (--argc < 1) goto bad;
			str = *(++argv);
			if (tool_san_ip(subject_alt_name, &subject_alt_name_len, sizeof(subject_alt_name),
				&subject_alt_name_count, str) != 1) {
				fprintf(stderr, "%s: invalid IP literal or SAN limit exceeded\n", prog);
				goto end;
			}
'''
DNS_BRANCH = r'''		} else if (!strcmp(*argv, "-subject_dns_name")) {
			if (--argc < 1) goto bad;
			str = *(++argv);
			if (tool_san_add(subject_alt_name, &subject_alt_name_len, sizeof(subject_alt_name),
				&subject_alt_name_count, X509_gn_dns_name, (const uint8_t *)str, strlen(str)) != 1) {
				fprintf(stderr, "%s: invalid DNS name or SAN limit exceeded\n", prog);
				goto end;
			}
'''


def certificate_overlays():
    result = []
    digests = {
        'certgen': '4a8c9bb4f16c28b8e0affa6bad65060f1d9f45d9a6d910978475c63e502f75ce',
        'reqgen': '2c3361149f0ae5c0597303d0ff22acafa8190743e46642095388eb8722241c6e',
        'reqsign': '89a3123e652073f7d02bc97dfc01d7edffe63bbdc7425805d5f06313a7d575e1',
    }
    for command, digest in digests.items():
        helpers = SAN_HELPERS + (CSR_ENCODE if command == 'reqgen' else CSR_DECODE if command == 'reqsign' else '')
        replacements = [('#include "passwd.h"', '#include "passwd.h"\n' + helpers)]
        if command == 'reqgen':
            replacements += [
                ('\tuint8_t attrs[512];', '\tuint8_t subject_alt_name[2048];\n\tsize_t subject_alt_name_len = 0;\n\tsize_t subject_alt_name_count = 0;\n\tuint8_t attrs[2304];'),
                ('\tuint8_t req[1024];', '\tuint8_t req[8192];'),
                ('\t\t} else if (!strcmp(*argv, "-key")) {', DNS_BRANCH + SAN_BRANCH + '\t\t} else if (!strcmp(*argv, "-key")) {'),
                ('\t" [-out pem]";', '\t" [-subject_dns_name str]* [-subject_ip str]*"\n\t" [-out pem]";'),
                ('"    -CN str                      Common name\\n"', '"    -CN str                      Common name\\n"\n"    -subject_dns_name str        Request DNS SAN (repeatable, max 64 SANs)\\n"\n"    -subject_ip str              Request IPv4/IPv6 SAN (repeatable)\\n"'),
                ('\tif (x509_req_sign_to_der(', '\tif (subject_alt_name_len && tool_san_attrs(attrs, &attrs_len, sizeof(attrs),\n\t\tsubject_alt_name, subject_alt_name_len) != 1) {\n\t\tfprintf(stderr, "%s: SAN attribute encoding failure\\n", prog);\n\t\tgoto end;\n\t}\n\n\tif (x509_req_sign_to_der('),
            ]
        else:
            replacements += [
                ('\tsize_t subject_alt_name_len = 0;', '\tsize_t subject_alt_name_len = 0;\n\tsize_t subject_alt_name_count = 0;'),
                ('\t" [-subject_dns_name str]*"', '\t" [-subject_dns_name str]* [-subject_ip str]*"'),
                ('"    -subject_dns_name str        Add DNS name to SubjectAltName extension\\n"', '"    -subject_dns_name str        Add DNS name to SubjectAltName extension\\n"\n"    -subject_ip str              Add IPv4/IPv6 SAN (repeatable, max 64 SANs)\\n"'),
                ('\t\t\tif (x509_general_names_add_dns_name(\n\t\t\t\tsubject_alt_name, &subject_alt_name_len, sizeof(subject_alt_name), str) != 1) {', '\t\t\tif (tool_san_add(subject_alt_name, &subject_alt_name_len, sizeof(subject_alt_name),\n\t\t\t\t&subject_alt_name_count, X509_gn_dns_name, (const uint8_t *)str, strlen(str)) != 1) {'),
                ('\t\t} else if (!strcmp(*argv, "-issuer_dns_name")) {', SAN_BRANCH + '\t\t} else if (!strcmp(*argv, "-issuer_dns_name")) {'),
            ]
            if command == 'reqsign':
                replacements += [
                    ('\tuint8_t req[512];', '\tuint8_t req[8192];\n\tconst uint8_t *req_attrs;\n\tsize_t req_attrs_len;\n\tuint8_t requested_san[2048];\n\tsize_t requested_san_len = 0;'),
                    ('\t\tNULL, NULL, NULL, NULL, NULL) != 1) {', '\t\t&req_attrs, &req_attrs_len, NULL, NULL, NULL) != 1) {'),
                    ('\tif (x509_cert_get_subject(cacert,', '\tif (tool_csr_san(req_attrs, req_attrs_len, requested_san, &requested_san_len, sizeof(requested_san)) != 1) {\n\t\tfprintf(stderr, "%s: invalid CSR SAN extension request\\n", prog);\n\t\tgoto end;\n\t}\n\tif (!subject_alt_name_len && requested_san_len) {\n\t\tmemcpy(subject_alt_name, requested_san, requested_san_len);\n\t\tsubject_alt_name_len = requested_san_len;\n\t}\n\n\tif (x509_cert_get_subject(cacert,'),
                ]
        if command == 'reqgen':
            signing_call = "\tif (x509_req_sign_to_der(\n\t\tX509_version_v1,"
            preflight = r"""	{
		size_t needed = 0;
		if (x509_req_sign_to_der(X509_version_v1, name, namelen, &x509_key,
			attrs, attrs_len, sign_algor, &x509_key, signer_id, signer_id_len,
			NULL, &needed) != 1 || needed > sizeof(req)) {
			fprintf(stderr, "%s: CSR exceeds output buffer capacity\n", prog);
			goto end;
		}
	}
"""
            replacements.append((signing_call, preflight + signing_call))
        result.append({'id': 'CERTIFICATE_SAN_' + command.upper(),
            'description': 'Bounded DNS/IP SAN and PKCS9 extensionRequest; inherit only reviewed SAN after CSR verification',
            'source_rel': 'tools/' + command + '.c', 'expected_sha256': digest, 'replacements': replacements})
    return result


OVERLAYS.extend(certificate_overlays())


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def main():
    if len(sys.argv) < 3:
        print("Usage: apply-overlays.py <upstream_source_dir> <output_generated_dir>", file=sys.stderr)
        sys.exit(1)

    upstream = pathlib.Path(sys.argv[1]).resolve()
    gen_dir = pathlib.Path(sys.argv[2]).resolve()
    gen_dir.mkdir(parents=True, exist_ok=True)

    manifest = {
        "generator": "native/apply-overlays.py",
        "patches": []
    }
    diffs = []

    for item in OVERLAYS:
        src_path = upstream / item["source_rel"]
        if not src_path.is_file():
            print(f"ERROR: missing source file: {src_path}", file=sys.stderr)
            sys.exit(1)

        orig_bytes = src_path.read_bytes()
        orig_sha = sha256_bytes(orig_bytes)
        if orig_sha != item["expected_sha256"]:
            print(f"ERROR: sha256 mismatch for {item['source_rel']}: expected {item['expected_sha256']}, got {orig_sha}", file=sys.stderr)
            sys.exit(1)

        text = orig_bytes.decode("utf-8")
        for old_txt, new_txt in item["replacements"]:
            cnt = text.count(old_txt)
            if cnt != 1:
                print(f"ERROR: replacement text in {item['source_rel']} matched {cnt} times (expected exactly 1)", file=sys.stderr)
                sys.exit(1)
            text = text.replace(old_txt, new_txt, 1)

        out_path = gen_dir / item["source_rel"]
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_bytes = text.encode("utf-8")
        out_path.write_bytes(out_bytes)
        derived_sha = sha256_bytes(out_bytes)

        # Generate unified diff
        orig_lines = orig_bytes.decode("utf-8").splitlines(keepends=True)
        derived_lines = text.splitlines(keepends=True)
        diff = "".join(difflib.unified_diff(
            orig_lines,
            derived_lines,
            fromfile=f"a/{item['source_rel']}",
            tofile=f"b/{item['source_rel']}"
        ))
        diffs.append(diff)

        manifest["patches"].append({
            "id": item["id"],
            "description": item["description"],
            "source_rel": item["source_rel"],
            "original_sha256": orig_sha,
            "derived_sha256": derived_sha,
            "derived_file": str(out_path.relative_to(gen_dir))
        })
        print(f"[apply-overlays] Applied {item['id']} -> {out_path} (orig={orig_sha[:8]}..., derived={derived_sha[:8]}...)")

    manifest_path = gen_dir / "overlays-manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    diff_path = gen_dir / "overlays.diff"
    diff_path.write_text("\n".join(diffs), encoding="utf-8")
    print(f"[apply-overlays] Wrote manifest to {manifest_path} and diff to {diff_path}")


if __name__ == "__main__":
    main()
