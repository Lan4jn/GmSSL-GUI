# Public software API coverage supplement

Baseline: GmSSL `24ae482701a7b124826c382fffc55c19f76d475d` (3.3.0-dev.1183).
This supplements the command inventory; it is **not a claim of complete C API coverage**.
One command can expose multiple algorithms/modes; internal arithmetic, streaming variants,
precomputation, assembly/AVX/CL variants and serialization helpers are not counted as new algorithms.
All code is an original Apache-2.0 adapter using the Apache-2.0 GmSSL headers/library.

## Implemented extension surface (14 commands)

| Command | Real public APIs | Exposed choices / exact constraints |
|---|---|---|
| api_digest | digest.h `digest`; sha3.h `sha3_256/512`, `shake128/256` | sm3, sha1, sha224/256/384/512, sha512-224/256; sha3-256/512; shake128/256. SHAKE requires outlen 1..4096, fixed digests reject outlen. No public SHA3-224/384 implementation in this revision. |
| api_hmac | hmac.h `hmac` | The 8 digest.h algorithms above; HEX key 0..4096 bytes. SHA3/SHAKE lack DIGEST descriptors and are not offered for HMAC. |
| api_hkdf | hkdf.h `hkdf_extract` + `hkdf_expand` | Same 8 digest.h algorithms; input is IKM; salt 0..64 bytes; info 0..4096 bytes; outlen 1..4096 and <=255*digest size; combined extract+expand only. |
| api_pbkdf2 | pbkdf2.h `pbkdf2_hmac_genkey` | Same 8 digests; pass 0..4096 UTF8 bytes, salt 0..64 bytes, iter 1..1,000,000; outlen 1..4096; ceil(outlen/digest_size)*iter <=4,000,000. Low iteration values are exposed for vector reproduction, not a password-storage recommendation. No business stdin. |
| api_sm3_kdf | sm3.h `sm3_kdf_init/update/finish` | Counter KDF, not HKDF. Binary input <=16MiB; outlen 1..4096. |
| api_aes | aes.h set key, encrypt/decrypt, cbc/ctr/gcm/ccm | AES-128/192/256: key 16/24/32 bytes; op encrypt/decrypt. ECB: block aligned, no IV; CBC: IV16, padding none(default) or pkcs7; CTR: IV16, no padding, reject counter overflow. GCM: IV1..32, tag 4/8/12/13/14/15/16; CCM: IV7..13, tag4/6/8/10/12/14/16; CCM IV13 requires payload <65536 bytes. AAD0..4096. Non-AEAD rejects AAD/taglen; non-CBC rejects padding. |
| api_ec_public | secp256r1/secp384r1 key_set_private_key + point serialization; sm2 equivalent | P256 key32, P384 key48, sm2 key32: big-endian raw scalar HEX; valid scalar enforced by upstream. Output SEC1 uncompressed point 65/97/65 bytes. No random keygen here (CLI eckeygen/sm2keygen already provide it). |
| api_ec_sign | secp256r1/secp384r1 `ecdsa_sign` | P256/P384, SHA256/SHA384 messages only; output DER8..72/104 bytes. Upstream digest_to_e accepts only 32/48-byte hashes, so SHA1/SHA224/SHA512 are deliberately absent. |
| api_ec_verify | secp256r1/secp384r1 `ecdsa_verify` | Same curves/hash choices; pub is uncompressed point HEX65/97; sig is complete DER8..104, no trailing bytes. Invalid signature gives nonzero status and zero output. |
| api_ecdh | secp256r1/secp384r1 `ecdh` | P256/P384; key32/48, pub65/97; rejects wrong encodings/off-curve/infinite points. Output shared affine X32/48. No identity binding/KDF implied. |
| api_sm2_ecdh | sm2.h `sm2_ecdh` | key32, pub65; explicit `sm2_z256_point_from_bytes==1` and non-infinity check before ECDH. Needed because upstream from_octets accepts the (0,0) infinity encoding. Output X32. This is not identity-bound SM2 key exchange. |
| api_zuc_mac | zuc.h `zuc_mac_init/update/finish` | ZUC-128 MAC (core EIA-3 primitive). Key 16 bytes HEX (allowKeyReference SYMMETRIC_KEY), IV 16 bytes HEX. Optional nbits: if given, enforces `ceil(nbits/8) == inlen` and unused trailing bits must be zero. Output: 4 bytes MAC (32-bit). |
| api_zuc256_mac | zuc.h `zuc256_mac_init/update/finish` | ZUC-256 MAC. Key 32 bytes HEX (allowKeyReference SYMMETRIC_KEY), IV 23 bytes HEX. Optional macbits (32, 64, 128; output 4, 8, or 16 bytes), default 32. Optional nbits with trailing bit zero-check. |
| api_sm9_kem | sm9.h `sm9_kem_encrypt/decrypt` | SM9 Key Encapsulation Mechanism. Encrypt: `-pubmaster` PEM, `-id` string 1..8191, `-outlen` 1..4096, outputs shared key K (`-out`) and uncompressed point C 65 bytes (`-cipherout`). Decrypt: `-key` encrypted private key PEM, `-pass` password, `-id` string, `-outlen`, input point C 65 bytes (`-in` or stdin, raw or hex), outputs shared key K (`-out`). |

Hex lengths in catalog min/max are characters, while this table uses bytes.
All digest/HMAC/KDF/EC/ZUC/SM9 outputs are lowercase HEX plus newline by default; `-bin`
selects raw bytes. AES is always binary. AEAD encryption format is `ciphertext || tag`;
decrypt consumes the same. GCM/CCM must return success before any plaintext is written,
even though upstream CCM internally computes plaintext before checking the tag.
CBC padding failures likewise publish no partial plaintext. Verification succeeds with
empty binary output (a newline in default HEX mode); its exit status is authoritative.

`-in` is ordinary business payload and intentionally has no allowedKeyKinds: platform
accepts file references only. API EC scalar inputs are secret HEX without key references;
RAW scalar is not a SYMMETRIC_KEY. AES/HMAC/ZUC secret HEX can reference a symmetric vault key.
SM9 master public key accepts `allowedKeyKinds: ["PUBLIC_KEY"]` and user private key accepts
`allowedKeyKinds: ["PRIVATE_KEY"]`. No extension creates private key files; KDF/ECDH/AES/KEM
outputs are marked sensitive.

### SM9 KEM Authenticity Boundary
SM9 KEM is a Key Encapsulation Mechanism, not an Authenticated Key Exchange (AKE) or AEAD scheme.
A malformed point C (invalid prefix, off-curve, infinity) or invalid private key password is
strictly rejected with non-zero exit status; however, for a valid point C on the curve, decrypting
with an incorrect user ID derives a different key K (without generating a cryptographic error).
This is intrinsic to the standard SM9 KEM algorithm, which does not embed an authentication tag
or integrity check; applications requiring authenticated identity binding and message confidentiality
must use the full SM9 hybrid encryption scheme (`sm9encrypt`/`sm9decrypt` with C3 HMAC-SM3 tag).

## Boundary contract

- Entry `int gmssl_extension_main(int argc,char **argv)`, argv0=gmssl, argv1=command;
  unknown command returns -2 without side effects. Success0, failure1.
- Max42 argv, max20 named options, each value <=8192 bytes; only per-command whitelisted
  flags, no duplicates. Numeric parse is strict and bounded. No tty interaction, shell,
  subprocess, network, password prompt or dynamic-library path.
- Business input <=16MiB; fixed bounded allocations input16MiB+1/output16MiB+32, freed
  with secure clearing on all outcomes. Key contexts, scalar buffers, passwords/secret
  argv values are cleared. Core-dump/resource limits remain runner responsibilities.
- `-in/-out/-cipherout/-pubmaster/-key` are engine-resolved paths, never arbitrary browser paths.
  Native additionally requires their parent resolve to the real worker cwd/input or cwd/output directory,
  restricted basename <=128, regular input file, O_NOFOLLOW; output O_EXCL0600 prevents
  symlink replacement/overwriting. Parent directories are controlled by the engine.
  The worker cwd is its private task root. Input devices/FIFOs are rejected.
- Output creation only follows successful cryptography. Worker output cap16MiB may be
  lower than AES ciphertext max input+tag; engine enforces its configured aggregate cap.
- Auth/parameter failure emits one generic diagnostic; no secret hex/password is logged.
- Runner owns the stdin argument frame; extension sees only business bytes, unmodified.
  Test `--runner` emits GMRUN001 + BE count + BE total + (BE len,value)* + business bytes.

## Real test evidence

Reproduction Python: bundled Python3.12 from `load_workspace_dependencies` (system Python
3.9 here has no SM3 provider). Tests require hashlib with SM3 and SHA512 truncated variants;
no cryptography dependency installation needed. Standalone build uses matching C_DEFINES
from native/.build/upstream/CMakeFiles/gmssl.dir/flags.make, fixed upstream include and
libgmssl.a; macOS additionally links `-framework Security`.

- `python3 native/extension-tests.py --binary native/.extension-test-build/extensions-asan`:
  **231 PASS** invocations, native/.extension-test-build/asan-tests.log.
  231 invocations无ASan/UBSan报告；仅adapter启用instrumentation，上游static未instrumented，不代表全库内存正确；未单独声称LeakSanitizer/零内存泄漏。
- Includes SHA/SM3/SHA3/SHAKE hashlib comparison; all8 HMAC/PBKDF2/HKDF digests;
  RFC5869; NIST AES128/192/256 ECB, CBC, CTR, GCM; RFC3610 CCM; all5 AES modes
  across key sizes, empty/nonaligned/binary payloads; altered AEAD tag; all3 curve generator
  KAT and ECDH d=1 known result plus two-party symmetry; ECDSA roundtrip/altered message/
  trailing DER; invalid scalar/peer;
  ZUC-128 EIA-3 1-bit vector and 50-byte zero vector; ZUC-256 MAC across 32, 64, 128 bit tags;
  SM9 KEM encrypt/decrypt roundtrips, invalid password, corrupted point (invalid 0x05 prefix),
  wrong user ID deriving distinct keys, parameter boundaries;
  unknown/duplicate flags; input/work/counter limits; file paths/overwrites/symlinks;
  AEAD failure creates no output file.
- ECDSA random signatures are validated by their matching public-key verification, not
  compared against deterministic RFC6979 signatures (GmSSL uses fresh randomness).
- Runner integration suite is separate and verified via `--runner` once runner.c hooks are compiled.

## API versus CLI: remaining useful operations and non-gaps

| Family | Existing user operations / API assessment | Remaining API-level difference |
|---|---|---|
| SM3/SHA/HMAC/KDF | sm3/sm3_hmac/sm3_pbkdf2 CLI plus extensions above | HKDF separate extract-only/expand-only steps not exposed; combined standard HKDF is. SHA3 HMAC absent in upstream generic DIGEST API. |
| AES | All modes actually declared in aes.h exposed above | No public AES OFB/CFB/XTS API in this baseline; do not invent it. |
| SM4 | CLI ECB/CBC(including no-pad and PKCS7)/CTR/CFB/OFB/CCM/GCM/XTS/FF1/CBC-MAC, GHASH | Streaming/block/CTR32/assembly variants are not new algorithms. Coverage/testing of CLI belongs to native/coverage.md. |
| ZUC | CLI zuc, zuc256 streams, zuc_128_eea3/eia3, plus extensions `api_zuc_mac` and `api_zuc256_mac` | Public software MAC primitives now covered across 32, 64, and 128 bit tags. |
| SM2 | keygen/sign/verify/encrypt/decrypt CLI; ECDH/public derivation extensions | sm2exch CLI already calls full identity-bound key_exchange and confirmation APIs. Fast/precompute/fixlen variants are not new algorithms. |
| P256/P384 | eckeygen CLI supports both + extensions public/sign/verify/ECDH | **Not exposed:** import/export PEM/DER EC key to raw scalar/point adapters. Browser EC extensions currently use raw scalar/point only. eckeygen itself is not a gap. |
| RSA | rsa.h exposes **only** rsa_public_key_print; x509 key parsing can carry RSA public metadata | No RSA keygen/private sign/decrypt/public encrypt/verify API in baseline. No RSA private operation claimed. Print-only helper not exposed as separate crypto operation. |
| SM9 | setup/extract/sign/verify/encrypt/decrypt/exchange CLI, plus raw KEM extension `api_sm9_kem` | sm9exch calls key_exchange+confirm already; `api_sm9_kem` covers raw key encapsulation/decapsulation. |
| Kyber | CLI keygen/encap/decap cover public KEM operations | Seeded test-vector generation and CPA inner primitive are not exposed; CPA is an internal building block, not a new end-user KEM. |
| SPHINCS | CLI keygen/sign/verify | Inner WOTS/FORS/XMSS tree/hash/address helpers not separate algorithms. Explicit optional-random deterministic signing control is not exposed through current catalog; assess separately from generic signing. |
| LMS/HSS/XMSS/XMSSMT | CLI keygen/sign/verify; stateful lifecycle owned by platform/integration | Remaining-signature count is a useful API-only management operation not exposed here. Update callbacks/cache internals are not new algorithms. Stateful CLI readiness must meet contracts.md before release. |
| X509/CMS/OCSP/CRL/CSR/SCT | Existing corresponding CLI commands | ASN.1 encoders/decoders/formatters are not counted as algorithms; full object-field editing/import/export is not claimed by this algorithm supplement. |
| TLS/TLCP/QUIC | Existing bounded server/client CLI tools | Handshake internals and record/key-schedule helpers not separate end-user algorithms. Network deployment policy/testing owned by engine. |
| Random | rand CLI / software CSPRNG | RDRAND/RDSEED CPU availability is separate capability from software RNG. |
| Utilities | ASN1, PEM, base64, block_cipher facade, BN/field arithmetic, HTTP/socket/endian/memory | Mostly encoding/glue/internal arithmetic; general encoding conversion UI remains a utility feature, not a new crypto algorithm. SDF/SKF/OpenCL hardware explicitly deferred. |

Unexposed operations in this table are not marked tested in extensions-catalog.json.
A passing fourteen-command suite establishes this surface only, not full software API closure.
