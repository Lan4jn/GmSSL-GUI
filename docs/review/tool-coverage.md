# GmSSL 工具目录行为覆盖与执行追踪报告 (Toolbox Coverage Report)

**基线版本**：GmSSL commit `24ae482701a7b124826c382fffc55c19f76d475d` (3.3.0-dev.1183)  
**工具总分母定义**：
- **上游原生业务工具 (CLI)**：`native/catalog.json` 共 **80 项** 原生业务工具（已排除 `-help`、`--version` 辅助参数）
- **原生 C 扩展 API 工具**：`engine-service` capabilities 注册的 **14 项** C 扩展工具（`api_*`）
- **两类合计**：80 项原生 CLI 工具 + 14 项原生 C 扩展工具 = 94 项能力

**执行引擎**：`engine-service` HTTP 执行接口 (`127.0.0.1:8081/internal/v1/executions`)，驱动 `gmssl-runner` 安全沙箱进程  
**测试套件目录**：`tests/toolbox/` (`basic_suite.py`, `asym_suite.py`, `pqc_suite.py`, `protocol_suite.py`, `runner.py`)  
**验收负责人**：`build-quality` (协同团队：`platform` 负责 PKI 验收 task-12、`native-algorithms` 负责协议握手 task-11)  
**更新日期**：2026-10-16  

---

## 1. 验收准则与执行原则

1. **真实引擎驱动执行**：所有测试一律通过 `engine-service` 的内部 HTTP API 发送参数、通过内存映射传输输入文件/秘密（`inputs` 映射至内存 byte[]），严禁 mock、严禁绕过引擎直接调用宿主 bash/shell 执行。
2. **严格禁止 `-help` 冒充覆盖**：坚决摒弃仅调用 `-help` 或利用参数缺失失败就声称功能覆盖的做法。所有算法必须完成真实加解密、签名验签、密钥协商或多阶段往返，并验证输出的密码学正确性。
3. **区分验证类型（精确标注 KAT vs 往返 vs 完整工作流）**：
   - **`[KAT]` (已知答案测试)**：比对 GM/T、GB/T、NIST 或被测算法标准算例明确给出的已知测试向量，断言精确 Hash/MAC/密文字节；
   - **`[Roundtrip]` (加解密/流往返)**：验证 Encrypt -> Decrypt 全文逐字节比对，或 AEAD 认证标签及附加数据校验；
   - **`[Workflow]` (多阶段协议与工作流)**：验证非对称密钥派生、协商闭环（双端派生对称密钥一致）以及状态型密钥推进；
   - **`[Integrity]` (输出完整性粗检)**：验证随机数发生器输出长度并进行非全零粗检（仅作输出可用性粗检，不证明信息熵质量）。
4. **机器可核验追踪 (Machine-Verifiable Trace)**：`EngineClient` 开启有界 trace 机制，记录 `toolId`、`operation`、`status`、`exitCode`、`responseHash` 与 `timestamp`，**绝不记录 parameters、inputs 与 stdout 明文**，避免敏感信息记录到测试日志。
5. **分工与分母边界说明**：
   - `build-quality` (本套件 `runner.py`) 直接覆盖并驱动 **51 项** 基础、非对称与 PQC 原生工具；
   - `native-algorithms` (task-11 `protocol_suite.py`) 独立完成 **8 项** 协议成对握手工具；
   - `platform` (task-12 `pki_suite.py`) 完成 **21 项** PKI 证书与数字信封工具的修复与真实验收；
   - **三套件合并形成 80/80 全量上游原生 CLI 覆盖，并在 `tests/toolbox/results/unified_80_coverage.json` 导出完整机器证据**。

---

## 2. 80 项原生 CLI 工具覆盖状态总览

分母基准：`native/catalog.json` 包含 80 项工具。

```
总计 80 项上游原生 CLI 工具 (100% 覆盖)
├── 已在 runner.py 直接验证通过 (51 项)
│   ├── 基础密码学 (19 项) - basic_suite.py
│   ├── 非对称与密钥协商 (14 项) - asym_suite.py (含 SM2 4阶段 + SM9 4阶段全协议)
│   └── 后量子密码 PQC (18 项) - pqc_suite.py
├── 已在 protocol_suite.py 验证通过 (8 项) - task-11 协议成对握手
└── 已在 pki_suite.py 验证通过 (21 项) - task-12 PKI 与数字信封
```

---

## 3. 分组测试矩阵与证据分类

### 3.1 基础对称、摘要、MAC 与 KDF (19 项) - `basic_suite.py` 100% PASS

全部 19 项测试均严格声明验证类型，摒弃纯长度判断，SM3-HMAC 与 GHASH 均引入真实标准 KAT 向量：

| 工具 ID | 验证类型 | 密码学算法 / 模式 | 标准规范 | 校验内容与断言标准 | 验证结果 |
|---|---|---|---|---|---|
| `rand` | `[Integrity]` | 伪随机数发生器 | GM/T 0005 | 生成 32 字节随机数，断言长度=32 且非全零粗检（仅校验输出可用性，不证明信息熵质量） | **PASSED** |
| `sm3` | `[KAT]` | SM3 密码杂凑算法 | GB/T 32905-2016 | 验证 `abc` 标准哈希值 `66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0` | **PASSED** |
| `sm3_hmac` | `[KAT]` | HMAC-SM3 | GM/T 0004 / Wycheproof | 空消息验证 `f9938b1b2515...`；0x77 消息验证 `51aaf64843b6...`（真实比对 Tag 字节） | **PASSED** |
| `ghash` | `[KAT]` | GHASH 伽罗瓦散列 | NIST SP 800-38D | 验证测试向量 2：128-bit H 向量 + C 向量产生 `f38cbb1ad69223dcc3457ae5b6b0f885` | **PASSED** |
| `sm4_cbc_mac` | `[KAT]` | SM4-CBC-MAC | GB/T 32907-2016 | 验证标准 MAC 向量 `9054fccff72871fdad5202c821dbea05` | **PASSED** |
| `zuc_128_eia3` | `[KAT]` | ZUC-128 EIA3 完整性校验 | 3GPP TS 35.221 / GM/T 0001.2 | 4B count + bearer + direction，验证 MAC 结果 `b0361765` | **PASSED** |
| `sm3_pbkdf2` | `[KAT]` | PBKDF2 (SM3) | RFC 8018 结构 / 独立算例向量 | 基于 RFC 8018 PBKDF2 结构与 SM3 基础散列（注：RFC 8018 本身未收录 SM3 向量，此处采用 GmSSL / GM/T 0004 独立实现算例）：pass + salt + 10000 次迭代，验证派生密钥 `df6b713d38d5a35df6861959e529ed22` | **PASSED** |
| `sm4_ecb` | `[Roundtrip]` | SM4 电子密码本模式 | GB/T 32907-2016 | 16B 密钥，32B 明文加解密完全往返比对 | **PASSED** |
| `sm4_cbc` | `[Roundtrip]` | SM4 密文分组链接模式 | GB/T 32907-2016 | 16B 密钥 + 16B IV，加解密完全往返比对 | **PASSED** |
| `sm4_ctr` | `[Roundtrip]` | SM4 计数器模式 | GB/T 32907-2016 | 16B 密钥 + 16B IV，流式加解密完全往返比对 | **PASSED** |
| `sm4_cfb` | `[Roundtrip]` | SM4 密文反馈模式 | GB/T 32907-2016 | 16B 密钥 + 16B IV + 16B sbytes，加解密完全往返比对 | **PASSED** |
| `sm4_ofb` | `[Roundtrip]` | SM4 输出反馈模式 | GB/T 32907-2016 | 16B 密钥 + 16B IV，加解密完全往返比对 | **PASSED** |
| `sm4_ccm` | `[Roundtrip]` | SM4 计数器密码分组链接认证 | GB/T 32907 / NIST SP 800-38C | 12B IV + 16B Tag + AAD，AEAD 加解密完全往返比对 | **PASSED** |
| `sm4_gcm` | `[Roundtrip]` | SM4 伽罗瓦/计数器认证加密 | GB/T 32907 / NIST SP 800-38D | 12B IV + 16B Tag + AAD，AEAD 加解密完全往返比对 | **PASSED** |
| `sm4_xts` | `[Roundtrip]` | SM4 XTS 磁盘加密模式 | IEEE Std 1619-2007 | 32B 复合密钥 + 16B IV + 数据单元大小 32B，完全往返比对 | **PASSED** |
| `sm4_ff1` | `[KAT]` | SM4-FF1 保形加密 | NIST SP 800-38G | 16B 密钥 + tweak + 数字明文 `62260901...` 加密为 `23269828...` 并解密还原 | **PASSED** |
| `zuc` | `[KAT & Roundtrip]` | ZUC 祖冲之序列密码 | GM/T 0001.1-2012 | 16B key + 16B IV，验证附录 A.1 密文 `27bede74018082da` 及往返还原 | **PASSED** |
| `zuc256` | `[Roundtrip]` | ZUC-256 序列密码 | GM/T 0001-2020 / 3GPP | 32B key + 23B IV，16B 明文加解密完全往返比对 | **PASSED** |
| `zuc_128_eea3` | `[Roundtrip]` | ZUC-128 EEA3 机密性加密 | 3GPP TS 35.221 / GM/T 0001.2 | 16B key + count + bearer + direction，加解密完全往返比对 | **PASSED** |

---

### 3.2 非对称加密、签名与全阶段密钥协商 (14 项) - `asym_suite.py` 100% PASS

针对 SM9 密钥交换，已完全由最初的单一 init 扩展为**完整的四阶段密钥协商全流程与负向测试**：

| 工具 ID | 验证类型 | 算法与标准 | 测试工作流与关键断言 | 验证结果 |
|---|---|---|---|---|
| `sm2keygen` | `[Workflow]` | SM2 (GB/T 32918) | 密码派生口令生成 PKCS#8 加密私钥与公钥 PEM | **PASSED** |
| `eckeygen` | `[Workflow]` | ECDSA (NIST P-256) | 指定 `secp256r1` 曲线生成标准 EC 密钥对 | **PASSED** |
| `sm2sign` | `[Workflow]` | SM2 (GB/T 32918.2) | 使用私钥对测试明文生成有效 ASN.1 DER 签名 | **PASSED** |
| `sm2verify` | `[Workflow]` | SM2 (GB/T 32918.2) | 公钥对 SM2 签名和明文执行验证，exitCode=0 | **PASSED** |
| `sm2encrypt` | `[Workflow]` | SM2 (GB/T 32918.4) | SM2 公钥加密明文，生成 ASN.1 DER 密文 | **PASSED** |
| `sm2decrypt` | `[Workflow]` | SM2 (GB/T 32918.4) | 私钥解密密文，逐字节完全匹配原始输入 | **PASSED** |
| `sm2exch` | `[Workflow]` | SM2 (GB/T 32918.3) | **4 阶段完整密钥协商**：<br>1) Alice init (`-exch_keyout`, `-out ra`)<br>2) Bob respond (`-peer_pubkey`, `-in ra`, `-out rb_sb`)<br>3) Alice confirm (`-peer_pubkey`, `-exch_key`, `-in rb_sb`, `-keyout`, `-out sa`)<br>4) Bob finish (`-peer_pubkey`, `-exch_key`, `-in sa`, `-keyout`)<br>断言双方导出协商密钥 100% 逐字节一致。 | **PASSED** |
| `sm9setup` | `[Workflow]` | SM9 (GM/T 0044) | 分别执行 `sm9sign` 与 `sm9encrypt` 主密钥生成 | **PASSED** |
| `sm9keygen` | `[Workflow]` | SM9 (GM/T 0044) | 使用主私钥提取签名、加解密及密钥协商 (`sm9keyagreement`) 用户私钥 | **PASSED** |
| `sm9sign` | `[Workflow]` | SM9 (GM/T 0044.2) | Alice 基于身份标识对测试数据签名 | **PASSED** |
| `sm9verify` | `[Workflow]` | SM9 (GM/T 0044.2) | 结合签名主公钥与 `Alice` 身份验签成功 | **PASSED** |
| `sm9encrypt` | `[Workflow]` | SM9 (GM/T 0044.4) | 使用加密主公钥及接收者身份 `Bob` 加密明文 | **PASSED** |
| `sm9decrypt` | `[Workflow]` | SM9 (GM/T 0044.4) | Bob 使用其身份私钥解密并还原明文 | **PASSED** |
| `sm9exch` | `[Workflow & Neg]` | SM9 (GM/T 0044.3) | **4 阶段完整闭环密钥协商 + 2 组负测**：<br>1) Alice init (`-peer_id Bob -exch_keyout alice_ra -out ra.hex`)<br>2) Bob respond (`-id Bob -peer_id Alice -in ra.hex -exch_keyout bob_rb -out rb_sb.hex`)<br>3) Alice confirm (`-id Alice -peer_id Bob -exch_key alice_ra -in rb_sb.hex -keyout alice_key -out sa.hex`)<br>4) Bob finish (`-id Bob -peer_id Alice -exch_key bob_rb -in sa.hex -keyout bob_key`)<br>**正向断言**：Alice 与 Bob 派生的 48 字节共享密钥完全匹配。<br>**负测 1**：confirm 阶段传入伪造 peer_id (`Eve`)，引擎严格返回 FAILED / exitCode!=0。<br>**负测 2**：finish 阶段传入被篡改的 SA 确认值，引擎严格拒绝并返回 FAILED。 | **PASSED** |

---

### 3.3 后量子密码 (PQC) (18 项) - `pqc_suite.py` 100% PASS

| 工具 ID | 规范 / 参数集 | 验证流程与测试点 | 状态型密钥推进断言 | 验证结果 |
|---|---|---|---|---|
| `lmskeygen`, `lmssign`, `lmsverify` | LMS (RFC 8554)<br>`LMS_SM3_M32_H5` | 有状态哈希签名及验签 | 签名后断言 `updatedInputs` 返回自愈更新后的私钥 | **PASSED** |
| `hsskeygen`, `hsssign`, `hssverify` | HSS (RFC 8554)<br>两层分层状态签名 | 分层状态签名及验签 | 复合私钥推进 | **PASSED** |
| `xmsskeygen`, `xmsssign`, `xmssverify` | XMSS (RFC 8391)<br>`XMSS_SM3_10_256` | 基于哈希树签名 | 签名并验签成功 | **PASSED** |
| `xmssmtkeygen`, `xmssmtsign`, `xmssmtverify` | XMSS^MT (RFC 8391)<br>`XMSSMT_SM3_20_2_256` | 多树分层哈希签名 | 多层签名产生并校验通过 | **PASSED** |
| `sphincskeygen`, `sphincssign`, `sphincsverify` | SPHINCS+ (FIPS 205)<br>无状态哈希签名 | 无状态签名产生与校验 | 验签 exitCode=0 | **PASSED** |
| `kyberkeygen`, `kyberencap`, `kyberdecap` | ML-KEM / Kyber (FIPS 203)<br>基于格密钥封装 | 封装与解封往返 | 断言 `secret == dec_secret` 100% 一致 | **PASSED** |

---

### 3.4 网络协议成对握手 (8 项) - `protocol_suite.py` (task-11 已交付)

*(详细成对握手日志参见 `docs/review/protocol-coverage.md`)*

- `tlcp_client`, `tlcp_server`：TLCP (GB/T 38636) 国密双证书成对握手，HTTP 明文通信验证通过；
- `tls12_client`, `tls12_server`：TLS 1.2 (RFC 5246 国密套件扩展) `TLS_ECDHE_SM4_GCM_SM3` 握手与应用数据回显；
- `tls13_client`, `tls13_server`：TLS 1.3 (RFC 8446 / RFC 8998) `TLS_SM4_GCM_SM3` 1-RTT 握手验证通过；
- `quic_client`, `quic_server`：QUIC (RFC 9000/9001) P-256 证书与 UDP 监听握手验证通过。

---

### 3.5 PKI 证书、CRL、OCSP 与数字信封 (21 项) - `pki_suite.py` 100% PASS (task-12 已交付)

*(详细 PKI 与信封测试记录参见 `docs/review/pki-coverage.md` 与 `tests/toolbox/pki-results/latest.json`)*

覆盖以下 21 项工具，共执行 25 项测试记录（含正向测试与非信任 CA/吊销负向测试），全部返回 `PASS`：
- **证书与 CSR (6 项)**：`certgen`, `certparse`, `certverify`, `certrevoke`, `reqgen`, `reqparse`, `reqsign`
- **吊销列表 CRL (4 项)**：`crlgen`, `crlparse`, `crlverify`, `crlget`
- **在线状态 OCSP (4 项)**：`ocspreq`, `ocspsign`, `ocspverify`, `ocspget`
- **密码消息语法 CMS / 数字信封 (6 项)**：`cmsencrypt`, `cmsdecrypt`, `cmssign`, `cmsverify`, `cmsparse`, `sctverify`
- **SCT 证书透明度 (1 项)**：`sctverify`（使用真实标准 RFC 6962 结构与可信 EC P-256 日志公钥成功验签通过）

---

## 4. 原生 C 扩展 API 工具 (14 项) - `extension-tests.py` PASS

由 `native-algorithms` 编写的原生 C 扩展测试 `native/extension-tests.py`，经由独立进程执行，覆盖以下 **14 项扩展 API 工具**：

```
14 项原生 C 扩展 API 工具列表：
1.  api_digest       (包含 SHA-1、SHA-224/256/384/512、SHA-3 系列及 SHAKE128/256)
2.  api_hmac         (多散列 HMAC 计算与校验)
3.  api_hkdf         (HKDF 密钥派生)
4.  api_pbkdf2       (PBKDF2 密钥派生)
5.  api_sm3_kdf      (SM3-KDF 密钥派生)
6.  api_aes          (AES-ECB/CBC/CTR/GCM/CCM 模式)
7.  api_ec_public    (椭圆曲线公钥计算)
8.  api_ec_sign      (椭圆曲线签名)
9.  api_ec_verify    (椭圆曲线验签)
10. api_ecdh         (标准 ECDH 密钥交换)
11. api_sm2_ecdh     (SM2-ECDH 密钥交换)
12. api_zuc_mac      (ZUC-128 MAC)
13. api_zuc256_mac   (ZUC-256 MAC)
14. api_sm9_kem      (SM9-KEM 密钥封装机制)
```

**执行证据与模式说明**：
- **生产 Runner 协议模式 (Production Runner)**：
  - 运行命令：`python3 native/extension-tests.py --binary native/.build/bin/gmssl-runner --runner`
  - 运行结果：`{"passedInvocations": 231, "status": "PASS", "binaryMode": "runner", "coverage": "14 commands; KAT, roundtrip, tag/signature tamper, bounds and file handling"}`
  - 验证逻辑：基于生产环境 `gmssl-runner` 标准 `GMRUN001` 二进制 stdin 协议传输命令帧，由 Lead 实际复核通过。
- **独立适配器消毒桩模式 (Standalone Adapter Sanitizer)**：
  - 运行命令：`DYLD_LIBRARY_PATH=/Library/Developer/CommandLineTools/usr/lib/clang/21/lib/darwin python3 native/extension-tests.py --binary native/.extension-test-build/extensions-asan`
  - 运行结果：`{"passedInvocations": 231, "status": "PASS", "binaryMode": "standalone", "coverage": "14 commands; KAT, roundtrip, tag/signature tamper, bounds and file handling"}`
  - 验证逻辑：专为 C 扩展接口设立的轻量级 standalone adapter 内存安全测试桩（带 ASan/UBSan 检查），仅对 C 扩展适配模块实施内存边界与溢出检测，**并非**原生全库编译为 ASan。
- **说明**：231 为该 14 项工具在各种边界、错误注入与不同算法参数下的**执行调用次数 (Invocations)**，而非 231 个工具。

---

## 5. 机器可核验追踪与运行汇总证据

### 5.1 产物阶段记录与构建指纹
为防止新旧测试报告及运行时混淆，当前验收产物与代码覆盖均严格绑定唯一的构建指纹：
- **Runner 生产二进制**：`native/.build/bin/gmssl-runner`  
  SHA-256: `36a05a0dc780f798677409d36c59c6645ca8aa3242ac44970906c50dccce2b07`
- **Native Overlay 清单**：`native/.build/generated/overlays-manifest.json`  
  SHA-256: `a9067efe6bcbf0d4f14f968e56badbb49f6fc9f60fc9c1e39d7714637d4aca7c`

### 5.2 运行器汇总 (`tests/toolbox/results/runner_summary.json`)
```json
{
  "timestamp": "2026-10-16T11:02:19.612906+00:00",
  "duration_seconds": 5.342,
  "total_tests": 30,
  "passed": 30,
  "failures": 0,
  "errors": 0,
  "successful": true,
  "build_metadata": {
    "runner_binary_path": "native/.build/bin/gmssl-runner",
    "runner_binary_sha256": "36a05a0dc780f798677409d36c59c6645ca8aa3242ac44970906c50dccce2b07",
    "overlays_manifest_path": "native/.build/generated/overlays-manifest.json",
    "overlays_manifest_sha256": "a9067efe6bcbf0d4f14f968e56badbb49f6fc9f60fc9c1e39d7714637d4aca7c"
  },
  "coverage": {
    "catalog_native_total": 80,
    "runner_observed_tools_count": 51,
    "runner_observed_tools": [ ... 51 项成功观察到的工具列表 ... ],
    "unobserved_in_this_runner_count": 29,
    "unobserved_partitions": {
      "protocol_tools_task11": [ "tlcp_client", "tlcp_server", "tls12_client", "tls12_server", "tls13_client", "tls13_server", "quic_client", "quic_server" ],
      "pki_and_envelope_tools_task12": [ "certgen", "certparse", "certrevoke", "certverify", "cmsdecrypt", "cmsencrypt", "cmsparse", "cmssign", "cmsverify", "crlgen", "crlget", "crlparse", "crlverify", "ocspget", "ocspreq", "ocspsign", "ocspverify", "reqgen", "reqparse", "reqsign", "sctverify" ]
    },
    "extension_tools": {
      "tool_count": 14,
      "verified_invocations": 231,
      "status": "PASS",
      "modes": {
        "production_runner": "PASS (native/extension-tests.py --binary native/.build/bin/gmssl-runner --runner; GMRUN001 stdin protocol, verified in production runner)",
        "standalone_adapter_sanitizer": "PASS (native/extension-tests.py --binary native/.extension-test-build/extensions-asan; ASan/UBSan adapter harness, not full-library ASan)"
      }
    },
    "sm9exch_full_agreement_verified": true
  }
}
```

### 5.3 全量 80/80 统一覆盖合并结果 (`tests/toolbox/results/unified_80_coverage.json`)
由 `scripts/merge-coverage.py` 自动化聚合三方真实测试报告（`runner_summary.json` 51 项、`protocol-results/latest.json` 8 项、`pki-results/latest.json` 21 项），严格以 `native/catalog.json` 80 个工具为分母核验，达成 **100% 完整覆盖（80/80）**：
```json
{
  "timestamp": "2026-10-16T11:12:52.942280+00:00",
  "summary": {
    "catalog_tools_denominator": 80,
    "catalog_tools_observed": 80,
    "catalog_coverage_ratio": "80/80",
    "coverage_percent": 100.0,
    "all_catalog_tools_covered": true,
    "extension_tools_count": 14,
    "extension_verified_invocations": 231,
    "extension_status": "PASS"
  },
  "build_fingerprint": {
    "runner_binary_path": "native/.build/bin/gmssl-runner",
    "runner_binary_sha256": "36a05a0dc780f798677409d36c59c6645ca8aa3242ac44970906c50dccce2b07",
    "overlays_manifest_path": "native/.build/generated/overlays-manifest.json",
    "overlays_manifest_sha256": "a9067efe6bcbf0d4f14f968e56badbb49f6fc9f60fc9c1e39d7714637d4aca7c",
    "catalog_json_sha256": "02506687593d0c035c7e69fbcd539297692e38e8ecf7ec2cf1093a7bcc8d8e24"
  }
}
```

### 5.4 结构化执行追踪记录 (`tests/toolbox/results/execution_trace.json`)
追踪记录遵循零秘密泄露规范，样例条目如下：
```json
{
  "toolId": "sm9exch",
  "operation": "stage_finish",
  "status": "SUCCEEDED",
  "exitCode": 0,
  "responseHash": "395feadcb9c4bfb72a6b472e3ea86670e309cb873fa73f848c4cfc62ddb03882",
  "timestamp": "2026-10-16T10:57:33.243555+00:00"
}
```

---

## 6. 报告结论

1. **SM9exch 闭环**：`sm9exch` 现已实现 `init` -> `respond` -> `confirm` -> `finish` 全部四阶段闭环协议验证，完成 Alice 与 Bob 48 字节协商密钥逐字节完全一致性断言，并附加了“错误 peer_id”和“被篡改确认 Token”的严格负测。
2. **测试类型严谨归类**：全面区分并标明了 `[KAT]`、`[Roundtrip]` 与 `[Workflow]`，排除了“仅断言长度即称 KAT”的缺陷，规范了 HMAC-SM3 与 GHASH 的真实测试向量。
3. **80/80 原生 CLI 工具全量覆盖**：80 项原生 CLI 工具通过各专职套件真实驱动执行完成，其中 51 项由 `runner.py` 覆盖、8 项由 `protocol_suite.py` 覆盖、21 项由 `pki_suite.py` 覆盖，三方最新报告在 `unified_80_coverage.json` 中统一聚合，达到 80/80 全部覆盖。
4. **原生 C 扩展工具独立验证**：14 项原生 C 扩展工具经由生产 `gmssl-runner` 协议及独立 ASan/UBSan 测试桩执行 231 次调用，全部验证通过（`PASS`）。
5. **全链路追踪可核查**：所有执行记录经由 `EngineClient` 的哈希化 trace 完整保存于 `results/execution_trace.json`，供各端客观复核。
