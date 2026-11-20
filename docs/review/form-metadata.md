# 94 个工具目录参数元数据、默认值与快捷枚举全量审查报告

**版本基准**：GmSSL commit `24ae482701a7b124826c382fffc55c19f76d475d` (3.3.0-dev.1183)  
**依据规范**：`docs/UX-SIMPLIFICATION.md`、GmSSL C 源码实证  
**关联任务**：`task-21` (补齐目录默认值枚举与快捷参数元数据)  
**维护责任**：teammate `native-algorithms`  
**自动化生成器**：`native/generate-catalog.py`  
**测试套件**：`native/test-form-metadata.py` (ALL PASSED)  
**机器可读产物**：`native/catalog.json`, `native/extensions-catalog.json`, `native/form-metadata.json`

---

## 1. 概述与核心治理准则

为支撑平台快捷流程、高级参数折叠、托管密钥与关联口令自动注入以及证书向导流程，本工作对平台纳管的全部 94 个业务工具（80 个上游原生 CLI 工具 + 14 个原生 C API 扩展工具）的全部 759 个参数补充了元数据和逐工具分类；静态目录覆盖不表示每个算法或参数组合已执行验收。

### 核心安全与体验规则落实
1. **IV 与 Nonce 绝不固定静态默认值**：
   - 严禁将对称加密（SM4/ZUC/AES 等）的 `iv`、`nonce`、`salt` 设置为固定全零或任何静态默认值。所有密码学安全随机参数在快捷/向导流程中由平台或引擎按规范安全生成，元数据中 `defaultValue` 显式为空，彻底杜绝重放与密钥流重用攻击。
2. **必填未提供默认参数绝对可见（零必填隐藏）**：
   - 任何 mandatory 且无 `defaultValue` 的关键操作参数（`required=True` 且 `defaultValue=None`），一律标记为 `advanced: false` 且 `preferred: true`，严禁被折叠隐藏在高级选项中，保证前端用户无需盲目搜寻必填项。
3. **私钥口令精确绑定至输入密钥文件 (`credentialKeyParameter`)**：
   - 严格审查所有私钥口令参数：仅当存在关联的 `INPUT_FILE` 私钥时，才建立 `credentialKeyParameter` 指向关系（如 `certgen`/`sm2sign` 的 `pass -> key`、`reqsign` 的 `pass -> key`、`sm9keygen` 的 `inpass -> in`、`sm2exch` 的 `exch_pass -> exch_key`）。
   - **keygen 等工具输出新私钥的口令不标记关联**：keygen 生成的新私钥口令（`outpass`/`pass`）属于新创建凭据，绝不错误绑定到输出文件名，由平台生成托管服务进行独立生成与托管。
4. **全量中文标签与上下文自适应命名**：
   - 759 个参数 100% 具备精准的中文标签（`label`），彻底解决了旧版将对称密钥与标量无差别标注为“私钥文件”的歧义：
     - 对称算法（SM4/ZUC/AES）的 `key`（HEX）精准标注为「对称密钥 (HEX)」；
     - 消息认证码（HMAC/CMAC/EIA3）的 `key`（HEX）精准标注为「MAC密钥 (HEX)」；
     - 椭圆曲线操作（ECDH/ECDSA）的标量 `key`（HEX）精准标注为「椭圆曲线私钥标量 (HEX)」或「SM2私钥标量 (HEX)」；
     - 有状态签名算法（LMS/HSS/XMSS/XMSS^MT）的 `key`（INPUT_FILE）精准标注为「有状态私钥文件」；
     - 非对称与 PKI 工具的私钥文件标注为「私钥文件」；
     - 输入输出文件（`in`/`out`）根据工具具体算法动作精准标注为「待加密明文文件」、「待解密密文文件」、「待签名原始数据文件」、「待验签原始数据文件」、「待计算摘要文件」、「证书输入/输出文件」、「密文/签名/摘要输出文件」等。
   - 为典型算法、曲线、迭代次数、有效期、哈希算法等补充了格式提示（`formatHint`）与规范建议（`recommendation`）。
5. **枚举选项完全来自上游 C 源码实证并与默认值 100% 互斥闭环**：
   - 所有枚举值（`options`）均经 `tools/*.c`、`src/x509_*.c`、`src/tls*.c`、`src/lms.c`、`src/xmss.c` 实证提取，且所有配置了默认值的枚举参数，其 `defaultValue` 均严格包含在 `options` 清单中（通过自动化测试断言保护）。
6. **消除模式条件依赖参数的默认冲突（Defect 4 根因治理）**：
   - 彻底修复 `api_aes` 在默认 `mode: "cbc"` 下携带 `taglen: 16` 导致触发 `EngineValidator.java` 拒收的缺陷（第 117 行 `if (v.containsKey("aad") || v.containsKey("taglen")) throw EngineException.invalid()`）。
   - 将模式依赖型参数（如 `api_aes` 的 `taglen` 与 `padding`）默认值置为 null，移入高级参数折叠区，并在 `recommendation` 中指引：GCM/CCM 模式缺省即生效 16 字节认证标签，CBC/CTR/ECB 模式禁止提供；CBC 填充缺省为 none，可选 pkcs7。同时确保 `api_digest` 在固定摘要算法下不赋予 `outlen` 默认值。

---

## 2. 参数分类状态全景统计

保持 80 个上游工具 + 14 个扩展工具 = 94 个业务工具。SAN 增加 4 参数，总数为 759。

- **可选未指定默认 (OPTIONAL_BLANK)**：474 项 (62.5%)。
- **必填未指定默认 (REQUIRED_USER_INPUT)**：104 项 (13.7%)。
- **有选项待选 (ENUM_OPTIONS)**：7 项 (0.9%)。
- **有默认已填 (DEFAULT_PROVIDED)**：174 项 (22.9%)。

分类按默认值、必填、可选枚举、其余可选的顺序判定；是否折叠以 advanced/preferred 为准。

## 3. 全部 94 个工具快捷参数矩阵

|序号|工具 ID|分类|参数数|首选参数|有默认字段|必填无默认字段|
|---|---|---|---:|---|---|---|
|1|rand|random|6|out|outlen, out|—|
|2|certgen|certificate|30|CN, key, pass, out|serial_len, O, OU, C, ST, L, days, algor, sig_alg, sm2_id, out|pass|
|3|certparse|certificate|3|in, out|—|—|
|4|certverify|certificate|9|in, cacert|—|in, cacert|
|5|certrevoke|certificate|5|in, out|reason|—|
|6|ocspreq|certificate|5|in, out|digest|in|
|7|ocspget|certificate|6|cert, out|digest|cert|
|8|ocspsign|certificate|22|cacert, signer, key, pass, out|sig_alg, sm2_id, out|cacert, signer, pass|
|9|ocspverify|certificate|11|cacert, signer|sm2_id|cacert, signer|
|10|crlget|certificate|3|cert, out|—|cert|
|11|crlgen|certificate|17|in, out, cacert, key, pass|out, sig_alg, sm2_id|cacert, pass|
|12|crlparse|certificate|3|in, out|—|in|
|13|crlverify|certificate|5|in, cacert|sm2_id|cacert|
|14|reqgen|certificate|16|CN, key, pass, out|C, ST, L, O, OU, algor, sig_alg, sm2_id, out|pass|
|15|reqparse|certificate|3|in, out|—|—|
|16|reqsign|certificate|27|in, out, cacert, key, pass|out, serial_len, days, sig_alg, sm2_id|cacert, pass|
|17|sm2keygen|key|4|pass, out|out, pubout|pass|
|18|sm2sign|asymmetric|6|key, pass, in, out|id, out|key, pass|
|19|sm2verify|asymmetric|6|in, sig|id|sig|
|20|sm2encrypt|asymmetric|5|in, out|—|—|
|21|sm2decrypt|asymmetric|5|key, pass, in, out|—|key, pass|
|22|sm2exch|asymmetric|23|stage, key, pass, in, out|id|stage|
|23|sm3|digest|9|in, out|out|—|
|24|sm3_hmac|mac|7|key, in, out|out|key|
|25|sm3_pbkdf2|kdf|8|pass, out|iter, outlen|pass|
|26|sm4_ecb|symmetric|6|encrypt, decrypt, key, in, out|encrypt, out|key|
|27|sm4_cbc|symmetric|8|encrypt, decrypt, key, iv, in, out|encrypt, out|key, iv|
|28|sm4_ctr|symmetric|7|encrypt, decrypt, key, iv, in, out|encrypt, out|key, iv|
|29|sm4_cfb|symmetric|8|encrypt, decrypt, key, iv, in, out|encrypt, out|key, iv|
|30|sm4_ofb|symmetric|7|encrypt, decrypt, key, iv, in, out|encrypt, out|key, iv|
|31|sm4_ccm|symmetric|10|encrypt, decrypt, key, iv, in, out|encrypt, taglen, out|key, iv|
|32|sm4_gcm|symmetric|10|encrypt, decrypt, key, iv, in, out|encrypt, taglen, out|key, iv|
|33|sm4_xts|symmetric|8|encrypt, decrypt, key, iv, in, out|encrypt, out|key, iv|
|34|sm4_ff1|symmetric|8|encrypt, decrypt, key|encrypt|key|
|35|sm4_cbc_mac|mac|7|key, in, out|out|key|
|36|zuc|symmetric|5|key, iv, in, out|out|key, iv|
|37|zuc256|symmetric|5|key, iv, in, out|out|key, iv|
|38|zuc_128_eea3|symmetric|7|key, in, out|out|key|
|39|zuc_128_eia3|mac|9|key, in, out|out|key|
|40|ghash|mac|9|in, out|—|—|
|41|sm9setup|key|6|alg, pass, out|pubout|pass|
|42|sm9keygen|key|7|alg, in, inpass, out, outpass|id, out|inpass, outpass|
|43|sm9sign|asymmetric|5|in, key, pass, out|out|pass|
|44|sm9verify|asymmetric|5|in|id|—|
|45|sm9encrypt|asymmetric|5|in, out|id|—|
|46|sm9decrypt|asymmetric|6|key, pass, in, out|id|pass|
|47|sm9exch|asymmetric|17|stage, key, pass, peer_id, in, out|id|stage, key, peer_id|
|48|cmsparse|envelope|2|in|—|in|
|49|cmsencrypt|envelope|4|in, out|—|—|
|50|cmsdecrypt|envelope|6|key, pass, cert, in, out|—|key, pass, cert, in|
|51|cmssign|envelope|6|key, pass, cert, in, out|out|key, pass, cert, in|
|52|cmsverify|envelope|3|in, out|—|in|
|53|tlcp_client|protocol|19|host, port, key, pass, in|host, port, cipher_suite, supported_group, sig_alg|—|
|54|tlcp_server|protocol|11|port, key, pass|port, cipher_suite|—|
|55|tls12_client|protocol|19|host, port, key, pass, in|host, port, cipher_suite, supported_group, sig_alg|—|
|56|tls12_server|protocol|15|port, key, pass|port, cipher_suite, supported_group, sig_alg|—|
|57|tls13_client|protocol|33|host, port, key, pass, in|host, port, cipher_suite, supported_group, sig_alg|—|
|58|tls13_server|protocol|25|port, key, pass|port, cipher_suite, supported_group, sig_alg|—|
|59|sctverify|certificate|9|in|digest|in|
|60|quic_client|protocol|9|host, port|host, port, cipher_suite, supported_group, sig_alg|—|
|61|quic_server|protocol|9|port, key, pass|port, cipher_suite, supported_group, sig_alg|—|
|62|eckeygen|key|6|curve, pass, out|curve, out, pubout|pass|
|63|lmskeygen|pqc|5|out|lms_type, out, pubout|—|
|64|lmssign|pqc|5|key, in, out|out|key|
|65|lmsverify|pqc|5|pubkey, in, sig|—|pubkey, sig|
|66|hsskeygen|pqc|5|lms_types, out|out, pubout|lms_types|
|67|hsssign|pqc|5|key, in, out|out|key|
|68|hssverify|pqc|5|pubkey, in, sig|—|pubkey, sig|
|69|xmsskeygen|pqc|5|out|xmss_type, out, pubout|—|
|70|xmsssign|pqc|5|key, in, out|out|key|
|71|xmssverify|pqc|5|pubkey, in, sig|—|pubkey, sig|
|72|xmssmtkeygen|pqc|5|out|xmssmt_type, out, pubout|—|
|73|xmssmtsign|pqc|5|key, in, out|out|key|
|74|xmssmtverify|pqc|5|pubkey, in, sig|—|pubkey, sig|
|75|sphincskeygen|pqc|4|out|out, pubout|—|
|76|sphincssign|pqc|5|key, in, out|out|key|
|77|sphincsverify|pqc|5|pubkey, in, sig|—|pubkey, sig|
|78|kyberkeygen|pqc|4|out|out, pubout|—|
|79|kyberencap|pqc|5|pubkey, out|outkey|pubkey|
|80|kyberdecap|pqc|5|key, in, out|—|key|
|81|api_digest|digest|5|alg, in, out|alg, out|—|
|82|api_hmac|mac|5|alg, key, in, out|alg, out|key|
|83|api_hkdf|kdf|7|alg, in, out|alg, outlen, out|—|
|84|api_pbkdf2|kdf|7|alg, pass, salt, out|alg, iter, outlen, out|pass, salt|
|85|api_sm3_kdf|kdf|4|in, out|outlen, out|—|
|86|api_aes|symmetric|9|mode, op, key, in, out|mode, op, out|key|
|87|api_ec_public|asymmetric|4|curve, key, out|curve, out|key|
|88|api_ec_sign|asymmetric|6|curve, key, alg, in, out|curve, alg, out|key|
|89|api_ec_verify|asymmetric|7|curve, pub, alg, sig, in, out|curve, alg|pub, sig|
|90|api_ecdh|asymmetric|5|curve, key, pub, out|curve, out|key, pub|
|91|api_sm2_ecdh|asymmetric|4|key, pub, out|out|key, pub|
|92|api_zuc_mac|digest|6|key, iv, in, out|out|key, iv|
|93|api_zuc256_mac|digest|7|key, iv, in, out|macbits, out|key, iv|
|94|api_sm9_kem|asymmetric|10|op, key, in, out|op, id, outlen, cipherout, out|—|

## 4. 自动化生成与测试验证证据

### 4.1 生成器设计
`native/generate-catalog.py` 脚本实现了基于上游 C 源码词法解析与元数据注记规则的完全可复现构建：
- 支持从固定源码仓库重新运行生成 `native/catalog.json`、`native/command-inventory.json`；
- 支持将增强元数据同步注入至 `native/extensions-catalog.json` 并汇总输出 `native/form-metadata.json`；
- 避免任何手动编辑单次 JSON 造成的重跑覆盖损失。

### 4.2 测试套件执行证据
执行 `python3 native/test-form-metadata.py` 得到全量测试通过证据：
```text
=== Testing Catalog and Form Metadata Integrity ===
Loaded 80 base tools + 14 extension tools = 94 total tools.
Checking security rule: No static zero IV or nonce defaults...
 -> PASSED: No static zero IV/nonce defaults found.
Checking UX rule: Mandatory parameters without default value cannot be advanced...
 -> PASSED: All mandatory un-defaulted parameters remain visible in quick view.
Checking credential key parameter bindings...
 -> PASSED: Verified all required credentialKeyParameter bindings.
Checking keygen tools output pass is not misbound to credentialKeyParameter...
 -> PASSED: Keygen tools output passwords are appropriately unbound.
Checking localized labels presence and context sensitivity...
 -> PASSED: 100% of 759 parameters across 94 tools have valid context-sensitive labels.
Checking evidence-based enums and defaultValue consistency...
 -> PASSED: 100% of parameters with default values and options are mutually consistent.
 -> PASSED: SM9 setup retains two master-key algorithms; keygen retains all three operations.
 -> PASSED: Full signing/protocol choices and typed SAN metadata remain available.
Checking catalog default smoke with a Python subset of engine cross-field rules...
 -> PASSED: 94 catalog default payloads passed the Python subset; live Java validation is a separate acceptance.

ALL 94 TOOLS METADATA AND CONTRACT TESTS PASSED!
```


## 5. task-27：DNS/IP SAN 与 CSR extensionRequest

### 实现与参数契约

- 不修改固定上游；native/apply-overlays.py 校验原文件 SHA-256 和每个替换锚点唯一性，再派生 certgen.c、reqgen.c、reqsign.c。生成 overlays-manifest.json 和 overlays.diff。
- certgen/reqgen/reqsign：subject_ip 为可重复 STRING；reqgen 新增可重复 STRING subject_dns_name。目录仍为 94 工具，新增 4 参数。
- IPv4/IPv6 通过 inet_pton 产生 4/16 字节 iPAddress GeneralName；禁止 zone、CIDR、主机名，不执行 DNS 查询。Darwin 的 inet_pton 会容忍 zone，因此先检查纯字面字符集。
- DNS/IP 合计最多 64 项、GeneralName DER 合计最多 2048 字节；DNS 单项最多 253 字节。每次写入之前由上游 x509_general_names_add_general_name 预估长度；属性 DER 和 CSR 输出额外预检容量。
- reqgen 写入标准 Attribute SEQUENCE { OID 1.2.840.113549.1.9.14, SET { SEQUENCE OF Extension }}，其值只包含 SAN，再由 GmSSL 签署 CSR。reqsign 接收缓冲扩大为 8192 字节，支持原 512 字节上限以上的正常 SAN 请求。
- reqsign 首先验 CSR 签名，再解析唯一 extensionRequest/唯一 SAN。仅继承经验证的 DNS/IP SAN，其他 GeneralName 类型明确失败；CA:true、keyCertSign、cRLSign 等请求扩展不复制。任何显式 subject_dns_name/subject_ip 覆盖 CSR 的整个 SAN 集合。

### 已运行的验收

命令：python3 native/test-certificate-san.py。实际调用 framed gmssl-runner，OpenSSL 3.6.4 仅作为测试夹具和独立解析/验签器，业务生成 provider 仍为 GmSSL。

1. certgen DNS、IPv4、IPv6 的真实 DER 由 openssl x509 解析。
2. reqgen extensionRequest 由 openssl req 解析并用 distid:1234567812345678 独立验证 SM2 自签。
3. reqsign 默认保留 SAN，openssl verify 验证颁发者签名；显式 SAN 覆盖通过。
4. 三个工具均测试非法 IP；certgen/reqgen 测试 65 项、254 字节 DNS 和超出 2048 字节 DER 失败。
5. 独立 OpenSSL CSR 请求 CA:true/证书签名用法，GmSSL 签发只继承 DNS/IP SAN。
6. 未审 URI SAN 明确失败；64 项合法 SAN 跨过旧 CSR 大小上限后仍完整签发。
7. 对合法重签的重复 extensionRequest、重复 SAN、异常 IP 字节长度和超限 CSR SAN 明确失败；篡改 CSR SAN 后验签失败。
8. 两次全新生成 overlay 的 manifest/diff 字节相同，原始和派生 SHA-256 均匹配。

### 签名/协议枚举边界补充

证书签名选项保留 9 个编译启用家族：SM2、ECDSA SHA256/384/512、LMS、HSS、XMSS、XMSSMT、SPHINCS。依据 src/x509_key.c 的 x509_key_supports_sign_algor / x509_sign_init 和 src/x509_alg.c 名称表，不把 OID 表中的 RSA 或 ECDSA SHA1/224 当作可签能力。certgen/reqgen 的 algor 同步保留原始 PQC 私钥格式入口，不提供 rsaEncryption 假选项。PQC 家族的选择保留不表示这些工具全部端到端已验证；须匹配密钥格式、签名缓冲限制及上游具体实现。

TLS1.2 套件补齐 AES128-CCM；TLS1.3 补齐 SM4-CCM/AES128-CCM，分别按 src/tls12.c、src/tls13.c 的能力表和 tls_ctx_set_cipher_suites 约束。TLCP 签名只保留其静态能力表中的 sm2sig_sm3。推荐默认与完整高级选择分离。

### 验证边界与交接

native/test-form-metadata.py 的 Python 仿真仅覆盖部分 Java 跨字段规则；不是完整 EngineValidator 等价测试，也不是 94 工具真实执行证明。原生 SAN 测试为上述有限用例的运行证据；HTTP 工作流、Java literal 校验和服务统一重启交由 integration/platform/cert-workflows/build-quality 完成。本次未修改 Java、CMake、固定上游或运行服务状态。


## 6. QA fresh30 toolbox：SM9 keyagreement 枚举回归修复

- 根因：生成器曾将 sm9setup 和 sm9keygen 的 alg 共用二选项，HTTP 元数据校验提前排除了合法 sm9keyagreement。
- 事实：tools/sm9setup.c:111 的执行 switch 只有 sm9sign/sm9encrypt；tools/sm9keygen.c:129 的 switch 另有 sm9keyagreement（146 行）。src/sm9_key.c 的 OID 名称表还可解析 sm9，但两个工具均没有该执行分支。
- 修复：逐工具从实际执行 case OID_sm9* 分支生成去重有序 options，而非照抄全局 OID 表或共用推荐子集。sm9keygen 保留完整三项；sm9setup 保留两项。
- 红灯：新增防收窄断言后，测试明确失败于 sm9keygen 缺少 sm9keyagreement；绿灯：重生成 catalog/form-metadata 后全套通过，工具/参数总数仍为 94/759。
- 原生冒烟：临时生成签名/加密两类 master key，依次执行 sm9keygen 的 sm9sign、sm9encrypt、sm9keyagreement，三条路径均退出 0 且输出非空加密私钥。
- 同类核对：api_ec_sign/api_ec_verify 的 sha256/sha384 来自 extensions.c:231 明确二选一校验；OCSP digest 下游 x509_digest_algors / ocsp_digest_from_oid 限定 SM3、SHA1、SHA2 常用六项，名称解析器额外认识 sha512-224/256 不表示 OCSP 可编码这些 OID。证书 algor/sig_alg 与协议 suite 按上一节真实 loader/sign dispatch 和协议能力数组区分。SCT 的摘要选项仍受其签名验证路径约束，未在本修复中把共享 digest 名称表盲扩为可用全集。
- 部署交接：本次仅 generator、目录、矩阵、回归测试与文档发生变更；不修改 Java，不重建/重启正在验收的 engine，不删除原 sm9exchangecase 或 task26-toolbox-core-final.log。QA 待 FULL_SAN 浏览器结束后，仅 engine 重包并刷新 catalog 资源，再 fresh 执行原失败用例。
- 边界：本地三算法原生冒烟与元数据测试通过，不替代刷新服务后的 HTTP sm9exch 完整链路验收。

## 7. SM9 分阶段必填与身份默认修正

2026-10-18 最终全工具回归在 `sm9exch` 初始化阶段捕获 HTTP 400：合法的 init 请求只有 pubmaster、peer_id、exch_keyout 和 out，目录却将 key、id、peer_id 静态设为全局必填。生成器现将分阶段使用的 key/id/peer_id 与其他交换阶段材料一起设为全局可选，stage 仍为唯一全局必填；各阶段的实际材料要求保留由原生工具检查，没有删除任一高级参数。

同时将 `1234567812345678` 默认值限制在已验证的 SM2 签名/交换身份场景；SM9 的 id/peer_id 是实际用户身份，不再套用 SM2 常量。新增回归同时检查 SM9 init 的全局必填集合、SM9 身份无默认，以及 SM2 签名默认仍保留。

精确证据：`.tools/logs/lead-sm9-stage-red.log` 为修改前预期失败，`.tools/logs/lead-sm9-stage-green.log` 为修后 94 工具/759 参数元数据测试通过；实际 HTTP 四阶段交换与最终部署目录身份由独立 QA 在引擎资源刷新后复验。


## 8. TLS/QUIC 曲线输入名称与真实解析器一致

固定上游 `tls_named_curve_from_name` 调用 `ec_named_curve_from_name`；`src/ec.c` 的 P-256 名称表使用 `prime256v1`。`OID_secp256r1` 与 `OID_prime256v1` 相同是内部常量关系，并不让字符串 `secp256r1` 成为该协议命令的合法输入。独立 QA 直接运行原生 QUIC 双进程确认：prime256v1 完成 HTTP/3 响应，secp256r1 则在参数解析退出。

因此 TLS 固定组枚举使用 sm2p256v1/prime256v1，QUIC 的默认值与选项使用 prime256v1；专用 EC 密钥生成器中已验证的 secp256r1/secp384r1 名称保持不变，因为其解析路径不同。`.tools/logs/lead-quic-group-red.log` 与 `lead-quic-group-green.log` 保存此回归的红/绿证据；原协议套件不改参数、不删用例，HTTP 14 项回归由 QA 刷新目录后复验。

