# GmSSL PKI 与数字信封工具真实覆盖与验收报告 (PKI & Digital Envelope Coverage)

**基线版本**：GmSSL commit `24ae482701a7b124826c382fffc55c19f76d475d` (3.3.0-dev.1183)  
**验收模块**：`native/` 证书与数字信封工具、`engine-service/` 执行引擎内部 API  
**执行文件**：`tests/toolbox/pki_suite.py`  
**证据目录**：`tests/toolbox/pki-results/`、`pki-results/` (`latest.json`, `pki_run_*.json`)  
**原生可执行体 SHA256 (`gmssl-runner`)**：`36a05a0dc780f798677409d36c59c6645ca8aa3242ac44970906c50dccce2b07`  
**Overlay 清单 SHA256 (`overlays-manifest.json`)**：`a9067efe6bcbf0d4f14f968e56badbb49f6fc9f60fc9c1e39d7714637d4aca7c`  
**验收角色**：teammate `platform`  
**更新日期**：2026-10-16  

---

## 1. 概述与验收口径

本报告针对 GmSSL 上游实现的全部 **16 个证书管理类工具** 与 **5 个数字信封/CMS 工具**（共 21 个命令行工具）进行真实执行、端到端业务工作流联调与覆盖验收：

- **证书与密钥基础设施 (16)**：
  - 证书生命周期：`certgen`、`certparse`、`certverify`、`certrevoke`
  - 证书签名请求 (PKCS#10 CSR)：`reqgen`、`reqparse`、`reqsign`
  - 证书吊销列表 (X.509 CRL)：`crlgen`、`crlparse`、`crlverify`、`crlget`
  - 在线证书状态协议 (OCSP)：`ocspreq`、`ocspget`、`ocspsign`、`ocspverify`
  - 证书透明度 (RFC 6962 CT)：`sctverify`
- **密码消息语法与数字信封 (5)**：
  - CMS 结构与解析：`cmsparse`
  - 签名数据 (SignedData)：`cmssign`、`cmsverify`
  - 数字信封 (EnvelopedData)：`cmsencrypt`、`cmsdecrypt`

### 验收铁律与状态判定准则
1. **真实引擎派发执行**：所有 21 个工具均通过 `engine-service` 的真实内部 HTTP 执行接口 (`/internal/v1/executions`) 调用 `gmssl-runner` 派发执行，严禁 mock 引擎、严禁绕过引擎直接调本地 shell。
2. **拒绝 `-help` 冒充**：严禁将 `-help` 或仅校验参数/命令存在视为功能测试通过；必须完成完整的证书签发、ASN.1 结构解析、密码学验签、吊销状态校验、受控网络分发与加解密还原。
3. **真实可验的密码学数据往返**：
   - **证书生命周期**：自签名根 CA 签发，通过 CSR 签发实体证书，验证证书链有效性及非受信 CA 拒绝。
   - **CRL 闭环**：通过 `crlgen` 原生参数 `-next_update` 直接生成携带合法有效期的 X.509 CRL，直接由 `crlverify` 验签通过，拒绝手工重签伪造。
   - **OCSP 状态问答**：构造真实双证书链发起请求，CA 签署 `good` 响应，并通过 HTTP 协议完成远程响应查询与验证。
   - **SCT 标准结构与负测**：SCT 签名待签数据严格采用 RFC 6962 Wire 布局，LogID 严格按标准基于 DER SPKI 计算 SHA-256，覆盖合法验签、篡改时间戳拒绝、以及不匹配 Log ID 拒绝。明确说明采用国密 SM2 签名算法 (`0x0708`) 扩展，不宣称公有浏览器 CT 日志通用兼容。
   - **CMS 数字信封与签名**：生成 SignedData 与 EnvelopedData，解析 ASN.1 语法并验证原文 100% 字节一致解密还原。
4. **历史缺陷驳回与 Native Overlay 修复**：历史上曾通过“在测试中模拟上游错误待签布局”以及“手动注入 nextUpdate 字段重签 CRL”迁就 bug，均被 Lead 明确驳回。所有底层缺陷均由 `integration` 在原生层通过构建 Overlay (`native/apply-overlays.py`) 修复派生源码，测试套件完全遵循标准协议进行正负向闭环验证。

---

## 2. 覆盖工具能力与参数支持矩阵

| 序号 | 工具 ID | 命令类别 | 典型参数 | 输入/输出格式 | 核心功能与工作流定位 |
|---|---|---|---|---|---|
| 1 | `certgen` | 证书 | `-C`, `-CN`, `-days`, `-key`, `-pass`, `-ca`, `-key_usage`, `-crl_http_uri`, `-out` | PEM / DER | 签发自签名根 CA 证书或包含扩展属性的实体证书 |
| 2 | `certparse` | 证书 | `-in`, `-out` | PEM -> 文本 | 解析并格式化打印 X.509 证书的完整 ASN.1 扩展结构 |
| 3 | `certverify` | 证书 | `-in`, `-cacert`, `-client`, `-server`, `-tlcp_server` | PEM | 严格比对密钥用法并校验 X.509 证书链有效性 |
| 4 | `certrevoke` | 证书 | `-in`, `-reason`, `-invalid_date`, `-out` | PEM -> DER | 吊销证书并生成 ASN.1 `RevokedCertificate` 条目 |
| 5 | `reqgen` | 证书/CSR | `-C`, `-CN`, `-key`, `-pass`, `-out` | PEM | 生成符合 PKCS#10 规范的证书签名请求 (CSR) |
| 6 | `reqparse` | 证书/CSR | `-in`, `-out` | PEM -> 文本 | 解析并打印 PKCS#10 CSR 结构及公钥主体信息 |
| 7 | `reqsign` | 证书/CSR | `-in`, `-cacert`, `-key`, `-pass`, `-days`, `-key_usage`, `-out` | PEM | CA 签署 CSR 请求生成颁发给终端用户的 X.509 证书 |
| 8 | `crlgen` | CRL | `-in`, `-cacert`, `-key`, `-pass`, `-next_update`, `-out` | DER (Revoked) -> DER (CRL) | 汇总证书吊销条目并由 CA 签名生成携带 nextUpdate 的 X.509 CRL |
| 9 | `crlparse` | CRL | `-in`, `-out` | DER -> 文本 | 完整解析并打印 X.509 CRL 结构、吊销列表与签名 |
| 10 | `crlverify` | CRL | `-in`, `-cacert` | DER + PEM | 校验 CRL 签名有效性并检查颁发者匹配与时间有效性 |
| 11 | `crlget` | CRL/网络 | `-cert`, `-out` | PEM -> DER | 提取证书 DistributionPoint 并受控从 HTTP 服务获取 CRL |
| 12 | `ocspreq` | OCSP | `-in`, `-out` | 串联 PEM 链 -> DER | 根据终端证书与颁发者证书生成符合 RFC 6960 的 OCSP 请求 |
| 13 | `ocspsign` | OCSP | `-reqin`, `-cacert`, `-signer`, `-key`, `-pass`, `-status`, `-out` | DER -> DER | CA 签署 OCSP 响应，置证书状态为 `good`/`revoked`/`unknown` |
| 14 | `ocspverify` | OCSP | `-reqin`, `-respin`, `-cacert`, `-signer` | DER + PEM | 依据 OCSP 请求及 CA 证书校验 OCSP 签名的真实性 |
| 15 | `ocspget` | OCSP/网络 | `-cert`, `-url`, `-out` | 串联 PEM + URL -> DER | 发起 HTTP POST 请求与远程 OCSP 响应器交互并获取状态 |
| 16 | `sctverify` | 证书透明度 | `-in`, `-cert`, `-log_key` | 二进制 SCT 列表 + PEM | 校验标准 RFC 6962 SCT 列表（SM2 扩展签名）与证书匹配性 |
| 17 | `cmsparse` | 数字信封 | `-in` | PEM / DER -> 文本 | 解析 CMS/PKCS#7 消息结构 (SignedData / EnvelopedData) |
| 18 | `cmssign` | 数字信封 | `-key`, `-pass`, `-cert`, `-in`, `-out` | 明文 -> PEM (CMS) | 使用发送方私钥与证书对载荷生成 CMS SignedData 签名 |
| 19 | `cmsverify` | 数字信封 | `-in`, `-out` | PEM (CMS) -> 明文 | 校验 CMS SignedData 签名并提取原始应用层明文数据 |
| 20 | `cmsencrypt` | 数字信封 | `-rcptcert`, `-in`, `-out` | 证书 + 明文 -> PEM (CMS) | 使用接收方 SM2 公钥加密随机对称密钥生成 EnvelopedData |
| 21 | `cmsdecrypt` | 数字信封 | `-key`, `-pass`, `-cert`, `-in`, `-out` | 私钥 + CMS -> 明文 | 使用接收方私钥解密 CMS EnvelopedData 并完整还原明文 |

---

## 3. 验收测试用例与实测结果清单

全部测试由 `python3 -m unittest tests.toolbox.pki_suite` 自动化完整执行，所有 21 个被测工具 100% 通过真实 `engine-service` HTTP 接口派发。完整日志和 JSON 输出持久化于 `tests/toolbox/pki-results/latest.json` 与 `pki-results/latest.json`。

| 用例编号 | 工具名称 | 对应类别 | 操作与测试流程 | 关键预期与判定依据 | 真实执行状态 |
|---|---|---|---|---|---|
| **PKI-01** | `certgen` | 证书签发 | 生成自签名 SM2 Root CA 证书 (`-ca -days 365`) | exitCode=0，产出非空 PEM 证书 | **PASS** |
| **PKI-02** | `certparse` | 证书解析 | 解析 PKI-01 产出的根证书 ASN.1 树状结构 | exitCode=0，输出包含 `version: v3`、`countryName: CN`、`commonName: RootCA` | **PASS** |
| **PKI-03** | `reqgen` | CSR 生成 | 用户生成 SM2 密钥并构造 PKCS#10 CSR | exitCode=0，产出标准 PKCS#10 CSR PEM | **PASS** |
| **PKI-04** | `reqparse` | CSR 解析 | 解析 PKI-03 产出的 CSR ASN.1 结构 | exitCode=0，解析输出包含 `commonName: AliceUser` | **PASS** |
| **PKI-05** | `reqsign` | CSR 签署 | Root CA 签署 AliceUser CSR 并指定密钥用途 | exitCode=0，产出由 CA 签名的终端实体证书 | **PASS** |
| **PKI-06** | `certverify` | 证书验签 | 验证合法终端证书与根 CA 的链式签名关系 | exitCode=0，终端证书通过 Root CA 链式验签 | **PASS** |
| **PKI-07** | `certverify` | 恶意/非信链 | 使用未授权的独立 FakeCA 校验 Alice 证书 | exitCode=1，引擎拒绝不受信证书链，安全阻断 | **PASS** |
| **PKI-08** | `certrevoke` | 证书吊销 | 吊销 Alice 证书并指定原因 `keyCompromise` | exitCode=0，生成 DER 编码的 RevokedCertificate 条目 | **PASS** |
| **PKI-09** | `crlgen` | CRL 生成 | CA 传入 `-next_update (now+30d)` 生成 X.509 CRL | exitCode=0，生成包含有效 nextUpdate 的 CRL DER 数据 | **PASS** |
| **PKI-10** | `crlparse` | CRL 解析 | 解析 PKI-09 生成的 X.509 CRL ASN.1 内容 | exitCode=0，包含 `tbsCertList`、`revokedCertificates` 及原因 | **PASS** |
| **PKI-11** | `crlverify` | CRL 闭环验签 | 直接使用 `crlgen` 真实输出由 CA 证书验证签名 | exitCode=0，无需手工重签即可闭环校验成功 | **PASS** |
| **PKI-12** | `crlget` | CRL 分发 | 生成带 `crl_http_uri` 证书，从 14438 端口获取 CRL | exitCode=0，获取内容与 CA 生成的 CRL 100% 字节一致 | **PASS** |
| **PKI-13** | `ocspreq` | OCSP 请求 | 传入由 CA 签发的双证书 PEM 链生成 DER 请求 | exitCode=0，生成包含 CertID 与 IssuerHash 的 DER 请求 | **PASS** |
| **PKI-14** | `ocspsign` | OCSP 响应 | CA 对 OCSP 请求签署 `status: good` 响应 | exitCode=0，生成由 CA 签名的 BasicOCSPResponse DER | **PASS** |
| **PKI-15** | `ocspverify` | OCSP 验签 | 校验 OCSP 响应是否与请求及 CA 证书匹配 | exitCode=0，验签成功并确认证书处于 `good` 正常状态 | **PASS** |
| **PKI-16** | `ocspget` | OCSP 远程 | 启动 14438 端口 HTTP/1.1 服务，发起远程 OCSP 查询 | exitCode=0，成功接收响应并与 CA 签署数据一致 | **PASS** |
| **PKI-17** | `sctverify` | SCT 正向验签 | 针对标准 RFC 6962 结构校验 CT Log 签署的 SCT 列表 | exitCode=0，标准待签数据与 SPKI LogID 验签成功 | **PASS** |
| **PKI-18** | `sctverify` | SCT 负测(篡改时间) | 篡改 SCT 时间戳（+100ms），签名保持不变 | exitCode=1，引擎严格拒绝时间戳篡改的 SCT 列表 | **PASS** |
| **PKI-19** | `sctverify` | SCT 负测(篡改LogID) | 篡改 SCT Log ID，与公钥计算出的 LogID 不匹配 | exitCode=1，引擎严格拒绝 Log ID 不匹配的 SCT | **PASS** |
| **PKI-20** | `cmssign` | CMS 签名 | 使用用户私钥与证书生成 CMS SignedData | exitCode=0，产出 `BEGIN CMS` SignedData 报文 | **PASS** |
| **PKI-21** | `cmsparse` | CMS 解析 | 解析 SignedData 结构中的 SignerInfo 与证书列表 | exitCode=0，输出 CMS 内部 OID 与签名结构 | **PASS** |
| **PKI-22** | `cmsverify` | CMS 验签 | 验证 SignedData 签名并解包还原原始文本 | exitCode=0，还原文本与原始载荷 100% 字节匹配 | **PASS** |
| **PKI-23** | `cmsencrypt` | 数字信封 | 使用接收方公钥将机密数据封装为 EnvelopedData | exitCode=0，产出包含 RecipientInfo 的 CMS 报文 | **PASS** |
| **PKI-24** | `cmsparse` | 信封解析 | 解析 EnvelopedData 报文中的对称密钥算法与密文 | exitCode=0，识别内容类型为 `envelopedData` | **PASS** |
| **PKI-25** | `cmsdecrypt` | 信封解密 | 使用接收方私钥解开数字信封还原机密数据 | exitCode=0，解密结果与原文 100% 字节一致 | **PASS** |

**实测统计**：总记录数 25，工具覆盖数 21/21 (100%)，测试通过率 100% (25/25 PASS)。

---

## 4. 上游 C 源码缺陷与 Native Overlay 修复深度分析

### 4.1 SCT Wire 格式、LogID 与 Overlay 修复分析 (`sctverify`)

#### 4.1.1 历史缺陷与驳回记录
- **上游源码缺陷定位**：`src/sct.c:49-65` 及 `src/tls.c:94`。  
  上游在 `tls_uint64_to_bytes` 写入 8 字节大端整数时，仅执行 `PUTU64(*out, a)`，**遗漏了 `*out += 8` 指针递增**。导致序列化待签数据时后续字段直接覆盖了时间戳的前 2 个字节，并在末尾留下了 8 个未初始化的栈内存字节。
- **历史驳回说明**：在此前的草案中，测试用例曾通过构造该错误布局并填充尾部 8 字节零来迁就上游 bug，Lead 明确指出“模拟上游错误布局后称 RFC 6962 通过绝不接受，必须修原生派生构建而非改测试迁就 bug”。该做法已被正式驳回并彻底废弃。
- **Log ID 算法偏离**：RFC 6962 Section 3.2 规定 `LogID = SHA-256(DER-encoded SubjectPublicKeyInfo)`。而上游 `src/sct.c` 及 `tools/sctverify.c` 曾错误调用 `x509_public_key_digest_ex`，对裸 65 字节非压缩公钥计算摘要，导致与国际标准及任何标准 CT 日志公钥定义不一致。

#### 4.1.2 Native Overlay 修复实施
由 `integration` 在 `native/apply-overlays.py` 与 CMake 构建链中注入补丁：
1. **`TLS_UINT64_TO_BYTES_POINTER_ADVANCE` (`src/tls.c`)**：
   在 `PUTU64(*out, a)` 后补齐 `*out += 8;`，使序列化指针严格线性推进。
2. **`SCT_LOG_ID_SPKI_DER_HASH` (`src/sct.c`)** 与 **`SCTVERIFY_LOG_ID_SPKI_DER_HASH` (`tools/sctverify.c`)**：
   重构 Log ID 派生逻辑：
   ```c
   uint8_t spki_buf[X509_PUBLIC_KEY_INFO_MAX_SIZE];
   uint8_t *p_spki = spki_buf;
   size_t spki_len = 0;
   DIGEST_CTX dgst_ctx;
   if (x509_public_key_info_to_der(key, &p_spki, &spki_len) != 1
       || digest_init(&dgst_ctx, digest) != 1
       || digest_update(&dgst_ctx, spki_buf, spki_len) != 1
       || digest_finish(&dgst_ctx, dgst, &dgstlen) != 1
       || dgstlen != SCT_LOG_ID_SIZE) { ... }
   ```
   局部精确修复 SCT 模块的 Log ID 计算，不破坏 `x509_public_key_digest_ex` 公共 API 语义。

#### 4.1.3 标准 Wire 格式定义与 SM2 扩展范围界定
测试套件构建的标准待签载荷严格遵循 RFC 6962 结构：
- **待签数据 wire 序列**：
  `version (1B: 0x00)` + `signature_type (1B: 0x00)` + `timestamp (8B uint64)` + `entry_type (2B uint16: 0x0000)` + `cert_len (3B uint24)` + `cert_der` + `extslen (2B: 0x0000)`。
- **SCT wire 结构**：
  `version (1B: 0x00)` + `log_id (32B: SHA256(DER SPKI))` + `timestamp (8B uint64)` + `extslen (2B: 0x0000)` + `sig_alg (2B: 0x0708)` + `siglen (2B)` + `sig_der`。
- **SM2 扩展验证范围说明**：
  RFC 6962 原始规范中仅定义了 RSA (`0x0401`) 与 ECDSA (`0x0403`) 等算法。GmSSL 扩展了 `0x0708`（`TLS_sig_sm2sig_sm3`）用于支持国密 SM2 算法的 SCT 签名与验签。**本次验收确认该实现符合 RFC 6962 基础 Wire 序列规范与国密扩展定义，明确说明不宣称公有 Web PKI / 商业浏览器公开 CT 日志的通用互操作性**。

#### 4.1.4 负测覆盖
- **PKI-18**：篡改时间戳（`timestamp + 100`），签名与证书保持不变，执行返回 `FAILED` (exitCode 1)，确认签名有效性严格绑定时间戳。
- **PKI-19**：篡改 Log ID（位翻转），与日志公钥计算出的 LogID 不一致，执行返回 `FAILED` (exitCode 1)，确认 Log 归属权校验有效。

---

### 4.2 X.509 CRL `nextUpdate` 缺陷与真实工具闭环 (`crlgen` -> `crlverify`)

#### 4.2.1 历史缺陷与驳回记录
- **上游源码缺陷定位**：`src/x509_crl.c:1565-1589` 与 `src/x509_cer.c:107-134`。  
  `x509_crl_get_details` 中局部结构体 `tbs` 未清零；解析无 `nextUpdate` 的 CRL 时，`x509_time_from_der` 遭遇后续字段直接返回 0，未将 `*tv` 置为哨兵 `-1`。导致 `tbs.next_update` 保留栈上随机垃圾（通常为 0）。后续 `x509_crl_check` 发现 `now >= 0` 判定 CRL 已过期并校验失败。
- **历史驳回说明**：在此前的草案中，测试用例曾通过手动解析 DER、强行注入 `nextUpdate` (2035) 字段并调用 `sm2sign` 重新以 CA 私钥签署。Lead 明确指出“手工注入 2035 再签只能证明 crlverify 能读外部 CRL，未证明 crlgen -> crlverify 工具链闭环，必须通过修改原生派生代码或扩展 API 选项实现工具链真实闭环”。该做法已被正式驳回并废弃。

#### 4.2.2 Native Overlay 修复与 Catalog 扩展
1. **`X509_TIME_FROM_DER_DEFAULT_SENTINEL` (`src/x509_cer.c`)**：
   在 `x509_time_from_der` 的 default 分支中，显式将 `if (tv) *tv = -1;` 赋值，确保未命中时明确置为无效哨兵。
2. **`X509_CRL_GET_DETAILS_INIT_SENTINELS` (`src/x509_crl.c`)**：
   对 `tbs` 结构体进行静态显式初始化，`this_update = -1`, `next_update = -1`。
3. **`native/catalog.json` 扩展**：
   在 `crlgen` 工具契约中将 `next_update` 参数类型由 `INTEGER` 修正为标准的 `STRING`（描述明确要求格式 `YYYYMMDDHHMMSSZ`，映射到 C 源码 `tools/crlgen.c:179` 的 `-next_update` 命令行选项）。
4. **服务编译生效**：
   `build-quality` 重新打包 `engine-service` 并热重启服务，确保 `next_update` STRING 契约在引擎校验器中完全生效。

#### 4.2.3 动态闭环验证
在测试套件 `test_04_revocation_and_crl_lifecycle` 中：
- `crlgen` 动态计算 `next_update = (now + 30 days)`（格式如 `20261115...Z`）并传入引擎；
- `crlgen` 成功生成原生签名的 X.509 CRL DER 文件（PKI-09）；
- 将该生成的 CRL 直接作为输入传入 `crlverify`，使用 CA 证书校验（PKI-11）；
- `crlverify` 原生执行返回 `status: SUCCEEDED`, `exitCode: 0`，实现从生成到校验的 100% 真实闭环。

---

### 4.3 CRL 远程拉取安全沙箱与原生拦截 (`crlget`)
`crlget` 命令通过 `engine-service` 的 `ExecutionService.java` 进行原生安全沙箱拦截：
1. 解析输入证书的 X.509 扩展 `2.5.29.31` (CRLDistributionPoints)；
2. 将 URI 提交至 `NetworkPolicy.java` 进行强校验（端口限制为受控白名单端口 `14438`）；
3. 执行服务受控发起 HTTP GET 下载，并就地调用本地 `crlparse` 原生命令验证 CRL 格式合法性；
4. 验证通过后将 CRL 原始字节写入目标产物文件。
在 `test_05_crlget_http_distribution` 中，配置测试证书的 `crl_http_uri` 为 `http://127.0.0.1:14438/ca.crl`，由内置轻量 HTTP 服务承接，成功完成下载与二进制对齐。

---

### 4.4 OCSP 响应器 HTTP/1.1 协议严格要求 (`ocspget`)
- **源码定位**：`src/http.c:67-76`。
- **机制特征**：
  GmSSL 原生 `http_parse_response` 要求 HTTP 状态行必须精确等于 `HTTP/1.1 200 OK\r\n`，若收到 Python `http.server` 默认的 `HTTP/1.0 200 OK\r\n` 则直接判定解析错误（返回 -1）。
- **实测适配**：
  在 `MockPkiHttpServer` 中强制指定 `protocol_version = "HTTP/1.1"`，并补全 `Connection: close` 与 `Content-Length` 首部，确保 `ocspget` 能够一次性顺利完成报文接收与 ASN.1 解析。

---

### 4.5 OCSP 请求链要求 (`ocspreq`)
- **源码定位**：`tools/ocspreq.c:100-112`。
- **机制特征**：
  `ocspreq` 命令输入必须为拼接的 PEM 文件（第一段为被查询的终端证书，第二段为签发该证书的 CA 证书），且两段证书之间不得包含空行。且终端证书的 `Issuer` 必须在字节级严格等于 CA 证书的 `Subject`（通过 `x509_name_equ` 校验）。在测试套件中通过 `reqsign` 严格签发，彻底保证了两端的一致性。

---

## 5. 构建与原生二进制凭证 (Artifact Provenance)

| 产物名称 | 本地路径 | SHA-256 校验和 |
|---|---|---|
| **原生 Runner 二进制** | `native/.build/bin/gmssl-runner` | `36a05a0dc780f798677409d36c59c6645ca8aa3242ac44970906c50dccce2b07` |
| **Overlay 清单文件** | `native/.build/generated/overlays-manifest.json` | `a9067efe6bcbf0d4f14f968e56badbb49f6fc9f60fc9c1e39d7714637d4aca7c` |
| **工具目录契约** | `native/catalog.json` | `02506687593d0c035c7e69fbcd539297692e38e8ecf7ec2cf1093a7bcc8d8e24` |

### 派生构建 Patch 列表
1. `TLS_UINT64_TO_BYTES_POINTER_ADVANCE` (`src/tls.c`)：修复 64 位大端整数序列化指针推进；
2. `X509_TIME_FROM_DER_DEFAULT_SENTINEL` (`src/x509_cer.c`)：时间解析默认分支置 `-1` 哨兵；
3. `X509_CRL_GET_DETAILS_INIT_SENTINELS` (`src/x509_crl.c`)：CRL 详情结构体初始赋 `-1`/`NULL`；
4. `SCT_LOG_ID_SPKI_DER_HASH` (`src/sct.c`)：SCT 核心模块 Log ID 切换为 DER SPKI SHA-256；
5. `SCTVERIFY_LOG_ID_SPKI_DER_HASH` (`tools/sctverify.c`)：SCT 校验 CLI Log ID 切换为 DER SPKI SHA-256。

---

## 6. 结论

通过 `tests/toolbox/pki_suite.py` 严格的自动化回归测试，GmSSL-GUI 项目现已达成：
1. **16 个证书管理类命令 100% 真实执行覆盖**；
2. **5 个数字信封/CMS 密码消息命令 100% 真实执行覆盖**；
3. **测试通过率 100%（25/25 细分用例全部通过，含 3 项负向安全测试）**；
4. **生成了完整的测试执行证据文件 (`tests/toolbox/pki-results/latest.json` 及 `pki-results/latest.json`)**；
5. **在不侵入上游 pristine checkout 的前提下，通过原生 Overlay 构建机制修复了上游关键 C 库缺陷，彻底杜绝了测试用例迁就上游 bug 的不良模式，实现了工具链的真实闭环验证与合规界定**。
