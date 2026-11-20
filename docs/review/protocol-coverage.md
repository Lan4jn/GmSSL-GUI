# GmSSL 协议工具真实成对联调与覆盖验收报告 (Protocol Tools Coverage)

**基线版本**：GmSSL commit `24ae482701a7b124826c382fffc55c19f76d475d` (3.3.0-dev.1183)  
**验收模块**：`native/` 原生协议工具、`engine-service/` 执行引擎内部 API  
**执行文件**：`tests/toolbox/protocol_suite.py`  
**证据目录**：`tests/toolbox/protocol-results/` (`latest.json`, `protocol_test.log`)  
**构建与运行时 SHA-256 锚定**：
- `gmssl-runner` 二进制：`36a05a0dc780f798677409d36c59c6645ca8aa3242ac44970906c50dccce2b07` (含 SCT SPKI hash & CRL optional 修复)
- `catalog.json` 清单：`02506687593d0c035c7e69fbcd539297692e38e8ecf7ec2cf1093a7bcc8d8e24`
- `engine-service` 服务包：`fc1580fb2504657570ef95558c9b7ea3c9d5007d5c96576df924ed6561736fdf`  
**验收角色**：teammate `native-algorithms`  
**更新日期**：2026-10-16  

---

## 1. 概述与验收口径

本报告针对 GmSSL 上游实现的全部 8 个协议类命令行工具进行真实执行与成对握手联调验收：
- **TLCP (GB/T 38636)**：`tlcp_server`、`tlcp_client`
- **TLS 1.2 (RFC 5246 与 GmSSL SM2/SM4 扩展)**：`tls12_server`、`tls12_client`
- **TLS 1.3 (RFC 8446 / RFC 8998: SM4 Cipher Suites for TLS 1.3)**：`tls13_server`、`tls13_client`
- **QUIC (RFC 9000/9001 实验性子集)**：`quic_server`、`quic_client`

### 验收铁律与状态判定准则
1. **真实进程与执行引擎**：所有测试用例均通过 `engine-service` 的真实内部 HTTP 执行接口 (`/internal/v1/executions`) 调用 `gmssl-runner` 派发执行，严禁 mock、严禁绕过引擎直接调 shell。
2. **拒绝 `-help` 冒充**：严禁将 `-help` 或仅校验参数/命令存在视为功能测试通过；必须完成完整的网络连接、协议握手、会话建立与应用数据往返。
3. **并发双槽成对联调**：服务端与客户端属于两个独立运行的并发子进程，真实占用 `engine-service` 配置的 2 个并发执行槽位。
4. **握手成功判定**：
   - 长连接监听服务（如 `tlcp_server`、`tls12_server`）：设计为持续监听直至超时，**严禁将超时直接作为握手通过的判据**；必须以客户端 exitCode=0 且收到预期的明文回显/响应为必要前提，结合服务端最终被有界超时清理（exitCode 143/TIMED_OUT）并无内存崩溃判定。
   - 单次连接退出服务（如 `tls13_server`、`quic_server`）：在处理完单次握手及请求后主动退出并返回 exitCode=0。

---

## 2. 协议命令与参数支持矩阵

| 工具 ID | 方向 | 传输层 | 典型密码套件 | 密钥与证书体系 | 退出行为特征 |
|---|---|---|---|---|---|
| `tlcp_server` | 服务端 | TCP | `TLS_ECC_SM4_GCM_SM3`<br>`TLS_ECC_SM4_CBC_SM3` | 国密双证书：签名证书/私钥 + 加密证书/私钥 | 持续监听连接；单次交互后保持监听，直至引擎超时清理终止 (TIMED_OUT) |
| `tlcp_client` | 客户端 | TCP | `TLS_ECC_SM4_GCM_SM3`<br>`TLS_ECC_SM4_CBC_SM3` | 验证服务端双证书 (需指定 CA)；可选双证书或单证书客户端认证 | 握手建立并发送 `-in` 或 `-get`，接收响应后主动关闭连接退出 (exitCode=0) |
| `tls12_server` | 服务端 | TCP | `TLS_ECDHE_SM4_GCM_SM3`<br>`TLS_ECDHE_SM4_CBC_SM3` | SM2 单证书/私钥 (`sm2p256v1` + `sm2sig_sm3`) | 持续监听连接；直至超时清理终止 (TIMED_OUT) |
| `tls12_client` | 客户端 | TCP | `TLS_ECDHE_SM4_GCM_SM3`<br>`TLS_ECDHE_SM4_CBC_SM3` | SM2 根 CA 验签；可选客户端证书认证 | 发送请求并接收响应后退出 (exitCode=0) |
| `tls13_server` | 服务端 | TCP | `TLS_SM4_GCM_SM3` | SM2 单证书/私钥 (`sm2p256v1` + `sm2sig_sm3`) | 处理完连接与应用层数据后主动正常退出 (exitCode=0) |
| `tls13_client` | 客户端 | TCP | `TLS_SM4_GCM_SM3` | SM2 根 CA 验签；可选客户端证书认证 | 发送请求并接收响应后正常退出 (exitCode=0) |
| `quic_server` | 服务端 | UDP | `TLS_AES_128_GCM_SHA256` | P256 证书/私钥 (`prime256v1` + `ecdsa_secp256r1_sha256`) | 发送 1-RTT HTTP/3 响应后主动正常退出 (exitCode=0) |
| `quic_client` | 客户端 | UDP | `TLS_AES_128_GCM_SHA256` | 内置 Initial Keys 协商 | 接收服务端 1-RTT HTTP/3 响应并输出后退出 (exitCode=0) |

---

## 3. 验收测试用例与实测结果清单

全部测试执行于 2026-10-16，由 `tests/toolbox/protocol_suite.py` 自动执行，结果记录于 `tests/toolbox/protocol-results/latest.json`。

| 用例编号 | 类别 | 协议 | 服务端工具与参数 | 客户端工具与参数 | 预期与实测结果 | 状态 |
|---|---|---|---|---|---|---|
| **PROTO-SEC-01** | 网络策略 | TLCP | `tlcp_server` (`port: 80`) | N/A | 端口 < 1024 被 `NetworkPolicy` 拒绝 (HTTP 400) | **PASS** |
| **PROTO-SEC-02** | 网络策略 | TLS 1.2 | N/A | `tls12_client` (`port: 9999`) | 非白名单端口 9999 被 `NetworkPolicy` 拒绝 (HTTP 400) | **PASS** |
| **PROTO-SEC-03** | 网络策略 | TLS 1.3 | N/A | `tls13_client` (`host: 8.8.8.8`) | 非白名单 IP 被 `NetworkPolicy` 拦截 (HTTP 400) | **PASS** |
| **PROTO-VAL-01** | 参数校验 | QUIC | N/A | `quic_client` (缺少 `-host`) | 缺少必选参数直接返回 FAILED | **PASS** |
| **PROTO-VAL-02** | 参数校验 | TLS 1.2 | `tls12_server` (`cipher: INVALID`) | N/A | 非法密码套件直接返回 FAILED | **PASS** |
| **PROTO-TLCP-01** | 真实成对握手 | TLCP | `tlcp_server` (Port 14435, SM4-GCM, 双证) | `tlcp_client` (SNI localhost, SM2 CA, 发送 HTTP GET) | 客户端握手成功，收到回显 `GET /tlcp_test HTTP/1.1`，Exit 0；服务端超时退出清理 (143) | **PASS** |
| **PROTO-TLCP-02** | 双向身份认证 | TLCP | `tlcp_server` (Port 14435, `-cert_request -cacert`) | `tlcp_client` (`-cert -key` 客户端证书) | 双向认证握手成功，收到 `GET /auth_test HTTP/1.1`，Exit 0 | **PASS** |
| **PROTO-TLS12-01** | 真实成对握手 | TLS 1.2 | `tls12_server` (Port 14434, SM4-GCM, SM2) | `tls12_client` (Port 14434, SM4-GCM, SM2) | 客户端握手成功，收到 `Hello GmSSL TLS 1.2 SM4-GCM`，Exit 0 | **PASS** |
| **PROTO-TLS12-02** | 真实成对握手 | TLS 1.2 | `tls12_server` (Port 14437, SM4-CBC, SM2) | `tls12_client` (Port 14437, SM4-CBC, SM2) | 客户端握手成功，收到 `Hello GmSSL TLS 1.2 SM4-CBC`，Exit 0 | **PASS** |
| **PROTO-TLS13-01** | 真实成对握手 | TLS 1.3 | `tls13_server` (Port 14433, SM4-GCM) | `tls13_client` (Port 14433, SM4-GCM) | 客户端握手成功 Exit 0，服务端完成单次会话正常 Exit 0 | **PASS** |
| **PROTO-TLS13-02** | 双向身份认证 | TLS 1.3 | `tls13_server` (Port 14438, `-cert_request`) | `tls13_client` (Port 14438, 客户端证书) | 双向认证成功，收到 `Hello TLS 1.3 Mutual Auth`，Exit 0 | **PASS** |
| **PROTO-QUIC-01** | 真实成对握手 | QUIC | `quic_server` (Port 14436, UDP, P256) | `quic_client` (Port 14436, UDP, P256) | 客户端收到 HTTP/3 响应 `hello from gmssl quic server`，Exit 0；服务端 Exit 0 | **PASS** |
| **PROTO-NEG-01** | 异常证书阻断 | TLCP | `tlcp_server` (Port 14435, SM2 证书) | `tlcp_client` (配置错误的 P256 Root CA) | 客户端证书链校验失败，握手终止，Exit 255 (FAILED) | **PASS** |
| **PROTO-NEG-02** | 曲线协商阻断 | TLS 1.2 | `tls12_server` (Port 14434, SM2 密钥) | `tls12_client` (配置不匹配的 `secp256r1`) | 椭圆曲线组协商失败，握手终止，Exit 255 (FAILED) | **PASS** |

**统计汇总**：共 14 项真实测试用例，**14 项全部通过 (100% PASS)**，0 项失败。

---

## 4. 上游实现成熟度与技术差异客观分析

在测试与代码审查过程中，确认上游固定基线（`24ae4827`）在协议层面的真实实现细节如下：

### 4.1 TLCP (GB/T 38636)
- **国密双证书规范**：完全遵循规范，服务端必须同时配置签名证书/私钥与加密证书/私钥。
- **证书链顺序要求**：上游 `tlcp_cert_chain_check_order` 要求证书链严格按照 `[签名证书, 加密证书, CA证书...]` 顺序拼接；客户端若提供双证书亦需保持该顺序。在测试中，客户端双证书与单证书均经实际验证。
- **运行模式**：`tlcp_server` 为多会话 TCP 监听器，接收客户端请求后输出并持续监听下一个连接，依赖 `engine-service` 的任务超时销毁机制。

### 4.2 TLS 1.2 与 TLS 1.3 密码套件规范说明
- **TLS 1.2 国密套件**：如 `TLS_ECDHE_SM4_CBC_SM3` 与 `TLS_ECDHE_SM4_GCM_SM3`，属于 GmSSL 基于国密规范对 TLS 1.2（RFC 5246）的扩展实现，不属于 RFC 8998（RFC 8998 规范标题明确为 *"SM4 Cipher Suites for TLS 1.3"*，仅定义 TLS 1.3 套件）。
- **参数显式绑定**：TLS 1.2 中使用 SM2 时必须显式指定 `-supported_group sm2p256v1 -sig_alg sm2sig_sm3`，若客户端配置为标准 `secp256r1` 则握手在 ClientHello/ServerHello 阶段被确定性拒绝。
- **进程生命周期差异**：
  - `tls12_server` 与 `tlcp_server` 类似，设计为多轮监听循环。
  - `tls13_server` 在处理完单次连接的应用层数据并完成 CloseNotify 交换后即主动退出（`ret = 0; goto end;`）。

### 4.3 QUIC 上游真实实现成熟度评估（重点客观记录）
- **严禁虚称成熟**：上游 `quic_server` 和 `quic_client` **并非完整的、生产级多流复用的 QUIC/HTTP3 传输协议栈**，其代码定位为 **RFC 9000/9001 规范的原型验证（PoC）实现**。
- **支持范围与局限**：
  1. **密码套件限制**：仅支持基于标准 TLS 1.3 的 `TLS_AES_128_GCM_SHA256` 及 NIST P-256 曲线（`prime256v1`），**目前尚未在上游 QUIC 实现中集成国密 SM4/SM2**。
  2. **帧处理能力**：实现了 Initial 包加密/解密、CRYPTO 帧密钥推导、以及 1-RTT 短包中单一 STREAM 帧的封装。
  3. **交互模式**：服务端仅能响应单次 Client Initial 探测，向 stream 0 发送预固化的固定 HTTP/3 响应帧（`"hello from gmssl quic server"`）后即关闭套接字退出。
  4. **未验证/不支持特性**：不支持乱序重传、无 ACK 丢包恢复、无流控窗口更新（MAX_DATA）、不支持 0-RTT 及连接迁移。
- **验收结论**：测试用例 `PROTO-QUIC-01` 成功验证了 GmSSL 原生所宣称的 QUIC UDP 握手探测与静态 HTTP/3 响应交付，但业务平台在设计产品功能时必须明确标注其原型/实验性状态，不可作为成熟 WebTransport/HTTP3 服务对外承诺。

---

## 5. 总结与归档文件

1. **测试脚本**：`tests/toolbox/protocol_suite.py`
   - 支持单脚本一键回归全部 14 个测试用例。
   - 自动适配 macOS Python 3.9 及工作区 Python 3.12。
2. **机器可读日志与结果**：
   - 结果 JSON：`tests/toolbox/protocol-results/latest.json`
   - 详细日志：`tests/toolbox/protocol-results/protocol_test.log`
3. **并发槽位已完全释放**：所有成对测试已执行完毕，2 个并发执行槽位已恢复空闲，可继续供其余集成测试使用。
