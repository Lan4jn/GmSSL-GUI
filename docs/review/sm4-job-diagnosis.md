# 用户 SM4 任务执行失败诊断与平台安全错误映射修复报告 (Task-17 Diagnosis & Fix)

**缺陷任务 ID**：`d56a3cd1-e352-4507-a3ba-cbed72e81355`  
**涉及工具**：`sm4_ecb`  
**创建时间**：`2026-10-17T03:02:03Z`  
**初态报错**：`Engine rejected request` (HTTP 502)  
**修复模块**：`platform-service/src/main/java/org/gmssl/gui/platform/Engine.java`、`EngineTransportTest.java`  
**验收角色**：teammate `platform`  
**完成日期**：2026-10-17  

---

## 1. 缺陷定位与根因诊断

### 1.1 历史任务现象与可观察性缺失
管理员用户项目中的作业 `d56a3cd1-e352-4507-a3ba-cbed72e81355` 运行失败，平台直接记录了终态错误信息：
```
status: FAILED
error: Engine rejected request
```
该错误信息为平台层抛出的通用 502 异常字符串，完全遮蔽了底层执行引擎（`engine-service`）返回的真实 HTTP 状态码与结构化错误码，导致调用方与前端无法诊断实际失败机理。

### 1.2 根因分析一：底层跨参数校验约束与缺陷复现（症状一致性确认）
经代码核查，`engine-service` 的 `EngineValidator.java` (L59-60) 对所有 `sm4_*` 对称加密模式（除 `sm4_cbc_mac` 外）存在严格的互斥与必选约束：
```java
if (c.startsWith("sm4_") && !c.equals("sm4_cbc_mac")) {
    exclusive(v, "encrypt", "decrypt");
    if (!v.containsKey("encrypt") && !v.containsKey("decrypt"))
        throw EngineException.invalid();
    ...
}
```
在解析 `BOOLEAN` 类型参数时，只有值为 `true` 的项会被记录进已解析参数映射；若提交参数中 `encrypt` 与 `decrypt` 均为 `false`（或未指定），则两者均不在映射中，导致触发 `EngineException.invalid()`，引擎返回 **HTTP 400 Bad Request**，响应体为：
```json
{
  "code": "INVALID_PARAMETERS",
  "message": "Parameters do not satisfy the tool contract",
  "requestId": "..."
}
```
在前端工具表单历史实现中，`encrypt` 与 `decrypt` 曾作为两个独立的复选框（Checkbox）呈现，且默认均处于未勾选（`false`）状态。**需要特别说明的是，由于平台出于安全隐私规范未持久化存储用户作业的敏感入参，用户历史作业的具体参数模式无法绝对确认；经受控复现测试，模式缺失（双 false）是已复现并确认存在的一种缺陷模式，与用户 Job `d56a3cd1-e352-4507-a3ba-cbed72e81355` 的失败症状完全一致，但并不作为其唯一原因的绝对确证。**

### 1.3 根因分析二：上游 ECB 分组对齐约束与 PKCS7 行为差异
进一步的浏览器端与底层测试显示了另一类关键输入约束：
1. **上游 GmSSL `sm4_ecb` 工具不具备 PKCS7 自动填充能力**：与 `sm4_cbc`（支持 `-pkcs7` 参数且默认开启）不同，`sm4_ecb` 在上游实现中严格按照纯分组加密规范执行，要求明文或密文长度**必须为 16 字节整数倍**。
2. 若输入数据为非 16 字节对齐（例如常见的未填充 ASCII 文本 38 字节），原生 runner 进程将直接返回非零退出码（exit code != 0），并提示 `Engine execution did not succeed`。
3. 该非对齐拒绝是**预期内的分组密码学边界规则**，而非后端内部 500 异常。平台后端按上游规范不擅自扩充 backend padding 逻辑，由前端协同增加字节长度提示与预检（或建议用户选用支持 PKCS7 的 CBC 模式）。

### 1.4 根因分析三：平台端 `Engine.java` 对非 2xx 响应的过度泛化
在修复前，`platform-service` 的 `Engine.java` (L51-52) 实现为：
```java
byte[] data = res.body();
if (res.statusCode() < 200 || res.statusCode() >= 300)
    throw new ApiError(502, "ENGINE_REJECTED", "Engine rejected request");
```
任何非 2xx 状态码（无论是客户端参数错误 400、大小超限 413、还是并发限制 429）均被无差别抛弃原始上下文，强制包装为 `502 ENGINE_REJECTED ("Engine rejected request")`，造成严重的可观察性缺失。

---

## 2. 最小修复方案与安全错误映射实现

依据 Lead 指令与安全规范，本修复在 `platform-service` 实施最小改动，建立**白名单状态与错误码安全映射机制**，并严格禁止直接反射底层响应的任意 `message` 文本，杜绝密钥、令牌与内部敏感路径的外泄：

### 2.1 安全映射规则矩阵

| 引擎 HTTP 状态 | 引擎 Code (识别白名单) | 映射后平台状态 | 映射后平台 Code | 映射后固定中文安全提示 (无反射) |
|---|---|---|---|---|
| **401 / 403** | 任意内部认证报错 | **502** | `ENGINE_CONFIGURATION_ERROR` | 执行引擎服务认证或配置异常 |
| **400** | `INVALID_PARAMETERS` | 400 | `INVALID_PARAMETERS` | 执行参数不符合工具规范 |
| **400** | `INVALID_REQUEST` | 400 | `INVALID_REQUEST` | 执行请求格式非法 |
| **400** | `TOOL_UNAVAILABLE` / `UNAVAILABLE` | 400 | `TOOL_UNAVAILABLE` | 工具在当前环境中不可用 |
| **400** | `UNKNOWN_TOOL` | 400 | `UNKNOWN_TOOL` | 未知或不支持的工具 |
| **400** | `NETWORK_POLICY` | 400 | `NETWORK_POLICY_VIOLATION` | 网络策略禁止该目标访问 |
| **400** | `SECRET_DIAGNOSTICS` | 400 | `SECRET_DIAGNOSTICS_FORBIDDEN` | 协议密钥诊断已被系统禁用 |
| **400** | `INVALID_CERTIFICATE` | 400 | `INVALID_CERTIFICATE` | 证书数据非法或无法解析 |
| **400** | `INVALID_CRL` | 400 | `INVALID_CRL` | CRL 格式或签名校验失败 |
| **409** | `DUPLICATE_EXECUTION` | 409 | `DUPLICATE_EXECUTION` | 执行标识已被占用 |
| **413** | `INPUT_LIMIT` / `OUTPUT_LIMIT` | 413 | `PAYLOAD_TOO_LARGE` | 输入或输出数据超过大小限制 |
| **429** | `BUSY` / `CONCURRENCY_LIMIT` | 429 | `ENGINE_BUSY` | 执行引擎繁忙，请稍后重试 |
| **503** | 引擎临时不可用 / 清理隔离 | 503 | `ENGINE_UNAVAILABLE` | 执行引擎服务暂时不可用 |
| **504** | 引擎执行超时 | 504 | `ENGINE_TIMEOUT` | 执行引擎处理超时 |
| **其他/未知/非JSON** | 未知内容或崩溃 HTML | 502 | `ENGINE_ERROR` | 执行引擎处理失败 |

### 2.2 核心安全防护特征
1. **防会话伪造防护**：内部服务间的 `X-Engine-Token` 认证错误（401/403）严格映射为 `502 ENGINE_CONFIGURATION_ERROR`，绝不向客户端下发 401，避免与终端用户的登录态/Token 失效混淆。
2. **彻底杜绝 Secret 反射**：即便引擎端返回了包含敏感内容（如密钥明文、报错堆栈或目录路径）的响应文本，平台层仅提取 JSON 结构中的 `code` 枚举值并匹配预设白名单，所有用户提示均使用平台定义的静态不可变中文字符串，无反射、无拼接。

---

## 3. 验证与测试结果

### 3.1 传输层与安全单测 (`EngineTransportTest.java`)
运行命令：`bash scripts/mvn.sh test -Dtest=EngineTransportTest -pl platform-service`
测试结果：**3/3 全部通过 (BUILD SUCCESS)**。
用例涵盖：
- `transportErrorMappingSafeguards - err400`: 模拟引擎返回包含敏感字符 `leaked_secret_key_123456` 的 400 响应，断言状态码为 400，code 为 `INVALID_PARAMETERS`，提示为 `执行参数不符合工具规范`，且响应文本中 100% 不包含敏感字符串。
- `transportErrorMappingSafeguards - err429`: 模拟 429 忙碌，断言映射为 429 `ENGINE_BUSY` 与安全中文提示。
- `transportErrorMappingSafeguards - err401`: 模拟引擎内部 401 认证失败，断言映射为 502 `ENGINE_CONFIGURATION_ERROR`（非 401）。
- `transportErrorMappingSafeguards - errMalicious`: 模拟非 JSON 恶意回显包含 `RAW_LEAKED_PRIVATE_KEY`，断言映射为 502 `ENGINE_ERROR`，且敏感内容被完全丢弃。

### 3.2 真实平台 HTTP 接口端到端加解密与负测验证
通过平台真实 REST API（`http://127.0.0.1:8080/api/v1`）执行闭环验证：
1. **SM4 加密正测（使用项目托管密钥引用）**：
   - 导入 16 字节 SM4 RAW 密钥 (`test-sm4-vault-key`)，上传 16 字节测试明文；
   - 提交 `sm4_ecb` 作业，入参 `encrypt: true`, `key: "key:<kid>"`, `in: "file:<fid>"`, `out: "cipher.bin"`；
   - 判定结果：`status: SUCCEEDED`, `exitCode: 0`，产出 16 字节有效密文。
2. **SM4 解密正测（使用十六进制密钥直接输入）**：
   - 上传上述密文，提交 `sm4_ecb` 作业，入参 `decrypt: true`, `key: "<hex>"`, `in: "file:<cfid>"`, `out: "recovered.bin"`；
   - 判定结果：`status: SUCCEEDED`, `exitCode: 0`，还原数据与原始明文 100% 字节一致。
3. **参数缺失负测（双 false 复现）**：
   - 提交 `sm4_ecb` 作业，入参 `encrypt: false, decrypt: false`；
   - 判定结果：`status: FAILED`，**作业记录的 `error` 字段精确呈现为 `"执行参数不符合工具规范"`，彻底消除了原先模糊的 `"Engine rejected request"`**，且无任何敏感信息泄露。
4. **互斥冲突负测（双 true 复现）**：
   - 提交 `sm4_ecb` 作业，入参 `encrypt: true, decrypt: true`；
   - 判定结果：`status: FAILED`，作业同样安全终止并给出 `"执行参数不符合工具规范"`。

---

## 4. 结论与协同交付

1. **环境与数据完整性保障**：受控重启操作仅局限于 `platform-service` 进程，未终止 `engine-service`，未清空或修改数据库，已保留用户既有项目、托管密钥资产以及历史失败任务记录原貌，IPv6 绑定与指定访问域名完全保持原样。
2. **前端 Guard 协同**：已发信通知 `web-verifier`，前端表单中针对 `sm4` 工具的 `encrypt` 与 `decrypt` 复选框应调整为单选（Radio Group），并默认选中 `encrypt`，在客户端层面协同防御双 false 提交。
3. **任务状态**：`task-17` 已在团队任务看板中标记为 `completed`。
