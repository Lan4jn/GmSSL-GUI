# 架构与安全性独立审查日志

**基线版本**：commit `24ae482701a7b124826c382fffc55c19f76d475d` (GmSSL v3.3.0-dev.1183)  
**更新日期**：2026-10-16  
**审查员**：独立审查员 (teammate `architecture`)  

---

## 1. 历史审查问题与修复状态跟踪

| ID | 模块 / 文件 | 严重级别 | 缺陷描述 | 状态 |
|---|---|---|---|---|
| REV-01 | `platform-service/Materials.java` | 高 | SQL 占位符数量（17个）与 schema（16列）不匹配，导致 materials 插入全部异常 | 已修复 (platform 修正为 16 个) |
| REV-02 | `platform-service/Vault.java:91-93` | 高 | 写入文件仅对临时文件 force 后 atomic move，缺失父目录 fsync，断电可能导致目录项未刷盘 | 已修复 (增加父目录 `FileChannel.READ.force(true)`) |
| REV-03 | 契约与架构设计 | 高 | 状态型密钥（LMS/XMSS）缺乏单一权威保护，允许外部导入或重复晋升易受回滚攻击 | 已闭环 (Lead 冻结单一权威契约，增加 `stateful_promotions` tombstone，禁止下载/复制/外导) |
| REV-04 | `engine-service/ExecutionService.java:40,63,156` | 中 | 任务取消与提交存在注册时间窗口竞态，可能遗漏终止子进程 | 已修复 (引入 `cancelledIds` tombstone 并在多阶段检测) |
| REV-05 | `engine-service/ExecutionService.java:118-120,135` | 中 | 任务执行期间未实时监控输出目录大小，超出限制仅在结束检查 | 已修复 (增加循环中每 50ms 轮询输出目录总大小并在超限时立即终止进程) |
| REV-06 | `engine-service/ExecutionService.java:144,170-176` | 高 | 工作目录清理异常被静默吞掉，未清理残留秘密可能被下一任务复用 | 已修复 (增加 `cleanupChecked` 与 `cleanupFailure` 检疫状态) |
| REV-07 | `native/catalog.json` & `engine-service` | 高 | 能力目录关键 INPUT_FILE 缺失 `allowedKeyKinds` 导致平台严格白名单拒绝正常私钥 | 已修复 (集成重新生成 catalog 并重新打包 engine jar) |

---

## 2. CRL Fetch 与网络安全策略审查跟踪

### REV-08: `ExecutionService.java:214-257` ASN.1 粗糙字节模式匹配与边界异常隐患
- **源码位置**：`engine-service/src/main/java/org/gmssl/gui/engine/ExecutionService.java:221-239`
- **具体问题**：
  1. **越界异常风险**：在 `extractCrlUri` 中，多处指针步进缺少边界检查。例如第 230 行 `if(pos<der.length&&der[pos]==0x01) pos+=2+(der[pos+1]&0xFF);`，若畸形/截断证书在结尾处恰为 `0x01`（`pos == der.length - 1`），读取 `der[pos+1]` 抛出 `ArrayIndexOutOfBoundsException`；第 232-233 行同理。导致服务抛出未捕获 500 异常而非预期的 400 `INVALID_CERTIFICATE`。
  2. **盲目字节匹配误判**：第 221-228 行使用线性全量匹配 OID `06 03 55 1d 1f`。若公钥、签名值或主体名随机字节碰巧包含该 5 字节，算法会误把该伪数据当成扩展区起始并尝试解析失败返回 `null`，导致证书后续真实的 CRL 分发点扩展被直接忽略。
- **状态**：**已修复闭环** (integration 已引入 DerReader 严格 remaining 检查与 parent 边界防溢出，并通过 5 类 CRL 测试与 231 项扩展测试)。

### REV-09: 网络策略监听与出站端口语义混淆（契约已澄清）
- **源码位置**：`engine-service/src/main/java/org/gmssl/gui/engine/NetworkPolicy.java:21-26`
- **审查与澄清过程**：
  - **初审发现**：现有单一 `port(int value)` 硬编码 `value < 1024` 拦截，导致标准 HTTP CRL（缺省端口 80）或标准 TLS client（缺省端口 443）即使配置了 `allowedPorts` 也无法连通。
  - **契约重塑 (Lead 明确)**：
    1. **监听端口（Listen Port）**：维持严防特权端口滥用原则，必须 `port >= 1024` 且必须落在 `allowedPorts` 白名单中；
    2. **出站目标端口（Outbound Target Port）**：支持目标端口范围 `1..65535`，但**必须显式包含在 `allowedPorts` 白名单内**（例如 80/443 默认不放行，需运维显式授权）；
    3. **目标地址防护不变**：云元数据 (169.254.169.254)、链路本地、多播、广播地址无论端口如何一律总禁，目标 IP 必须严格白名单匹配；
    4. **代码整改**：NetworkPolicy 将现存单一 `port()` 拆分为 `validateListenPort()` 与 `validateOutboundPort()` 两套正交语义；默认本地端口池 14433..14438 维持不变，并在 ops 文档中补齐说明。
- **状态**：**已确认整改并归档为网络设计标准**。

### REV-10: `ExecutionService.java:259-272` 网络抓取整体超时与响应体有界限制
- **源码位置**：`engine-service/src/main/java/org/gmssl/gui/engine/ExecutionService.java:261-263,287`
- **具体问题**：
  - 同步阻塞 `client.send(httpReq, ...)` 期间未轮询 `live.cancelled` 状态；且使用 `HttpResponse.BodyHandlers.ofByteArray()` 会将全量大响应体接收进内存后才校验 413，存在恶意大体积 CRL 导致 OOM 的风险。
- **状态**：**已修复闭环** (integration 已补充整体超时控制与流式大小拦截)。

---

## 3. 本轮新增最终审查项

### REV-11: SCT 与 CRL 标准适配 5 Overlay 补丁合入
- **涉及模块**：`native/` 原生 Runner 与底层扩展 (runner commit `36a05a...`)
- **审查描述**：
  - 上游 GmSSL 固定提交在 RFC 6962 SCT 证书扩展及特定 CRL 分发点扩展处理上存在参数边界与格式解析缺陷。
  - native 模块引入了 5 个覆盖补丁（overlay），并在 `extensions.c` 中补齐了 P256/SCT 及 CRL 扩展规范适配。
  - 验证证据：通过 Lead 独立标准 P256/SCT+CRL 5 组用例实测，以及 231 项扩展算法测试与根 Java 21 测试，runner 行为完全符合预期且零回归。
- **状态**：**已验证并闭环**。

### REV-12: 材料安全删除时序与孤立临时文件周期重试清理
- **涉及模块**：`platform-service/Materials.java`, `MaterialController.java`, `VaultRecovery.java`
- **审查描述**：
  - **安全删除时序 (Safe Delete)**：修复前材料删除操作存在若先物理删除 Vault 密文再校验外键或事务提交失败，导致“磁盘密文已删但数据库记录残留”的不一致风险。整改后实现先做严格项目归属与 RBAC 权限校验，在事务内提交数据库清理，再安全回收物理 Vault 密文。
  - **孤立临时文件自动回收机制**：`VaultRecovery.java` 增加了 `@Scheduled(fixedDelay = 60000)` 周期扫描任务，定时检索创建超过 1 小时且未被任何任务绑定的孤立临时文件（`temporary=true and bound_job_id is null`），自动执行物理清理与重试，彻底杜绝恶意大量上传临时文件占满磁盘。
  - 验证证据：`PlatformIntegrationTest` (10/10 PASS) 及全量 HTTP 端到端回归 `tests/e2e/results/e2e_da8dcd9d89/report.json`。
- **状态**：**已修复并实测验证**。
