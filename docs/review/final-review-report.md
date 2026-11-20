# 独立审查与端到端验收最终报告

**报告日期**：2026-10-16  
**上游代码基线**：commit `24ae482701a7b124826c382fffc55c19f76d475d` (GmSSL v3.3.0-dev.1183)  
**冻结执行版本**：runner commit `36a05a...` (集成 5 overlay 原生补丁)、platform 最新安全删除时序与周期清理机制  
**审查员身份**：独立审查员 (teammate `architecture`)  
**写边界声明**：所有测试脚本与报告输出严格限定于 `tests/e2e/` 与 `docs/review/`，未改动任何业务实现与工程模块代码。

---

## 1. 自动化验收实测数据与机器可读报告索引

本轮端到端自动化验收包含三套独立运行套件，**所有实测结论均基于真实服务与本地环境运行生成的机器可读报告，无任何 Mock、占位符或假通过**：

| 测试套件 | 验证范围 | 最终实测统计 | 结果报告路径 |
|---|---|---|---|
| **原生 Runner 协议与参数防泄露** (`native_runner_acceptance.py`) | 11 类畸形/截断/NUL/超长协议帧校验拦截、非法 OS argv 探测拒绝、真实 SM3 "abc" KAT、长任务 stdin 秘密不在 OS argv 泄露 (ps 实时监测) | **14 PASS / 0 FAIL** | `tests/e2e/results/native_089e9379fe/report.json` (`report.txt`) |
| **基础与业务 HTTP 端到端隔离** (`http_acceptance.py`) | 匿名访问拦截、真实双用户登录与 Cookie HttpOnly/SameSite 隔离、CSRF 校验、RBAC 角色保护（最后 Owner 保护/VIEWER 限制）、双用户/双项目物理隔离、真实 SM3/SM4-GCM/SM2 密码操作、**临时文件全生命周期闭环（FILE-01）**、状态型私钥受控单一权威、任务超时/取消/并发限流、内部 Token 认证、非法网络阻断、全链路敏感信息泄露扫描（**深度扫描 238 个持久化与日志文件无明文密钥**） | **21 PASS / 0 FAIL / 1 SKIP** *(SKIP: STATE-03 由专有套件独立执行)* | `tests/e2e/results/e2e_da8dcd9d89/report.json` (`report.txt`) |
| **状态型 pending 重启恢复隔离实测** (`stateful_restart_acceptance.py`) | 启动隔离 platform 实例（随机端口、独立 H2、隔离 vault），生成真实 LMS 密钥并首签；停机后直连 H2 注入故障标记 (`pending=true`, `status='RUNNING'")；重启验证原任务转 FAILED、pending 标记跨生命周期持久保留且阻止后续签名产物泄露 | **3 PASS / 0 FAIL** | `tests/e2e/results/restart_18958922c3/report.json` (`report.txt`) |

---

## 2. 核心专项验收结论

### 2.1 临时文件生命周期（FILE-01 已完全闭环）
- **功能契约实现**：
  1. `POST /projects/{pid}/files` 支持 `temporary: true` 参数；
  2. `POST /projects/{pid}/keys` 传入 `temporary: true` 时被严格拒绝（400），临时标记仅对普通文件有效；
  3. 任务使用临时文件时，数据库原子执行 CAS 绑定（`bound_job_id=? where id=? and bound_job_id is null`），并发二次消费被拒绝（409/400）；
  4. 任务达到终态（成功/失败/超时）或排队取消后，系统自动物理清理数据库记录与 Vault 密文，后续单文件查询与下载均返回 404；
  5. 普通永久文件不受任何影响，保持长期持久化与可重复读取。
- **实测证据**：`tests/e2e/results/e2e_da8dcd9d89/report.json` (PASS FILE-01)。

### 2.2 状态型密钥防重放与重启恢复（STATE-01 ~ STATE-03）
- **单一权威原则**：禁止外部导入状态型私钥（LMS/HSS/XMSS/XMSSMT）；仅允许受控 keygen 任务产物进行唯一晋升；数据库通过 `stateful_promotions` tombstone 永久禁止重复晋升；禁止原始私钥下载与复制。
- **Durability 与 Fail-Closed**：私钥写入 Vault 落地时强制对文件及父目录执行 fsync（`force(true)`）；若写入失败则以 `VAULT_ERROR` fail-closed 保留 pending 标记。
- **断电恢复边界声明**：
  `stateful_restart_acceptance.py` 是在受控测试环境下，直连隔离 H2 数据库对专属材料注入 `pending=true` 和 `RUNNING` 状态以模拟进程崩溃中断。**该项实测证明了平台重启恢复扫描与 pending 跨生命周期阻断逻辑的正确性，但不等同于物理断电或整机断电的硬件级断电抗性证明**。

### 2.3 网络策略与端口语义澄清（NETWORK-01 与 REV-09）
- **监听端口（Listen Port）**：维持严防特权端口滥用原则，必须 `port >= 1024` 且必须落在 `allowedPorts` 白名单中；
- **出站目标端口（Outbound Target Port）**：支持目标端口范围 `1..65535`，但**必须显式包含在 `allowedPorts` 白名单内**（例如 80/443 默认不放行，需运维显式授权）；
- **目标地址防护**：云元数据 (169.254.169.254)、链路本地、多播、广播地址无论端口如何一律总禁，目标 IP 必须严格白名单匹配。

---

## 3. 审查发现与缺陷追踪汇总 (REV-01 ~ REV-12)

在本次独立审查全流程中，审查员共提出 12 项核心架构与安全发现，推动各模块 owner 修复闭环：

1. **REV-01 (`Materials.java`)**：SQL 占位符数量越界，导致 materials 插入全部异常。-> *已修复*。
2. **REV-02 (`Vault.java`)**：atomic move 前缺少父目录 fsync，断电易致目录项丢失。-> *已修复 (补充父目录 force(true))*。
3. **REV-03 (契约架构)**：状态型私钥缺乏单一权威，存在重放攻击风险。-> *已闭环 (确立单一晋升与 tombstone 机制)*。
4. **REV-04 (`ExecutionService.java`)**：任务取消与提交存在注册时间窗口竞态。-> *已修复 (引入 cancelledIds tombstone)*。
5. **REV-05 (`ExecutionService.java`)**：任务运行期间缺少实时输出目录限额监控。-> *已修复 (50ms 轮询检测)*。
6. **REV-06 (`ExecutionService.java`)**：工作目录清理失败被静默吞掉，存在残留泄密。-> *已修复 (引入检疫隔离与报警机制)*。
7. **REV-07 (`catalog.json`)**：关键算法缺少 `allowedKeyKinds` 导致平台白名单拒绝。-> *已修复 (重生成 catalog 并更新打包)*。
8. **REV-08 (`ExecutionService.java`)**：CRL 提取中 ASN.1 粗糙匹配与越界异常。-> *已修复 (引入 DerReader 严格 remaining 与 parent 边界保护，通过 5 组 CRL 测试与 231 项扩展测试)*。
9. **REV-09 (`NetworkPolicy.java`)**：监听与出站端口语义混淆，导致缺省 80 端口被拦截。-> *已澄清 (契约重塑为监听与出站独立语义)*。
10. **REV-10 (`ExecutionService.java`)**：网络抓取无整体绝对超时与大响应体流式拦截。-> *已修复 (引入全局超时与流式拦截)*。
11. **REV-11 (`native/` 扩展)**：SCT 与 CRL 规范适配补丁。-> *已通过 5 个原生 overlay 补丁及 Lead 独立标准 P256/SCT+CRL 5 类专项测试闭环*。
12. **REV-12 (`platform-service/`)**：材料安全删除时序与孤立临时文件定时重试回收。-> *已通过权限先行校验、事务内安全清理与定时重试任务闭环，通过 PlatformIntegrationTest 10/10 PASS 及最终 HTTP 回归验证*。

---

## 4. 生产环境边界声明与技术局限性说明

按照系统安全审查要求，明确以下运行边界与尚未在当前单机开发环境中实测的事项：

1. **Docker / Linux / PostgreSQL 生产矩阵未实测**：
   - 当前所有端到端与集成验证均在 macOS ARM64 环境配合内置嵌入式 H2（PostgreSQL 兼容模式）执行；
   - 生产环境的 Docker 容器镜像交付、真实 Linux 发行版内核（如 cgroups、seccomp 策略）以及独立高可用 PostgreSQL 物理数据库集群，需在发布流水线中补充专用实测验证。
2. **上游 GmSSL C 库未全量覆盖 ASan 测试**：
   - 依赖的上游 C 代码库及原生扩展在本次编译中未启用全链路 AddressSanitizer (ASan) 或长时间的 Fuzzing 模糊测试，生产部署面临未覆盖代码分支引发底层段错误的潜在隐患。
3. **QUIC 协议支持为实验性原型**：
   - 系统的 QUIC 协议套件基于 GmSSL 原生试验性代码实现，适用于功能联调与受控测试，尚未达到抗网络抖动、高并发丢包及生产级工业级安全加固标准。
4. **硬件级物理断电恢复抗性未验证**：
   - 状态型密钥的重启恢复（STATE-03）验证了软件层面由异常退出留下的 pending 标记能正确阻断后续签名并防范回滚，但由于未在物理断电、磁盘写入掉电或存储控制器崩溃条件下进行破坏性测试，不能等同于物理断电抗性证明。

---

## 5. 最终审查结论

经独立审查与最后一次 shared HTTP 21 全量回归测试（报告：`tests/e2e/results/e2e_da8dcd9d89/report.json`），系统在密码功能完备性、会话安全、RBAC 保护、多租户强隔离、状态型私钥单一权威以及临时文件安全删除全生命周期上均已达标并留存完备证据。独立审查员确认**接受当前冻结版本**，Task-8 正式交付完成。
