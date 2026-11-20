# DM8 生产 Bean / Spring 事务 / 非成员权限补测

## 最终结论与实际命令

- task-40 最后一次完整实测：**PASS，27 条断言，Java 与 Python runner 退出码均为 0**；27 是断言数，不是 27 个独立业务场景。
- 重跑命令：仓库根目录执行 `python3 tests/dm/run_production_verification.py`；仅离线编译可追加 `--compile-only`。
- 最新脱敏日志：`.tools/logs/dm-production-verification.log`，mtime **2026-10-19T16:34:27+0800**，权限 0600。
- 本轮 UUID-only ledger：`tests/dm/target/dm-production-ledger-208c382ade8e0177.json`，0600，记录 2 用户 / 1 项目 / 3 材料，无账号名或秘密。

## 真实调用链与证据边界

以下 helper 简称 `tests/dm/src/org/gmssl/gui/platform/Dm8ProductionVerification.java`，所有行号均指最终冻结源码。

1. **冻结生产类**：helper:27-28 直接导入 production Store/Vault/Materials/CredentialService/Auth/AccountController/ErrorAdvice；:163 检查 CredentialService 的 CodeSource 来自抽取的冻结 JAR BOOT-INF/classes。不是复制 AES 或自写业务服务。
2. **最小 Spring 上下文**：生产 Controller 与 Auth 经真实 loopback HTTP 调用；DataSource 是测试配置的 DriverManagerDataSource，Spring 自动装配 JdbcTemplate、PlatformTransactionManager、TransactionTemplate。不是完整 PlatformApplication 引导/全服务验收；没有 Jobs、定时清理或 Engine 任务。
3. **目标隔离**：helper:52-65 在应用启动前校验测试用户名/schema 命名并与真实连接的 getSchema()/getUserName() 对齐；不打印这些值。Python 仅读取唯一私有 .env.dm-test，不读取其他 .env。
4. **真实非成员 403**：helper:175-190 以真实生产 API 创建项目、普通用户并登录，确认其无 membership，再执行 GET /api/v1/projects/{pid}，断言 HTTP 403 且 code=FORBIDDEN。脱敏日志含 GET 路由与实际 status=403，不靠角色字段推断。
5. **真实生产加解密**：helper:195-205 调用 Materials.create、CredentialService.savePassphrase/getPassphrase、Materials.raw/dto、Vault.read。512 字节随机测试口令得到 540 字节真实 GCM 信封，生产解密回读完全一致，数据库字段不等于明文。
6. **生产实现定位**：CredentialService.java:41/46/52 为 savePassphrase→Vault.encryptWithAad→TransactionTemplate，:80/93 为 getPassphrase→Vault.decryptWithAad；Materials.java:64/71/107 为 create→createControlled→TransactionTemplate，:156 为生产 delete。执行加载的是冻结 JAR，而非重新编译这些源文件。
7. **两种真实 Spring 回滚**：helper:207-226 中同一 TransactionTemplate 包裹 production Materials.create 与 CredentialService.savePassphrase，先确认两表事务内均有记录，分别 setRollbackOnly() 和抛 ControlledAbort；没有用手工 conn.rollback 代替 Spring。
8. **独立连接观察**：helper:86-94 直接 ds.getConnection()，不是 Spring 事务绑定的 JdbcTemplate 连接；:223-226 逐次断言本轮 material ID 在 materials 与 key_credentials 均为 0。
9. **本轮清理**：helper:232-262 按 ledger 内本次 ID 清理材料、凭据、用户、会话、项目、membership 和 audit；独立连接核验本轮三材料两表为零、两用户及其 sessions/actor audit 为零、项目及 membership/project audit 为零。结论仅限本轮，不声称整个 schema 为空。
10. **临时资源**：本轮 Java 进程 exit 0，try-with-resources 关闭测试 Spring/Tomcat 与随机端口；Python TemporaryDirectory 清理该次绝对临时目录及 Vault，离线检查 production-* 临时目录剩余 0。没有按进程名 kill，也没有启停既有 H2 服务。

## 首轮失败及恢复记录

- 首轮核心生产验证成功，但 helper 清理误用了 audit_events.user_id（冻结 DDL 实际为 actor），整体 exit 1；没有把该轮宣称为完整通过。
- 修正仅限测试 helper。一次性恢复按独有 admin 前缀、近 30 分钟创建时间、CREATE_USER 审计、OWNER 关联项目交叉限定，确认恰好两用户一项目且无材料/任务后，以精确 ID 在事务中清理；没有 DELETE LIKE。
- 恢复证据：`.tools/logs/dm-production-recovery.log`，6 条断言、exit 0、0600。恢复时尚未持久化 UUID ledger，存在流程缺口；未追造已删除 ID。后续 runner:74-78 均在 Java/数据库写入前创建空 0600 ledger，再随本次创建结果记录 UUID。
- 既有 Dm8CompatibilityHarness 的 540B 是合成 0x5a 字节；旧回滚只覆盖材料行。它们仍是 JDBC 能力证据，不转述成生产凭据/Spring 双表事务。本报告的新生产 AES 与两种 Spring 双表回滚结论仅由本次 helper 实测支撑。

## 冻结身份（补测后重新 SHA-256 核对，均未修改）

| 工件 | SHA-256 |
|---|---|
| deploy/gmssl-gui-linux-amd64/artifacts/platform-service-0.1.0-SNAPSHOT.jar | 19842a750c9581479163727febdb3fedac8078620b8e0645571f9fd04a3279d8 |
| deploy/gmssl-gui-linux-amd64/artifacts/01_schema_dm8.sql | 32d422f198c02819ed54710a17eac363b4487e63b0f33261c6d7777349c799da |
| deploy/gmssl-gui-linux-amd64.tar.gz | 223c40e5a592a2be359060bf4ba950178cd6830d01f5f3c7c0d084b00e5e5587 |
| tests/dm/src/org/gmssl/gui/platform/Dm8ProductionVerification.java（267 行） | 5ed2780a17f721c1555502814f44afb30f6546b9de3b06cee2242bba2633d938 |
| tests/dm/run_production_verification.py（117 行） | 223485565d0c25177f047f2872d5326c6d0e645e899a468f43040c71ec110e40 |

仅新增上述两份测试源码与本报告，另产脱敏日志和 UUID ledger；未改 production 源码、JAR、DDL、release、旧 owner 报告或原 JDBC harness。最终源码/日志/报告现已冻结，交 architecture task-41 独立只读复核，不并行连库。
