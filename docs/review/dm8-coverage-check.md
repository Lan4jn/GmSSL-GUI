# DM8 验收覆盖事实校准

- 范围：静态阅读 `tests/dm` 四个公开 Java 源文件、`dm8-acceptance.md` 与归档 `.sha256`；未连接数据库、执行测试或读取私有日志/环境文件。
- 当前公开 Java 类为 `Dm8CompatibilityHarness`、`Dm8AppSmokeTest`、`Dm8AppLifecycleTest`、`Dm8MetadataChecker`；未找到高级验证 class。
- 四文件均未出现生产 `CredentialService` 方法调用或生产 `Materials` 方法调用；`Materials` 仅见于注释。
- 四文件均未出现 Spring `TransactionTemplate`、事务管理器或生产 Bean 获取/注入调用链。
- `Dm8CompatibilityHarness.main`：`tests/dm/src/org/gmssl/gui/platform/dm/Dm8CompatibilityHarness.java:178-180` 将 540 字节数组填充为 `0x5a`；不是 Cipher 加密产物，源码亦未构造 AAD。
- 同方法 `:193-218` 用 JDBC PreparedStatement 写入材料和凭据并 `conn.commit()`；`:220-230` 比较凭据字段字节一致性。
- 同方法 `:239-255` 在新事务内仅插入材料后 `conn.rollback()`；`:257-262` 仅检查材料计数为零。
- 此 rollback 分支没有新增凭据或检查凭据残留；前一分支的凭据已在 `:218` 提交。
- 因此公开源码证明的是 JDBC 二进制往返及材料行回滚测试设计，不是生产 CredentialService/Materials Bean 或 Spring 多表事务验证。
- `Dm8AppLifecycleTest.main` 的 `:62-82` 启动应用，`:105-119` 仅探测 HTTP session；其注释列举材料 API 并非实际调用证据。
- `docs/review/dm8-acceptance.md:62-64` 的“100% 一致 AAD / 生产数据层等价 / 两表零残留”超出上述公开源码证据，应收窄或另附实际 helper 源码。
- 当前 `deploy/gmssl-gui-linux-amd64.tar.gz.sha256:1` 为 `223c40e5a592a2be359060bf4ba950178cd6830d01f5f3c7c0d084b00e5e5587`。
- 当前 `dm8-acceptance.md:90` 已引用同一完整值；该文件未检出 `1f37`，integration 早前报告的 `1f37…` 属旧身份，不应继续用于本归档。
- 本次仅读取摘要文件，未重新计算压缩包哈希；既有真实连接、9 项 JDBC、应用登录/项目/RBAC运行结论不在本次重跑范围。
