# 达梦数据库 (DM8) 适配改造精简实施计划

**计划编号**：`PLAN-DM8-01`  
**关联任务**：`task-34` 冻结 DM8 改造计划与验收约束  
**责任人**：`architecture` (系统架构师)  
**编写依据**：
- `docs/review/dm-migration-inventory.md`（架构盘点与 V1..V6 历史保护原则）
- `docs/review/dm-dependency-research.md`（官方 Maven 依赖与 Flyway 11 兼容性事实）
- `docs/DM8-CONNECTION.md` & `.env.dm-test.example`（实库测试隔离与安全保护规则）
**冻结技术路线**：
- 官方 JDBC 驱动：`com.dameng:DmJdbcDriver18:8.1.3.140` (Maven Central 原生依赖)。
- 迁移策略：DM 环境通过 Spring Profile (`spring.profiles.active=dm`) 显式关闭 Flyway 自动迁移 (`spring.flyway.enabled=false`)；采用独立外部 DBA 初始化 DDL 脚本 (`platform-service/src/main/resources/db/dm/schema.sql`)。
- 历史保护：**严格保留现有 H2 / PostgreSQL 的 `db/migration/V1..V6` 全部 6 个文件原字节不动**，绝不进行就地修改，彻底杜绝破坏既有环境的 Flyway 校验和。
- 架构约束：不自写复杂的 Flyway SPI 数据库适配插件，不自研庞大的迁移器框架；本地开发与单元/集成测试继续默认保持 H2 内存库运行，对现有开发人员体验 0 侵入。

---

## 一、三专职 Worker 职责划分与精确文件边界

```
┌─────────────────────────────────────────────────────────────┐
│                      实施依赖流 (DAG)                        │
└─────────────────────────────────────────────────────────────┘
  [Phase 1: platform] 数据层依赖 + DM Profile + 独立 DDL 脚本
         │
         ├───> [Phase 2: integration] 独立空 Schema 实库连通与行为验证
         │
         └───> [Phase 3: build-quality] 独立部署包/Compose/README 运维改造
                         │
                         ▼
               [Phase 4: architecture] 终审独立验收与报告封版
```

---

### Phase 1: `platform` 数据层与配置改造

**责任人**：`platform`  
**工作目标**：在不破坏现有开发测试前提下，引入达梦官方驱动、配置独立 DM profile、提供独立达梦 DDL 脚本。  
**允许修改与新建的文件边界**：
- `platform-service/pom.xml` (修改)
- `platform-service/src/main/resources/application-dm.yml` (新建)
- `platform-service/src/main/resources/db/dm/schema.sql` (新建)

**具体实施规约**：
1. **Maven 依赖引入 (`platform-service/pom.xml`)**：
   - 引入达梦官方 Central 驱动依赖，保持 `runtime` 作用域：
     ```xml
     <dependency>
         <groupId>com.dameng</groupId>
         <artifactId>DmJdbcDriver18</artifactId>
         <version>8.1.3.140</version>
         <scope>runtime</scope>
     </dependency>
     ```
   - 保留现有的 `flyway-core`, `flyway-database-postgresql`, `postgresql`, `h2` 不动。
2. **达梦专用配置 (`platform-service/src/main/resources/application-dm.yml`)**：
   - 显式声明关闭 Flyway 自动执行，配置达梦驱动类名与连接占位符：
     ```yaml
     spring:
       flyway:
         enabled: false
       datasource:
         driver-class-name: dm.jdbc.driver.DmDriver
         url: ${SPRING_DATASOURCE_URL:jdbc:dm://localhost:5236?schema=GMSSL&caseSensitive=true}
         username: ${SPRING_DATASOURCE_USERNAME:gmssl}
         password: ${SPRING_DATASOURCE_PASSWORD:}
     ```
3. **达梦独立 DDL 脚本 (`platform-service/src/main/resources/db/dm/schema.sql`)**：
   - 包含系统全量 9 张表的最新结构与索引（汇总 V1..V6 变更），供用户 DBA 在达梦实库预先执行。
   - **关键字段适配**：
     - `key_credentials` 表中的 `encrypted_passphrase` 字段明确定义为 `varbinary(4096) not null`（避免 PostgreSQL 专有 `bytea` 报错，避免 `BLOB` 的 DmdbBlob 强制转型异常）。
     - 其余表结构保持标准 ANSI SQL 声明（`varchar(36)` 主键、`varchar(40)` 时间戳、外键约束、`audit_project` 复合索引）。
4. **自测验收门槛**：
   - 执行 `scripts/mvn.sh -pl platform-service test`：**现有 100% 单元/集成测试必须全部保持 PASS**（验证 H2 默认模式未受任何破坏）。

---

### Phase 2: `integration` 达梦实库连通与行为独立验证

**责任人**：`integration`  
**工作目标**：使用用户提供的本地 Mac 可达的达梦独立空测试 schema（配置于私有 `.env.dm-test`），运行独立探测脚本，核验实库真实语法与行为。  
**前置条件**：用户已根据 `.env.dm-test.example` 填妥私有配置 `.env.dm-test`（由外部提供测试实例，严禁使用生产或 SYSDBA schema）。  
**允许修改与新建的文件边界**：
- `tests/database/test_dm8_live_connection.py` 或 `tests/database/` (新建独立测试工具/用例)
- `.tools/logs/dm-live-test-*` (日志输出)
- `docs/review/dm-live-verification.md` (测试实据报告)

**核心核验用例与实库检查清单**：
1. **Schema 隔离检查**：检查连接目标为独立空测试 schema，禁止 SYSDBA / SYS / CTISYS 等系统账户；禁止回显任何明文密码。
2. **DDL 幂等建表验证**：直连执行 `platform-service/src/main/resources/db/dm/schema.sql`，验证 9 张表及索引在目标 DM8 实例上成功建立，无语法或类型报错。
3. **VARBINARY / 二进制映射实测**：
   - 写入一段测试二进制字节流（模拟 AES-256-GCM 密文），执行 `select encrypted_passphrase from key_credentials`。
   - 验证 JDBC `ResultSet.getObject()` 返回的具体 Java 类（验证是否为 `byte[]`，确认与 `CredentialService.java:89` 的 `(byte[])` 强制类型转换完全相符）。
4. **悲观行锁 (`FOR UPDATE`) 并发实测**：
   - 开启双连接事务，连接 1 执行 `SELECT ... FOR UPDATE`，连接 2 验证排他锁等待行为及事务提交后的正常释放。
5. **大小写与 JSON 映射实测**：
   - 验证双引号别名（`"userId"`, `"resourceType"`）大小写保留。
   - 验证未加双引号列名在 Spring `ColumnMapRowMapper` 及 Jackson JSON 序列化中的实际输出 Key，确认不影响前端属性解析。
6. **验收报告产出**：输出 `docs/review/dm-live-verification.md`，附带实库详细版本号、`COMPATIBLE_MODE` 参数与各用例执行证据。

---

### Phase 3: `build-quality` 部署包与运维文档改造

**责任人**：`build-quality`  
**工作目标**：适配外部已有达梦数据库实例场景，改造部署编排、初始化检查、配置模板与 README 文档。  
**允许修改与新建的文件边界**：
- `deploy/gmssl-gui-linux-amd64/compose.yaml` (修改)
- `deploy/gmssl-gui-linux-amd64/.env.example` (修改)
- `deploy/gmssl-gui-linux-amd64/README.md` (修改)
- `deploy/gmssl-gui-linux-amd64/scripts/check.sh` & `init.sh` (修改)
- `scripts/package-linux-amd64.sh` (修改)
- `tests/deployment/` (回归用例更新)

**具体实施规约**：
1. **Compose 服务解耦**：
   - 按需求“直连外部已有达梦实例，不内置 PG 容器”原则：
     - 在 `compose.yaml` 中移除内置的 `postgres:17-alpine` 服务及 `postgres-data` 卷定义。
     - `platform` 服务环境变量中：
       ```yaml
       SPRING_PROFILES_ACTIVE: dm
       SPRING_DATASOURCE_URL: ${SPRING_DATASOURCE_URL:?Set external DM8 JDBC URL}
       SPRING_DATASOURCE_USERNAME: ${SPRING_DATASOURCE_USERNAME:?Set DM8 username}
       SPRING_DATASOURCE_PASSWORD: ${SPRING_DATASOURCE_PASSWORD:?Set DM8 password}
       ```
2. **初始化与配置模板 (`.env.example`)**：
   - 提供清晰的达梦连接串示例：
     ```bash
     SPRING_PROFILES_ACTIVE=dm
     SPRING_DATASOURCE_URL=jdbc:dm://192.168.1.100:5236?schema=GMSSL&caseSensitive=true
     SPRING_DATASOURCE_USERNAME=gmssl_user
     SPRING_DATASOURCE_PASSWORD=your_secure_password
     ```
3. **运维与备份指引 (`README.md`)**：
   - 增加“达梦数据库前置准备”章节：说明运维 DBA 需预先执行 `schema.sql` 初始化表结构。
   - 替换原有 PostgreSQL 备份指导为达梦官方备份说明（删除 `pg_dump`，指导使用达梦 `dexp / dimp` 逻辑导出工具）。
4. **重新打包与自检**：
   - 运行 `scripts/package-linux-amd64.sh` 生成最新的达梦适配独立部署包，更新 `SHA256SUMS` 与 `manifest.json`。
   - 运行 `tests/deployment/` 测试套件，确保语法、安全权限与排除项全部 PASS。

---

### Phase 4: `architecture` 独立终审与验收归档

**责任人**：`architecture`  
**工作目标**：对 platform、integration、build-quality 的最终产物进行独立复核。  
**验收标准**：
1. `V1..V6` 历史迁移脚本字节完全未被修改（校验和与历史提交一致）。
2. `application-dm.yml` 与 `schema.sql` 语法合规。
3. `mvn test` 现有本地测试套件 100% 通过。
4. 部署归档中无敏感信息，达梦配置支持开箱即用。
5. 出具达梦适配综合终审报告 `docs/review/dm-final-acceptance.md`。

---

## 二、关键约束与红线规约 (Red Lines)

1. **🚫 严禁就地修改 `db/migration/V1..V6`**：已有迁移脚本的原字节受 Flyway 校验和严格保护，任何原文件修改均视为重大事故。
2. **🚫 严禁自写大而化之的 Flyway SPI 数据库方言插件**：避免在工程中引入对 Flyway 11 内部私有 API 的高度耦合。
3. **🚫 严禁将 H2 的兼容模式视为达梦实库兼容证据**：所有实库兼容性断言必须来自于真实的 DM8 实例测试日志。
4. **🚫 严禁泄露真实私有凭据**：`.env.dm-test` 必须始终处于 `.gitignore` 忽略范围，严禁在任何脚本、日志或提交信息中打印达梦密码。
5. **🚫 严禁执行未受保护的 Git 操作**：未经指令严禁执行 `git commit` 或 `git push`。
