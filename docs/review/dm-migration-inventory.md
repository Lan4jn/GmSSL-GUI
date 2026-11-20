# 数据库切换达梦 (DM8) 只读盘点与迁移评估报告 (已校准)

**任务编号**：`task-31` 盘点 PostgreSQL 耦合点并评估达梦迁移路径  
**责任人**：`architecture` (系统架构师)  
**审查性质**：**纯只读静态分析与盘点**（未修改任何业务源码、未启停服务、未读取私有凭据）  
**目标环境**：达梦数据库 8 (DM8) 外部已有独立空测试 schema 实例连接，严格保留现有 H2 开发测试历史与已有 Vault/H2 数据不动。  
**日期**：2026-10-19 (第二版校准)  

---

## 一、盘点核心结论摘要与边界界定

1. **整体耦合度评级**：**低到中度（Low-Medium）**。
   - 系统基于 Spring `JdbcTemplate` 原生 SQL 交互，无复杂 ORM（无 Hibernate 级联与实体状态机）。
   - **零深度 PG 专有高级语法依赖**：全工程 **0 处** `ON CONFLICT`、**0 处** `RETURNING`、**0 处** `SKIP LOCKED`、**0 处** `INTERVAL` 算子、**0 处** `::` 类型强转、**0 处** `JSON/JSONB` 数据库类型操作、**0 处** `BIGSERIAL/SERIAL`。
   - 主键在 Java 层生成为 UUID 字符串（`VARCHAR(36)`），时间戳在 Java 层生成为 ISO-8601 字符串（`VARCHAR(40)`），不依赖数据库自增序列与数据库函数。
2. **核心阻塞点（Blockers）与设计纠偏**：
   - **🚨 历史迁移文件校验和不可破坏原则**：原 `db/migration/V1..V6` 是已有生产/开发环境（H2、PostgreSQL）的已应用迁移，**严禁直接修改 `V6__key_credentials.sql` 原文件**（否则会导致已应用库的 Flyway 校验和报错中断）。
   - **迁移路径方案**：达梦采用**独立迁移目录**（如 `classpath:db/migration/dm` 或按数据库厂商配置多源路径），DM 独立脚本中使用达梦支持的二进制类型定义，严禁污染或篡改历史通用脚本。
   - **事实与推断的严格界定**：本报告中的所有达梦语法兼容性、BOOLEAN 映射、LOB/VARBINARY 返回类型均标记为**静态推断（待实库核验）**，绝不将 H2 本地运行等同于达梦实库证据。实库真实行为须在后续独立空 schema 连通测试中进行逐项确认。
3. **迁移实施路线定调**：
   - 最低风险 route 保持开放，等待 `integration` (`task-32`) 对官方 DM8 JDBC 工件与 Flyway 原生/插件支持的调研实证，不盲目预设“自写 SPI 适配器”。

---

## 二、Flyway 迁移脚本兼容性逐行盘点 (V1..V6)

当前平台共有 6 个 Flyway 脚本（路径：`platform-service/src/main/resources/db/migration/`）：

| 脚本文件 | 行号 | 源码原句 | 静态分析与达梦兼容性推断 | 迁移架构设计方案 |
| :--- | :--- | :--- | :--- | :--- |
| `V1__platform.sql` | 1 | `create table app_users(id varchar(36) primary key, username varchar(100) not null unique, password_hash varchar(100) not null, role varchar(10) not null, enabled boolean not null, created_at varchar(40) not null);` | **推断兼容（待实库核验）**。DM8 语法支持 `BOOLEAN`，内部通常映射为 BIT/TINYINT。 | 原文件保留。DM8 独立脚本中根据实库配置决定保留 `boolean` 或显式写为 `bit/tinyint`。 |
| `V1__platform.sql` | 2 | `create table sessions(token_hash varchar(64) primary key, user_id varchar(36) not null references app_users(id), csrf varchar(100) not null, expires_at bigint not null);` | **完全兼容**。外键及 `bigint` 均与 ANSI SQL 一致。 | 原文件保留。 |
| `V1__platform.sql` | 3 | `create table projects(id varchar(36) primary key, name varchar(200) not null, description varchar(2000) not null, created_at varchar(40) not null);` | **完全兼容**。`varchar(2000)` DM8 原生支持。 | 原文件保留。 |
| `V1__platform.sql` | 4 | `create table memberships(project_id varchar(36) not null references projects(id), user_id varchar(36) not null references app_users(id), role varchar(10) not null, primary key(project_id,user_id));` | **完全兼容**。复合主键与外键标准语法。 | 原文件保留。 |
| `V1__platform.sql` | 5 | `create table materials(... stateful boolean not null, pending boolean not null ...);` | **推断兼容（待实库核验）**。BOOLEAN 字段在 DM8 正常映射。 | 原文件保留。 |
| `V1__platform.sql` | 6 | `create table jobs(... truncated boolean not null);` | **推断兼容（待实库核验）**。`varchar(8000)` 与 `boolean` 兼容。 | 原文件保留。 |
| `V1__platform.sql` | 7 | `create table artifacts(id varchar(36) primary key references materials(id), job_id varchar(36) not null references jobs(id), sensitive boolean not null);` | **完全兼容**。共享主键外键约束。 | 原文件保留。 |
| `V1__platform.sql` | 8 | `create table audit_events(...);` | **完全兼容**。标准字符与无自增主键。 | 原文件保留。 |
| `V1__platform.sql` | 9 | `create index audit_project on audit_events(project_id,created_at);` | **完全兼容**。复合 B-Tree 索引标准语法。 | 原文件保留。 |
| `V2__stateful_dedup.sql` | 1 | `create table stateful_material_history (digest varchar(64) primary key, material_id varchar(36) not null, created_at varchar(40) not null);` | **完全兼容**。标准 ANSI 表定义。 | 原文件保留。 |
| `V3__controlled_stateful_keys.sql` | 1 | `alter table artifacts add column stateful_private boolean not null default false;` | **推断兼容（待实库核验）**。DM8 支持 ALTER TABLE ADD COLUMN 语法，DEFAULT false 需实库确认。 | 原文件保留。 |
| `V3__controlled_stateful_keys.sql` | 2 | `create table stateful_promotions(source_artifact_id varchar(36) primary key, key_id varchar(36) not null, created_at varchar(40) not null);` | **完全兼容**。 | 原文件保留。 |
| `V4__stateful_source.sql` | 1 | `alter table artifacts add column stateful_source boolean not null default false;` | **推断兼容（待实库核验）**。 | 原文件保留。 |
| `V5__temporary_files.sql` | 1 | `alter table materials add column temporary boolean not null default false;` | **推断兼容（待实库核验）**。 | 原文件保留。 |
| `V5__temporary_files.sql` | 2 | `alter table materials add column bound_job_id varchar(36);` | **完全兼容**。 | 原文件保留。 |
| `V6__key_credentials.sql` | 3 | `encrypted_passphrase bytea not null,` | **🚨 静态语法不兼容 (BLOCKER)**。`bytea` 是 PostgreSQL 专属类型，DM8 原生解析器会报错。 | **严禁直接修改 V6 原文件**。在 DM8 独立迁移脚本目录中，此列定义为 `varbinary(4096)`。 |
| `V6__key_credentials.sql` | 8 | `alter table materials add column generation_provider varchar(20);` | **完全兼容**。 | 原文件保留。 |

---

## 三、Java 业务层 SQL 字符串与 JdbcTemplate 交互盘点

经全量扫描，系统数据库操作全部收敛于 `platform-service`，`engine-service` 为纯计算微服务（无任何数据库交互）。

### 1. 语法特性盘点表
- `ON CONFLICT`：**0 处**。所有去重/更新逻辑在 Java 层先查询后插入/更新（如 `CredentialService.java:61-75`）。
- `RETURNING`：**0 处**。所有主键均由 Java 生成，插入后无需 `RETURNING id`。
- `FOR UPDATE SKIP LOCKED`：**0 处**。无基于 SQL 队列表的 SKIP LOCKED 消费。
- `SELECT ... FOR UPDATE`：**共 6 处**（ANSI/Oracle 标准行级悲观锁，待达梦实库多连接并发核验）：
  1. `CredentialService.java:56`: `"select id from materials where project_id=? and id=? for update"`
  2. `Materials.java:159`: `"select * from materials where project_id=? and id=? for update"`
  3. `JobController.java:102`: `"select id from artifacts where id=? for update"`
  4. `AccountController.java:66`: `"select * from app_users where id=? for update"`
  5. `AccountController.java:162`: `"select id from projects where id=? for update"`
  6. `AccountController.java:177`: `"select id from projects where id=? for update"`
- `INTERVAL` 算子：**0 处**。会话过期计算在 Java 层（`now + 8 * 3600000L`）。
- `::` 类型强转：**0 处**。SQL 中无任何 PostgreSQL 样式强转。
- `ILIKE`：**0 处**。无不区分大小写模糊匹配。
- 批量更新 (`batchUpdate`)：**0 处**。全部为单条精细事务。

### 2. 二进制数据类型映射 (`byte[]`)
- **文件与行号**：`platform-service/src/main/java/org/gmssl/gui/platform/CredentialService.java:89`
- **代码实现**：`byte[] encrypted = (byte[]) rows.getFirst().get("encrypted_passphrase");`
- **DM8 适配点分析**：
  - 若在数据库中使用 `VARBINARY(4096)`，达梦 JDBC (`DmJdbcDriver18`) 在理论上 `ResultSet.getObject()` 返回 `byte[]`，但**必须待实库核验**。
  - 若使用 `BLOB`，达梦 JDBC 返回 `dm.jdbc.driver.DmdbBlob`，直接 `(byte[])` 强制类型转换会抛出 `ClassCastException`。因此建议定义为 `VARBINARY`，并在实库中验证返回对象的实际类型。

### 3. 列名别名与大小写敏感度陷阱 (Case Sensitivity)
- **文件与行号**：
  - `AccountController.java:144`: `select m.user_id as "userId",u.username,m.role from memberships m ...`
  - `AccountController.java:205-207`: `select id,actor,action,resource_type as "resourceType",resource_id as "resourceId",outcome,created_at as "createdAt" ...`
- **DM8 行为分析（待实库核验）**：
  - 双引号内的别名（`"userId"`, `"resourceType"` 等）在 DM8 中严格保持大小写。
  - 未使用双引号的列（如 `id`, `username`, `role`），在 DM8 默认转换为大写（`ID`, `USERNAME`, `ROLE`）。
  - Spring JDBC 的 `ColumnMapRowMapper` 内部采用 `LinkedCaseInsensitiveMap`，因此 Java 代码中通过 `m.get("id")` 可以不区分大小写读取。
  - **接口 JSON 暴露风险**：部分接口直接返回 `s.rows(...)` 时，Jackson 会将 Map 的 Key 直接序列化为 JSON 字段。若数据库返回大写，可能导致前端接收到的属性名发生变更，需在实库中进行全链路验证。

---

## 四、Spring 配置、H2 兼容模式与驱动依赖盘点

### 1. Spring Datasource 配置
- **文件路径**：`platform-service/src/main/resources/application.yml`
- **当前行号 (8-10)**：
  ```yaml
  spring:
    datasource:
      url: ${SPRING_DATASOURCE_URL:jdbc:h2:file:./data/platform;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE}
      username: ${SPRING_DATASOURCE_USERNAME:sa}
      password: ${SPRING_DATASOURCE_PASSWORD:}
  ```
- **达梦连接串格式**：
  `jdbc:dm://<host>:<port>?schema=<SCHEMA>&caseSensitive=true`
  - 驱动类名：`dm.jdbc.driver.DmDriver`

### 2. Maven 依赖与驱动获取事实 (`platform-service/pom.xml`)
- **当前依赖 (行 7-10)**：
  ```xml
  <dependency><groupId>org.flywaydb</groupId><artifactId>flyway-core</artifactId></dependency>
  <dependency><groupId>org.flywaydb</groupId><artifactId>flyway-database-postgresql</artifactId></dependency>
  <dependency><groupId>org.postgresql</groupId><artifactId>postgresql</artifactId><scope>runtime</scope></dependency>
  <dependency><groupId>com.h2database</groupId><artifactId>h2</artifactId><scope>runtime</scope></dependency>
  ```
- **达梦官方 JDBC 驱动事实**：
  - 驱动坐标：`com.dameng:DmJdbcDriver18` (版本 `8.1.3.140`) 已存在于 Maven 中央仓库。
  - 支持 Java 8 / 11 / 17 / 21。
  - 也可作为本地离线 jar 放入项目 `lib/`。

---

## 五、自动化测试现状与实库验证边界

在 `platform-service/src/test/` 共有 3 个集成测试类：
1. `PlatformIntegrationTest.java:137`
2. `CertificateWorkflowTest.java:278`
3. `KeyGenerationIntegrationTest.java:193`
- **当前测试运行事实**：
  现有测试全部使用 H2 内存库（`jdbc:h2:mem:...;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE`）。
- **严格边界界定**：
  - H2 的测试通过**绝不能被视作达梦实库兼容的证据**。
  - 在没有真实外部 DM8 数据库实例连通凭据前，达梦实库兼容性测试处于 **Pending（待定）** 状态。
  - 必须保留本地 H2 测试用于日常开发与 CI 回归，对达梦实库的验证必须使用独立空 schema 进行专项测试。

---

## 六、部署编排、运维脚本与文档中的 PostgreSQL 依赖

| 文件路径 | 行号范围 | PostgreSQL 依赖内容 | 达梦改造方案 |
| :--- | :--- | :--- | :--- |
| `compose.yaml` | 3-14, 63, 68, 103 | `postgres:17-alpine` 容器、健康检查 `pg_isready`、数据卷 `postgres-data` | 按需求“连接外部现有达梦实例，不内置 PG 容器”：可提供外部 DM 连接配置 profile，平台直连外部 DM8。 |
| `deploy/gmssl-gui-linux-amd64/compose.yaml` | 4-16, 67, 72, 109 | 同上（预编译独立包编排） | 移除 `postgres` 容器，配置外部达梦连接变量。 |
| `deploy/gmssl-gui-linux-amd64/README.md` | 18, 88, 123, 142, 147-149 | `postgres` 容器介绍、`postgres-data` 数据卷说明、`pg_dump` 在线导出命令 | 替换为达梦数据库连接说明，删除 `pg_dump`，增补达梦自带 `dexp / dimp` 逻辑导出工具或企业备份说明。 |
| `deploy/gmssl-gui-linux-amd64/scripts/stop.sh` | 12 | 打印信息中的 `volumes postgres-data and vault-data` | 提示信息中移除 `postgres-data`。 |
| `scripts/package-linux-amd64.sh` | 198 | `manifest.json` 中基础镜像声明 `"postgres": "postgres:17-alpine"` | 移除 postgres 基础镜像声明，减小无用拉取期望。 |

---

## 七、实库验证清单（Schema 现场核验项）

在获取到真实达梦测试 schema 凭据后，必须严格执行以下实库核验，而非凭空断言：
1. **实库详细版本与模式**：确认 DM8 准确构建版本（如 8.1.3.x），确认当前实例的 `COMPATIBLE_MODE`（0=默认, 1=SQL92, 2=Oracle, 3=MS SQL Server, 4=MySQL）及 `CASE_SENSITIVE` 大小写敏感设置。
2. **Flyway 原生迁移兼容**：验证 Flyway 在该 DM8 版本下创建 `flyway_schema_history` 元数据表与执行 DDL 迁移的能力。
3. **VARBINARY 与 LOB 行为**：核实插入与读取 `encrypted_passphrase` 时 JDBC 返回的对象是否为 `byte[]`，以及最大容量与内存消耗。
4. **时间戳精度与格式**：确认 `VARCHAR(40)` 字符串保存 ISO-8601 是否产生任何截断或字符集编码异常。
5. **FOR UPDATE 并发加锁行为**：在多事务连接下验证 `select ... for update` 是否正确持有排他行锁、并在事务提交/回滚后释放，确认无锁超时或死锁异常。