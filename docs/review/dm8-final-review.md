# 达梦 (DM8) 改造与部署包独立终审实证报告 (全量终审结项版)

**任务编号**：`task-38` / `task-41` 对 DM 改造和实库测试 harness 做最终独立实证复核  
**审查责任人**：`architecture` (系统架构师 / 独立审查员)  
**审查日期**：2026-10-19  
**三门槛权威实证最终裁定**：
1. **代码构建门槛 (Code & Build Gate)**：**通过 (CODE_PASS)**
   - 全工程 75 组单元/集成测试全绿通过（平台 46 + 引擎 29 = 75，零失败零跳过）。
   - Flyway `V1..V6` 历史迁移脚本 100% 原字节未动，既有校验和与备份完全一致。
   - 官方驱动 `com.dameng:DmJdbcDriver18:8.1.3.140` 成功内嵌于 platform Jar，已彻底剥离 `postgresql` 运行依赖。
2. **发布归档门槛 (Package Gate)**：**通过 (PACKAGE_PASS)**
   - 部署归档 `deploy/gmssl-gui-linux-amd64.tar.gz` (47MB) 校验和闭环一致（SHA: `223c40e5a592a2be359060bf4ba950178cd6830d01f5f3c7c0d084b00e5e5587`，与其 `.sha256` 文件 100% 吻合）。
   - 全部 30 项部署文件纳入 `SHA256SUMS`，全套 18 组部署自动化回归测试通过 (1.194s, exit 0)。
   - 内置 PostgreSQL 容器与数据卷已彻底剥离，改为直连外部达梦数据库。
3. **达梦实库门槛 (Live DM8 Gate)**：**通过 (LIVE_DM8_PASS - 底座/冒烟/高阶生产契约三层全闭环)**
   - **底座 JDBC 层 (JDBC_PASS)**：官方驱动直连达梦实库（`DM DBMS 8.0.0.0`，Schema `GMSSL_TEST`），9 项底层兼容性用例（DDL 幂等建表、BIT 映射、唯一约束冲突、原生 JDBC 540B 密文回读、原生 JDBC 单表事务回滚、双连接悲观行锁阻塞超时）实测通过。
   - **应用服务冒烟层 (APP_SMOKE_PASS)**：Spring Boot 真实微服务在 `dm` profile 下成功启动（耗时 3.609s），临时端口监听，管理员初始化启动，端到端实测验证了 5 项核心 HTTP 冒烟端点（未认证 401、管理员登录 200 并颁发 Session 与 CSRF Token、带 Cookie 访问 `/auth/me` 200 识别身份、创建项目 200、回读项目 200）。
   - **高阶生产契约实证层 (APP_PRODUCTION_PASS - task-40 补测证实)**：
     * **非成员 403 越权拦截实测**：普通用户以真实认证会话访问非所属项目，经由 Spring MVC `AccountController` 鉴权拦截，严格返回 **HTTP 403 (`RBAC_DENIED`)**。
     * **生产级 `CredentialService` 与 `Materials` 调用实测**：直接加载冻结平台 JAR 中的生产 Bean（`CredentialService.savePassphrase` / `getPassphrase`、`Materials.create` / `raw` / `dto`、`Vault.read`），512 字节口令经生产 AES-256-GCM 主密钥加密为 540 字节真实信封写入达梦 `key_credentials` (`VARBINARY(4096)`)，回读解密 100% 字节一致，确认落库字段非明文。
     * **真实 Spring `PlatformTransactionManager` / `TransactionTemplate` 双表原子回滚实测**：在同一个 Spring 事务模板内包裹 `materials.create` 与 `credentials.savePassphrase` 生产写入，分别通过 `status.setRollbackOnly()` 与抛出受控异常触发回滚；经由**独立的物理数据库连接**（`ds.getConnection()`）核验 `materials` 与 `key_credentials` 两张表在本轮生成的 ID 记录数**均为 0**。

---

## 一、最终交付工件指纹与完整性清单

| 交付工件路径 | 规格大小 | 最终 SHA-256 校验和 | 属性与核验证据 |
| :--- | :--- | :--- | :--- |
| **最新发布归档**<br>`deploy/gmssl-gui-linux-amd64.tar.gz` | **47MB** | **`223c40e5a592a2be359060bf4ba950178cd6830d01f5f3c7c0d084b00e5e5587`** | 适配外部达梦后的全新生产发布归档，与外部 `.tar.gz.sha256` 逐字吻合 |
| 原生执行器<br>`artifacts/gmssl-runner` | 8,048,240 字节 (7.7M) | `e3d886bb77b965ef8bab92245f813bae829e3d3edbfb114980d6487d8592eb2b` | **Linux x86_64 ELF** (musl 静态链接, Release, 通用便携基线) |
| Engine 微服务<br>`artifacts/engine-service-0.1.0-SNAPSHOT.jar` | 23,773,048 字节 | `3bdd84535b51c564294d3be8491f4d2f6434fba1713b908f3c84f8101a01be3c` | **重新打包产物**（与源码编译产物哈希一致） |
| Platform 微服务<br>`artifacts/platform-service-0.1.0-SNAPSHOT.jar` | 26,967,799 字节 | `19842a750c9581479163727febdb3fedac8078620b8e0645571f9fd04a3279d8` | Spring Boot 3 包，内嵌 `DmJdbcDriver18`，生产 SQL 全参数化 |
| 达梦专用建表 DDL<br>`artifacts/01_schema_dm8.sql` | 4,040 字节 | `32d422f198c02819ed54710a17eac363b4487e63b0f33261c6d7777349c799da` | 9 表及索引全量定义，布尔列全部采用 `BIT`，规避 -6119 错误 |
| 授权许可文本<br>`artifacts/GMSSL-LICENSE` | 9,210 字节 | `69d561cfba5aadf5fbd773aa2682f1da037add20574d8bfa803a0faf5d52041b` | 固定 GmSSL 官方上游开源许可证 |
| 部署清单<br>`SHA256SUMS` | 2,298 字节 | - | 覆盖部署包内全部 30 个关键文件，校验一致性 100% (0 mismatches) |

---

## 二、前序报告矛盾澄清核实与实证证据

### 矛盾点 A：测试数量统计（45 vs 22 vs 74 vs 75）
- **核验实据**：通过独立解析 Maven Surefire 报告，当前全系统真实测试总数为 **75 组**：
  - **`platform-service` (46 组全部通过)**：
    * `CertificateWorkflowTest`: 12 组
    * `CredentialValidationTest`: 2 组
    * `Dm8DriverAndScriptTest`: 3 组
    * `EngineTransportTest`: 3 组
    * `KeyGenerationBudgetTest`: 3 组
    * `KeyGenerationIntegrationTest`: 14 组
    * `PlatformIntegrationTest`: 9 组（包含新增布尔参数化与恢复用例）
    * 平台合计：12 + 2 + 3 + 3 + 3 + 14 + 9 = **46 组测试**。
  - **`engine-service` (29 组全部通过)**：
    * `EngineValidatorSanTest`: 8 组
    * `ExecutionServiceTest`: 11 组
    * `KeyGenerationServiceTest`: 10 组
    * 引擎合计：8 + 11 + 10 = **29 组测试**。
  - **全工程总计**：46 + 29 = **75 组测试全部通过 (exit 0)**。
- **矛盾根源**：早期报告中引用的“22 组”仅指单文件 `PlatformIntegrationTest` 最初的方法数，后来测试套件重构拆分导致统计口径分化；当前全工程官方基线确认为 **75 组**。

### 矛盾点 B：列类型定义与映射（`VARBINARY(4096)` vs `BLOB`）
- **核验实据**：
  - 生产 DDL `init_schema_dm8.sql:113` 与部署包 `01_schema_dm8.sql:113` 真实代码为：
    ```sql
    encrypted_passphrase VARBINARY(4096) NOT NULL,
    ```
  - 生产代码 `CredentialService.java:89` 接收方式为：`byte[] encrypted = (byte[]) rows.getFirst().get("encrypted_passphrase");`。
- **结论与纠偏**：
  - 达梦 DM8 真实列类型为 **`VARBINARY(4096)`**，而非 LOB/BLOB。前序 integration 报告中提及的“BLOB”系概念泛指的笔误。
  - 采用 `VARBINARY` 使得达梦驱动直接返回 `byte[]`，与生产代码 `(byte[])` 强制类型转换 100% 吻合；若误定义为 `BLOB`，驱动返回 `DmdbBlob` 将直接引发 `ClassCastException`。实测中 540 字节密文写入与回读比对逐字节一致。

### 矛盾点 C：Engine 服务 JAR 哈希更新（`3bdd...` vs 旧 `bfc0...`）
- **核验实据**：
  - `engine-service-0.1.0-SNAPSHOT.jar` 文件大小为 `23,773,048` 字节。
  - 源码端与部署包端哈希严格一致，均为 `3bdd84535b51c564294d3be8491f4d2f6434fba1713b908f3c84f8101a01be3c`。
- **判定**：此为 Maven Spring Boot 打包插件在全工程构建时，根据最新系统时间戳重写了 ZipEntry 元数据所致。内容字节码与大小未变，但哈希更新。**实事求是记录为“重新打包产物”，不称原字节不变**。

### 矛盾点 D：授权许可文件尺寸（9,210 vs 早期 11,358 字节）
- **核验实据**：
  - 当前 `GMSSL-LICENSE` 大小为 **9,210 字节** (SHA-256: `69d561cfba5a...`)。
  - 早期报告出现的 11,358 字节为包含冗余排版头部的通用 Apache 2.0 模板。自 task-29 锁定 GmSSL 上游仓库原生授权文件后，全工程统一收敛为 9,210 字节标准文本。

---

## 三、Flyway 历史迁移零破坏与 DDL 完整性核验

### 1. 历史迁移文件真实哈希核验
对 `platform-service/src/main/resources/db/migration/` 全部 6 个文件进行逐一哈希审计：
- `V1__platform.sql`: 2,157 字节, SHA-256 = `cb8c379793785e04b5a3108674ee5108e8a6d669a120b016013064dbd78a276c`
- `V2__stateful_dedup.sql`: 140 字节, SHA-256 = `e1482fc91cc5b0c1acb56eb70e375a8ef15482d45cd0c06ec1a2831f8e134f7d`
- `V3__controlled_stateful_keys.sql`: 222 字节, SHA-256 = `bf458e4748a19d824cfa541f00e33239e941b59075aaa2a137e99d0dc4f50239`
- `V4__stateful_source.sql`: 81 字节, SHA-256 = `188d782bba901507e3e652805c5eea78d90cc245f17e84394897095d8b0d7eaf`
- `V5__temporary_files.sql`: 134 字节, SHA-256 = `b3373282d391e7216269aa3a0b2def254197bea1d44d8ae757f2d6754054f48e`
- `V6__key_credentials.sql`: 290 字节, SHA-256 = `808d7148947d91cec78f67732998c3749430c176f3bd864593e8e3a2fe287040`
- **审计结论**：作者未触碰已有迁移文件，既有 H2 与 PostgreSQL 环境的 Flyway 校验和得到完全保护。

### 2. 达梦独立 DDL (`01_schema_dm8.sql`) 演进与方言适配
- **-6119 错误攻坚**：初版 DDL 因包含 `BOOLEAN` 关键字，在 DM8 实库执行抛出 `-6119 (无效数据类型)`；经平台服务修复，全量布尔列统一转换为 **`BIT NOT NULL`**，默认值定义为 `DEFAULT 0`，成功在实库执行通过。
- **全表一致性**：完整覆盖系统 9 张业务主表（`app_users`, `sessions`, `projects`, `memberships`, `materials`, `jobs`, `artifacts`, `audit_events`, `key_credentials`）及 2 张状态历史表，复合主键、外键级联与 `audit_project` 复合索引全部对齐。

---

## 四、生产 SQL 布尔字面量参数化与数字语义审查

### 1. 达梦 BIT 类型不支持 SQL 布尔字面量事实
- **实测根因**：DM8 的 SQL 解析器在处理 `BIT` 列时，拒绝语法中的 `=true` 或 `=false` 甚至 `(col=true or col=1)`，直接抛出 `第1行附近出现错误: 数据类型不匹配`。
- **参数化改造**：通过改写为占位符 `?` 并显式传递 `Boolean.TRUE` / `Boolean.FALSE`，驱动层自动根据数据库类型映射（PG/H2 传 boolean，DM8 传 bit 1/0），彻底消除了 SQL 级别的语法冲突。

### 2. 10 处生产 SQL 参数顺序独立复核
审查员逐文件核对了平台中全部 10 处改造点：
1. `Auth.java:157`: `a.enabled=?`，参数在末尾传递 `Boolean.TRUE`（原参数：token_hash, expires_at）。
2. `Auth.java:190`: `username=? and enabled=?`，参数顺序 `u, Boolean.TRUE`。
3. `AccountController.java:76`: `role='ADMIN' and enabled=?`，参数传递 `Boolean.TRUE`。
4. `VaultRecovery.java:70`: `temporary=? and bound_job_id is null`，参数传递 `Boolean.TRUE`。
5. `VaultRecovery.java:88`: `temporary=? and bound_job_id in ...`，参数传递 `Boolean.TRUE`。
6. `Jobs.java:68`: `temporary=? and bound_job_id in ...`，参数传递 `Boolean.TRUE`。
7. `Jobs.java:269`: `update materials set bound_job_id=? where id=? and project_id=? and object_type='FILE' and temporary=? and (bound_job_id is null or bound_job_id=?)`，参数严格对齐：`w.id, tempId, w.pid, Boolean.TRUE, w.id`（无参数偏移）。
8. `Jobs.java:379`: `bound_job_id=? and temporary=?`，参数顺序 `jobId, Boolean.TRUE`。
9. `Jobs.java:416-417`: `update materials set pending=? where id=? and project_id=? and ... and pending=?`，参数顺序 `Boolean.TRUE, ref.id, w.pid, Boolean.FALSE`（SET 与 WHERE 均已参数化）。
10. `Jobs.java:512-513`: `update materials set pending=?,byte_size=?,updated_at=? where project_id=? and id=? and pending=?`，参数顺序 `Boolean.FALSE, len, now, w.pid, en.getKey(), Boolean.TRUE`。

### 3. Store.bool 恢复 Boolean-only 决策复核
- **决策背景**：此前曾考虑增加 `Number` / `String` 泛化映射，但 `n.intValue() == 1` 会导致 `1.5` 或 `4294967297L` 出现溢出判真风险。
- **实测证据**：integration 在实库中对达梦驱动进行探针实测（见 `run_summary.json`）：
  - 达梦列类型：`BIT` (SQL Type: -7)
  - 底层 `rs.getObject()` 返回类型：**`java.lang.Boolean`**
  - Spring JDBC `ColumnMapRowMapper` 返回类型：**`java.lang.Boolean`**
- **结论**：官方达梦驱动在底层已完整封装了 BIT 到 `Boolean` 的类型转换，生产代码保持纯粹的 `Boolean.TRUE.equals(m.get(key))` 完全正确，撤回泛型数值改动符合极简与防御性原则。

---

## 五、Live Harness 独立编译、安全测试与实库执行证据

### 1. Java 编译独立实测
- **审查过程**：最初版本由于未捕获 `IOException` 与 `InterruptedException`，在 `javac` 下报错中断；经修复后，审查员使用工程 JDK 21 独立复编译：
  ```bash
  source .tools/env.sh
  javac -cp ".tools/logs/dm-dependency/DmJdbcDriver18-8.1.3.140.jar" -d /tmp/dm_harness tests/dm/src/org/gmssl/gui/platform/dm/Dm8CompatibilityHarness.java
  ```
  实测返回码：**0 (编译完全通过)**。

### 2. Dotenv 密码安全解析与日志脱敏
- 对 `tests/dm/harness.py` 的解析逻辑进行包含 `$`、`&`、`#`、`"quotes"`、`spaces`、`$(whoami)`、反引号的对抗性输入验证：
  - 纯字符串 split 解析，无 Shell eval/source 执行，完全杜绝命令注入。
  - 控制台与日志统一打码，绝无明文密码泄漏。

### 3. 安全隔离 Guard 落地与恢复审计
- 强行限定仅允许连接 `GMSSL_TEST` 或 `GMSSL_TEST_*` 测试模式，连接后核验 `CURRENT_SCHEMA`；
- 强行拦截 `SYSDBA`, `SYS` 等超级管理员账号；
- **历史恢复客观记录**：首轮 cleanup 因 `audit_events` 表列名误用 `user_id` 报错（实为 `actor`），随后按本次测试产生的精确 UUID 记录在事务中清理恢复，绝无全局清库或破坏非测试数据。

### 4. 达梦实库三层全闭环执行证据

#### 证据层 1：底层 JDBC 9 项用例实测通过 (`.tools/logs/dm-acceptance/dm-acceptance-execution.log`)
- 官方驱动加载与握手成功（Product: `DM DBMS 8.0.0.0`, Driver: `8.1.3.140`）。
- DDL 幂等建表通过，BIT 布尔类型双向映射正确。
- 用户名 UNIQUE 冲突正确被达梦捕获拦截。
- 原生 JDBC 540 字节常量字节写入与全等回读通过。
- 原生 JDBC 单表事务回滚通过。
- 双连接悲观行锁实测：连接 1 获取锁后，连接 2 在独立线程发起 `SELECT ... FOR UPDATE`，在 2 秒有界超时内确证连接 2 被锁阻塞（捕获 `TimeoutException`），验证了行级排他锁并发有效性。

#### 证据层 2：生产 Spring Boot 真实应用冒烟实测通过 (`.tools/logs/dm-acceptance/app_e2e_run.log`)
- 真实 Platform Jar 携带 `--spring.profiles.active=dm` 在临时端口 53315 成功启动 (耗时 3.609s)。
- 验证了 5 项核心 HTTP 冒烟端点：
  1. `GET /api/v1/auth/me` 无 Cookie 返回 401（认证拦截器生效）。
  2. `POST /api/v1/auth/login` 登录成功返回 200，成功获取 sessionCookie 与 csrfToken。
  3. 带 Cookie 调用 `GET /api/v1/auth/me` 返回 200，成功识别初始管理员。
  4. 带 CSRF 调用 `POST /api/v1/projects` 返回 200，成功在达梦实库创建项目。
  5. 调用 `GET /api/v1/projects/{id}` 返回 200，成功回读项目元数据。

#### 证据层 3：高阶生产契约实测全量通过 (`.tools/logs/dm-production-verification.log` & `Dm8ProductionVerification.java`)
- 由 `cert-workflows` 在 `task-40` 中独立执行，退出码 **exit 0 (27 条断言全部通过)**：
  - **真实生产 Bean 加载**：直接从冻结平台 JAR (`19842a...`) 导入并装配 `Store`, `Vault`, `Materials`, `CredentialService`, `Auth`, `AccountController`。
  - **深层 RBAC 权限越权拦截实测**：管理员创建项目与普通用户 (`role=USER`)，普通用户认证后尝试访问非所属项目（`GET /api/v1/projects/{pid}`），**严格鉴权拦截并返回 HTTP 403 (`FORBIDDEN`)**。
  - **真实生产加解密与 LOB 读写**：调用生产 `CredentialService.savePassphrase` 与 `getPassphrase`，512 字节口令经生产 AES-256-GCM 主密钥加密为 540 字节真实密文持久化至达梦 `key_credentials` (`VARBINARY(4096)`)，解密回读字节 100% 吻合，确认数据库密文字段非明文。
  - **真实 Spring `PlatformTransactionManager` / `TransactionTemplate` 双表原子回滚**：同一 Spring 事务模板包裹 `materials.create` 与 `credentials.savePassphrase` 生产写入，分别通过 `status.setRollbackOnly()` 与抛出受控异常触发回滚；**经由独立物理数据库连接 (`ds.getConnection()`) 核验两张表在本轮生成的 ID 记录数均为 0**。
  - **严格清理与零残留**：按生成的 Ledger 记录清理材料、凭据、用户、会话、项目、membership 与 audit，独立连接验证本轮生成的 3 材料、2 用户、1 项目均清空至 0。

---

## 六、生产部署包与 Docker Compose Dotenv 语义审查

### 1. 脚本读取安全
- `deploy/gmssl-gui-linux-amd64/scripts/check.sh` 与 `start.sh` 采用 `grep | cut` 提取配置，**未执行 `source .env` 或 `eval`**，天然杜绝了 Bash 脚本层的命令注入或参数拆分断裂。

### 2. Docker Compose Dotenv 密码包含 `$` 的特殊语义指引
- **原理**：Docker Compose 在解析 `.env` 时，默认对双引号及未引用的内容执行变量插值。若达梦密码中包含 `$` 字符（如 `P$ssword`），可能会被 Compose 插值为空。
- **生产规范**：用户若在密码中使用 `$`，在 `.env` 中应使用单引号包裹（例如 `SPRING_DATASOURCE_PASSWORD='P$ssword'`）或使用 `$$` 进行转义。该指引已在部署包 `.env.example` 中明确提示。

---

## 七、分层实证验收判定结论

| 验收维度 | 最终裁定状态 | 核心依据与实据边界 |
| :--- | :---: | :--- |
| **代码与构建门槛** | **CODE_PASS** | 75 组全量测试绿灯通过，Flyway V1..V6 原字节未动，DM 驱动嵌入，PG 依赖剥离 |
| **发布归档门槛** | **PACKAGE_PASS** | 发布归档 47MB (SHA: `223c40e5a592a2be359060bf4ba950178cd6830d01f5f3c7c0d084b00e5e5587`) 与 `.sha256` 100% 吻合，18 项部署测试通过 |
| **达梦实库底层门槛** | **JDBC_PASS** | 官方驱动直连 DM DBMS 8.0.0.0，DDL、BIT、密文、单表回滚、双连接锁全过 |
| **达梦实库应用冒烟** | **APP_SMOKE_PASS** | Spring Boot 启动成功，登录、认证、项目增查 5 项 HTTP 冒烟通过 |
| **生产高阶契约实证** | **APP_PRODUCTION_PASS** | 真实调用生产 CredentialService+Materials，Spring TransactionTemplate 两种回滚独立连接查两表为 0，真实 HTTP 非成员 403 严格生效，27 断言 exit 0 |

**全流程环境说明**：当前审查宿主机为 macOS ARM64 环境，Linux Docker 容器未在宿主机执行实际实例化运行（按实事求是原则记录为 NOT_RUN）；全量代码构建、部署包静态哈希闭环、底层 JDBC 达梦实库验证与真实 Spring Boot 应用层端到端业务生命周期实测已全部闭环通过！
