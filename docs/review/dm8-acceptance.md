# 达梦 DM8 数据库适配与 Linux 独立部署包验收审查报告 (事实校准版)

**审查状态**：部分就绪（代码与部署包已验证；达梦实库完成基础 JDBC 9 项与真实应用登录/项目 RBAC 403；生产级 CredentialService 与 Spring 事务回滚待 task-40 补齐）  
**审查日期**：2026-10-19  
**审查智能体**：Integration (独立验证与集成质量)  
**审查范围**：
1. 达梦 DM8 官方驱动真实性与供应链解析
2. 真实 DM8 实例（DM DBMS 8.0.0.0）有界只读元数据与独立 JDBC 9 项兼容性实测
3. 真实 DM8 实例下 Spring Boot 独立临时实例端到端登录、会话与项目 RBAC 403 权限隔离实测
4. Linux amd64 预编译独立部署包最终归档、全量 SHA256SUMS 与自动化回归核验

---

## 一、真实 DM8 实例实测执行结果与关键指标

连接用户唯一指定的私有实库环境（目标模式：`GMSSL_TEST`，严格遵循超级用户与非测试 Schema 拦截红线）：

### 1. 达梦实库产品元数据
- **Product Name**: `DM DBMS`
- **Product Version**: `8.0.0.0` (Database Major.Minor: `8.0`)
- **Driver Name**: `dm.jdbc.driver.DmDriver`
- **Driver Version**: `8.1.3.140` (Maven Central 官方坐标 `com.dameng:DmJdbcDriver18:8.1.3.140`)
- **JDBC Version**: `4.0`
- **Current Schema**: `GMSSL_TEST` (受控隔离测试模式)

### 2. 字段方言实测证据与类型映射探针
- **-6119 错误闭环验证**：
  原 DDL 中使用 `BOOLEAN` 关键字时，达梦实库报错 `-6119 (无效的数据类型)`。经将布尔列全量定义为 `BIT`（`DEFAULT 0` / `DEFAULT 1`）后，建表 DDL 全量成功执行。
- **值对象类型实测探针（原始输出证据）**：
  在 `app_users` 表对 `enabled BIT` 列进行真实写入（`true/1` 与 `false/0`）后查询验证：
  - `raw rs.getObject("enabled")` -> `true` (`java.lang.Boolean`) / `false` (`java.lang.Boolean`)
  - Spring `ColumnMapRowMapper.mapRow` -> `value=true` (`java.lang.Boolean`) / `value=false` (`java.lang.Boolean`)
  **结论**：官方达梦 JDBC 驱动在获取 BIT 列对象时直接返回标准的 `java.lang.Boolean`。平台端在 `Store.bool` 保持了严格的 Boolean-only 语义判定，完全避免了类型混淆与权限溢出风险。

### 3. 独立 JDBC 兼容性 Harness 9 项实测全量 PASS
运行 `./scripts/test-dm.sh`，全部 9 项底层驱动与方言测试通过：
1. **[PASS] 1. dm.jdbc.driver.DmDriver SPI 动态加载**
2. **[PASS] 2. 真实 JDBC Connection 握手与 Product Name/Version 读取**
3. **[PASS] 3. 01_schema_dm8.sql 离线 DDL 执行与幂等性保障**
4. **[PASS] 4. app_users CRUD 与 BIT -> Boolean 双向真实映射**
5. **[PASS] 5. UNIQUE 唯一索引冲突拦截强制生效（捕获达梦唯一键违规异常）**
6. **[PASS] 6. VARBINARY(4096) 540 字节 mock 口令密文（固定模式字节写入）与逐字节全等回读**
7. **[PASS] 7. 单连接 JDBC 事务原子性与回滚（Materials 单表回滚不残留）**
8. **[PASS] 8. 悲观并发锁两独立 Connection 实测（连接 1 持有 SELECT ... FOR UPDATE，连接 2 尝试获取时被达梦内核真实阻塞超时，连接 1 commit 后释放）**
9. **[PASS] 9. 测试模式内临时数据安全清理**

---

## 二、真实 Spring Boot 应用端到端业务生命周期实测（已测范围与未覆盖边界）

使用 platform 最终交付的 `platform-service-0.1.0-SNAPSHOT.jar`（SHA: `19842a...`，修复了 10 处 SQL 布尔字面量参数化），在随机分配的本地未占用端口（PID: `29098`，Port: `54209`）与独立临时 Vault 目录下独立启动 Spring Boot 实例进行真实 HTTP 业务链路验证：
- **启动参数安全隔离**：所有数据库密码、Master Key、Engine Token 均纯通过环境变量注入，**严禁传入进程 argv**，控制台不输出包含密码的明文信息。

### 1. 真实已测通过的业务 API 范围
1. **[PASS] 1. Spring Boot 正常启动并在达梦实库上完成数据源装配**：HikariCP 成功加载并维持达梦连接（`Started PlatformApplication in 2.731 seconds`）。
2. **[PASS] 2. 未认证端点拦截**：访问 `GET /api/v1/auth/me` 正确返回 HTTP 401 `UNAUTHENTICATED`。
3. **[PASS] 3. 初始管理员认证**：调用 `POST /api/v1/auth/login`，认证成功返回 HTTP 200，并颁发有效会话 Cookie（`GMSSL_SESSION`）与 `csrfToken`。
4. **[PASS] 4. 会话鉴权回查**：携带 Cookie 请求 `GET /api/v1/auth/me`，成功执行参数化 SQL 并返回 HTTP 200 及管理员身份（`role=ADMIN`）。
5. **[PASS] 5. 项目创建与持久化**：携带管理员 Cookie 与 CSRF Token 调用 `POST /api/v1/projects`，成功在达梦 `projects` 与 `memberships` 表中插入项目记录，返回 HTTP 200 并获取项目 ID。
6. **[PASS] 6. 管理员创建普通用户**：调用 `POST /api/v1/users` 创建 `role=USER` 的普通账号，返回 HTTP 200。
7. **[PASS] 7. 普通用户登录**：普通用户调用 `POST /api/v1/auth/login` 登录成功，获取其专属会话。
8. **[PASS] 8. RBAC 403 严格隔离实测**：普通用户尝试访问非成员的管理员项目（`GET /api/v1/projects/{pid}`），系统严格鉴权并返回 **HTTP 403 FORBIDDEN**。

### 2. 诚实更正：未在生产 Bean/服务层覆盖的边界（标注为 NOT_RUN）
- **[NOT_RUN] 生产级 CredentialService 与 Vault 真实加解密**：
  此前测试仅验证了向 `key_credentials` 表的 `VARBINARY(4096)` 列进行直接 JDBC mock 字节读写，**未实际通过 Spring 容器调用生产 `CredentialService.savePassphrase` 与 `getPassphrase`**，未执行由真实 Vault 驱动的 AES-256-GCM 口令加解密链路。
- **[NOT_RUN] 跨 Materials 与 key_credentials 的 Spring 声明式事务回滚**：
  此前测试仅通过底层 JDBC 单连接进行了 SQL 级别的 `conn.rollback()` 验证，**未通过 Spring `@Transactional` 或 `TransactionTemplate` 在发生异常时触发跨表原子回滚**。
- **后续承接**：以上两项未覆盖的生产服务层测试已交由 `cert-workflows` 队友在 `task-40` 中作为唯一执行 owner 进行补齐与实测，本智能体不夸大测试范围。

---

## 三、最终 Linux amd64 预编译发布包核验（与 build-quality 对齐）

对 build-quality 最终打出的发布包及交付目录进行全量闭环审计：
1. **最终工件指纹对齐**：
   - **platform-service JAR**:
     - 路径: `deploy/gmssl-gui-linux-amd64/artifacts/platform-service-0.1.0-SNAPSHOT.jar`
     - SHA-256: `19842a750c9581479163727febdb3fedac8078620b8e0645571f9fd04a3279d8`
     - 内嵌官方达梦驱动，生产 SQL 全量参数化，彻底消除布尔类型不匹配。
   - **达梦专用建表 DDL**:
     - 路径: `deploy/gmssl-gui-linux-amd64/artifacts/01_schema_dm8.sql`
     - SHA-256: `32d422f198c02819ed54710a17eac363b4487e63b0f33261c6d7777349c799da`
     - 全量使用 `BIT` 列，无 `BOOLEAN` 关键字，随附完整 10 张表与索引定义。
   - **Linux 原生执行器**:
     - 路径: `deploy/gmssl-gui-linux-amd64/artifacts/gmssl-runner`
     - SHA-256: `e3d886bb77b965ef8bab92245f813bae829e3d3edbfb114980d6487d8592eb2b`
     - Linux x86_64 ELF 纯静态 musl 便携基线，零宿主库依赖。
   - **计算引擎 JAR**:
     - 路径: `deploy/gmssl-gui-linux-amd64/artifacts/engine-service-0.1.0-SNAPSHOT.jar`
     - SHA-256: `3bdd84535b51c564294d3be8491f4d2f6434fba1713b908f3c84f8101a01be3c`
2. **发布归档一致性**：
   - 归档文件: `deploy/gmssl-gui-linux-amd64.tar.gz` (47MB)
   - 外部校验和: `deploy/gmssl-gui-linux-amd64.tar.gz.sha256`
     - **SHA-256: `223c40e5a592a2be359060bf4ba950178cd6830d01f5f3c7c0d084b00e5e5587`**（与实际压缩包及 `.sha256` 校验文件 100% 完全吻合）
   - 目录清单: `deploy/gmssl-gui-linux-amd64/SHA256SUMS` 覆盖全部 30 个文件，`sha256sum -c` 100% OK。
3. **编排与脚本安全**：
   - `compose.yaml` 完全剥离 PostgreSQL 容器与数据卷声明，显式配置 `SPRING_PROFILES_ACTIVE=dm`。
   - `check.sh` 校验达梦连接串必须符合 `jdbc:dm://`，严禁静默回退 H2。
   - `stop.sh` 仅执行 `docker compose stop`，严禁使用 `down -v`，确保用户私钥卷绝对安全。
4. **自动化部署回归套件**：
   - 运行 `python3 -m unittest discover -s tests/deployment -p 'test_*.py' -v`：**18/18 PASS (0.828s)**。

---

## 四、分层验收最终结论汇总表

| 验收层级 | 验收项 | 判定结果 | 关键证据与指标 |
| :--- | :--- | :--- | :--- |
| **代码与构建层** | 平台 46 项单测 | **PASSED** | `mvn test -pl platform-service` 46 项全部通过 |
| **代码与构建层** | 离线 Harness 单元测试 | **PASSED** | `tests/dm/test_harness_unit.py` 6/6 PASS（Dotenv 解析、密码特殊字符、安全规则、离线编译） |
| **部署交付层** | 独立部署包与 Compose | **PASSED** | 18 项部署测试全绿，零 PG 依赖，SHA256SUMS 100% 闭环，归档 SHA `223c40e5...` |
| **达梦实库层** | JDBC 核心 9 项用例 | **PASSED** | 官方驱动、BIT 映射、VARBINARY(4096)、原子回滚、双连接锁通过 |
| **达梦实库层** | 应用登录与项目 RBAC | **PASSED** | 独立 Spring Boot 启动成功 (2.731s)，Bootstrap、Login、Session、RBAC 403 严格隔离、Project 增查通过 |
| **达梦实库层** | 生产 CredentialService 真实调用与 Spring 事务回滚 | **NOT_RUN** | 未在生产容器/Bean 级别执行，转交 task-40 (cert-workflows) 补齐实测证据 |
