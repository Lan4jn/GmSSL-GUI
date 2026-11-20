# 达梦数据库 (DM8) 适配与 Linux 独立部署包终审报告

**审查责任人**：`architecture` (系统架构师 / 独立审查员)  
**审查日期**：2026-10-19  
**终审结论**：**通过 (PASS) - 具备正式发布与现场验证就绪条件**  
**审查对象**：
1. 平台服务达梦适配与历史兼容性保护（`platform-service`、`pom.xml`、`application-dm.yml`、`db/dm/init_schema_dm8.sql`）
2. 现有 H2/Flyway 历史迁移零破坏核验（`db/migration/V1..V6` 校验和保护）
3. Linux amd64 预编译发布包（`deploy/gmssl-gui-linux-amd64/`、归档 `deploy/gmssl-gui-linux-amd64.tar.gz`）
4. 达梦实库独立验证 Harness 与安全隔离约束（`tests/dm/`、`scripts/test-dm.sh`、`.env.dm-test.example`）

---

## 一、最终交付工件指纹与完整性清单

| 交付工件路径 | 规格大小 | 最终 SHA-256 校验和 | 属性与核验证据 |
| :--- | :--- | :--- | :--- |
| **最新发布归档**<br>`deploy/gmssl-gui-linux-amd64.tar.gz` | **46MB** | **`7f06af9e898d7572f30f39b57ffcea031c60ea66d3bd2dce099ef72cc832209c`** | 适配外部达梦后的全新生产发布归档，与外部 `.tar.gz.sha256` 逐字吻合 |
| 原生执行器<br>`artifacts/gmssl-runner` | 8,048,240 字节 (7.7M) | `e3d886bb77b965ef8bab92245f813bae829e3d3edbfb114980d6487d8592eb2b` | **Linux x86_64 ELF** (musl 静态链接, Release, 通用便携基线) |
| Engine 微服务<br>`artifacts/engine-service-0.1.0-SNAPSHOT.jar` | 23,773,048 字节 | `bfc0809ae5af88541a6ffc9ee07c0e14d4e52bdde27c36e1d1046dde05be3950` | 纯计算引擎，无数据库依赖 |
| Platform 微服务<br>`artifacts/platform-service-0.1.0-SNAPSHOT.jar` | 28,155,932 字节 | `8cf4a0b2aa94060b9ea0415a2eb2fa955f10b7f83ad7ef2294da1bc370ce1804` | Spring Boot 3 包，已内嵌官方 `DmJdbcDriver18:8.1.3.140`，剥离 PG 依赖 |
| 达梦专用建表 DDL<br>`artifacts/db-dm-schema.sql` | 4,217 字节 | `b0ef36b69b552fa4c79eaec61dff44d0cfef80fcebb8c68eb9443e031c261e4e` | 包含 9 张表及索引完整定义，供 DBA 预先在独立 schema 初始化 |
| 版本描述清单<br>`manifest.json` | 2,780 字节 | `e5233ea25eb8f2bf29a6e138a0b0d381b5c479320dd5e3789d38c6439be9b657` | 移除 postgres 依赖声明，已被 `SHA256SUMS` 覆盖 |
| 部署清单<br>`SHA256SUMS` | 2,298 字节 | - | 覆盖部署包内全部 30 个关键文件，校验一致性 100% (0 mismatches) |

---

## 二、架构基线与核心改动核验

### 1. 历史迁移零破坏 (Flyway V1..V6 Checksum Preserved)
- **核验对象**：`platform-service/src/main/resources/db/migration/V1__platform.sql` 至 `V6__key_credentials.sql`。
- **核验结果**：**Git status 0 修改，全部 6 个文件原字节完全未动**。
- **架构意义**：严格遵守历史不可变性原则，杜绝了直接就地修改 V6 导致已部署环境校验和破坏的严重隐患。
- **达梦独立 DDL 路径**：在 `platform-service/src/main/resources/db/dm/init_schema_dm8.sql` 与 `ops/dm8/01_schema_dm8.sql` 中维护达梦专用的完整建表语句。

### 2. Spring 驱动与 Profile 解耦
- **Maven 依赖 (`platform-service/pom.xml`)**：
  - 正式引入达梦官方 Central 驱动：`com.dameng:DmJdbcDriver18:8.1.3.140`（runtime 作用域，编译后已打包进 `BOOT-INF/lib/`）。
  - 成功剥离 `postgresql` 与 `flyway-database-postgresql` 运行依赖，避免不必要的类路径污染。
  - 保留 `com.h2database:h2` 与 `flyway-core`，保证本地开发与单元/集成测试继续开箱即用。
- **达梦配置 (`application-dm.yml`)**：
  - `spring.flyway.enabled: false`：达梦环境下关闭 Flyway 自动迁移，转由 DBA 预先执行脚本，避免 Flyway 社区版对 DM8 的不兼容报错。
  - `driver-class-name: dm.jdbc.driver.DmDriver`：显式绑定达梦驱动。

### 3. 本地测试回归与零破坏
- 执行命令：`scripts/mvn.sh -pl platform-service test`
- 实测结果：**45 组测试全部通过 (0 Failures, 0 Errors, BUILD SUCCESS)**。
- 证明：在引入达梦驱动和分离 Profile 后，本地基于 H2 的开发回归测试 100% 保持完好。

---

## 三、部署包与 Compose 容器编排改造核验

### 1. PostgreSQL 容器与数据卷解耦
- **编排文件**：`deploy/gmssl-gui-linux-amd64/compose.yaml`
- **核验事实**：
  - 容器服务中已**彻底移除** `postgres:17-alpine` 服务定义及 `postgres-data` 具名数据卷。
  - `platform` 服务环境变量显式配置：
    ```yaml
    SPRING_PROFILES_ACTIVE: dm
    SPRING_DATASOURCE_URL: ${SPRING_DATASOURCE_URL:?Set external DM8 JDBC URL}
    SPRING_DATASOURCE_USERNAME: ${SPRING_DATASOURCE_USERNAME:?Set DM8 username}
    SPRING_DATASOURCE_PASSWORD: ${SPRING_DATASOURCE_PASSWORD:?Set DM8 password}
    ```
  - 容器网络保持精简，只有 `platform` 需向外部达梦实例发起数据库连接，`engine` 仍处于只读隔离沙箱内。

### 2. 管控脚本鲁棒性与防护
- **`scripts/check.sh`**：
  - 自动检测环境变量：若 `SPRING_PROFILES_ACTIVE=dm`（默认），校验 `SPRING_DATASOURCE_URL`、`SPRING_DATASOURCE_USERNAME`、`SPRING_DATASOURCE_PASSWORD` 是否填写；未填写时直接友好报错拦截，防止启动时报数据库连接失败。
  - 仍严格保留缺少 `SHA256SUMS` 的 fail-closed 拦截与非 Linux x86_64 宿主拦截。
- **`scripts/init.sh`**：
  - 维持双文件存在保护与 0600 权限设置，仅随机生成系统安全密钥（Token、Master Key 等），绝不伪造外部数据库账号密码。
- **`scripts/stop.sh`**：
  - 执行 `docker compose stop`，仅保留密钥存储卷 `vault-data`。

### 3. 部署自动化测试回归 (18/18 PASS)
- 执行命令：`python3 -m unittest discover -s tests/deployment -p 'test_*.py' -v`
- 实测结果：**18 组测试用例全部通过 (0.935s, exit 0)**。
- 覆盖项：ELF 结构、零源码泄露、达梦驱动打包验证、PG 剥离验证、.dockerignore 凭据屏蔽、KAT 数组防切词、初始化幂等性等。

---

## 四、达梦实库独立验证 Harness 与安全隔离约束

### 1. 安全隔离边界核验
- **私有凭据管理**：`.env.dm-test` 已由 `.gitignore` 严格忽略，模板文件 `.env.dm-test.example` 仅含说明与空密码占位。
- **安全拦截规则（`tests/dm/harness.py` & `Dm8CompatibilityHarness.java`）**：
  - 强制 Schema 白名单：仅允许以 `GMSSL_TEST` 或 `GMSSL_TEST_` 开头的独立测试模式，拦截任何生产或系统模式（`SYS`, `CTISYS` 等）。
  - 强制超级用户拦截：严禁使用 `SYSDBA`, `SYS`, `SYSSSO` 等管理员账密连库。
  - 凭据输出脱敏：控制台与日志中所有数据库 URL、用户名、密码一律打码。

### 2. 实库验证状态说明
- 当前运行状态记录于 `.tools/logs/dm-acceptance/run_summary.json`：
  - `"status": "NOT_RUN"`
  - 真实说明：用户当前尚未在本地填入私有实库账密，测试套件严格遵循安全规则**未盲目执行或以假数据冒充实测**。
- **现场实测就绪性**：
  - 一键验证脚本已就绪：`./scripts/test-dm.sh`。
  - 待用户在本地配置可达的达梦测试实例 `.env.dm-test` 后，一键执行即可自动完成：
    1. 官方 DmDriver 加载
    2. 握手与版本元数据解析
    3. DDL 9 张表及索引加载
    4. BOOLEAN 与 BLOB/VARBINARY 二进制回读
    5. UNIQUE 唯一约束冲突捕获
    6. 事务回滚一致性
    7. `SELECT ... FOR UPDATE` 悲观行锁并发占用

---

## 五、终审裁定与结论

- **终审裁定**：**通过 (PASS) - 具备正式交付条件**
- **结论要点**：
  1. 系统成功将持久层由内置 PostgreSQL 切换为直连外部达梦 (DM8) 架构，彻底剥离了 PG 依赖与容器负担。
  2. 100% 保护了已有 H2 / PostgreSQL 的 Flyway `V1..V6` 历史迁移脚本，现有本地回归测试 45/45 全量通过。
  3. 达梦初始化 DDL 与配置完整进入 Linux amd64 预编译发布包（SHA: `7f06af9e...`），全套 18 组部署测试无异常。
  4. 达梦实库兼容性 Harness 与脱敏安全防护已全部就位，支持现场随时通过 `./scripts/test-dm.sh` 完成最终实库握手。
