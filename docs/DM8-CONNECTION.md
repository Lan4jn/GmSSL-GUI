# 达梦数据库 (DM8) 实库连接与配置说明

本文档指导如何在本地或测试环境中配置私有达梦数据库 (DM8) 连接信息，供后续平台真实数据库兼容性测试使用。

---

## 一、配置文件准备

1. **从公共模板复制私有配置**：
   在项目根目录下执行：
   ```bash
   cp .env.dm-test.example .env.dm-test
   ```

2. **限制私有配置文件权限（强制）**：
   为防止凭据泄露，必须将私有配置文件权限设为仅当前用户可读写：
   ```bash
   chmod 600 .env.dm-test
   ```
   > **注**：项目 `.gitignore` 已配置 `.env.*` 规则，`.env.dm-test` 不会被纳入版本控制。严禁将包含真实密码的文件提交至代码仓库。

---

## 二、配置项与变量契约

在 `.env.dm-test` 中填写以下环境变量：

| 环境变量名 | 说明 | 示例值 |
| :--- | :--- | :--- |
| `DM_TEST_JDBC_URL` | 达梦数据库 JDBC 连接串 | `jdbc:dm://127.0.0.1:5236?schema=GMSSL_TEST` |
| `DM_TEST_USERNAME` | 测试用户名 | `GMSSL_TEST` |
| `DM_TEST_PASSWORD` | 测试用户密码 | `<你的测试密码>` |
| `DM_TEST_SCHEMA` | 测试模式（Schema）名 | `GMSSL_TEST` |

---

## 三、安全与隔离红线（必读）

为了防止意外污染或损坏现有数据，请严格遵守以下隔离规则：

1. **严禁连接生产环境**：
   必须使用独立的本地开发实例或受控测试服务器。
2. **严禁使用系统高权限用户**：
   **禁止**使用 `SYSDBA`、`SYSSSO`、`SYS` 等系统预置超级用户，也不要使用 `SYS` 等系统模式。
3. **使用独立的空模式 / 专用测试账号**：
   - 优先保持 **Schema 与 Username 一致**（例如创建名为 `GMSSL_TEST` 或 `GMSSL_TEST_*` 的用户与同名模式）。
   - 该账号只需拥有其所属 schema 下的表操作权限：
     - 建表 / 删表：`CREATE TABLE`
     - 建索引 / 删索引：`CREATE INDEX`
     - 常规数据操作：`SELECT`, `INSERT`, `UPDATE`, `DELETE`
4. **网络连通性确认**：
   - 如果达梦实例运行在远程 Linux 服务器或 Docker 容器中，请确认宿主机端口映射正常且防火墙放行（默认端口 `5236`）。
   - 在执行测试的机器上使用 `nc -zv <HOST> 5236` 或 `curl -v telnet://<HOST>:5236` 确认网络连通。

---

## 四、初始化 SQL 与启动方式说明

1. **DBA 执行初始化 SQL 脚本**：
   - 脚本位置：`platform-service/src/main/resources/db/dm/init_schema_dm8.sql`（构建后随包位于类路径 `/db/dm/init_schema_dm8.sql`）。
   - 该脚本完整定义了对齐 V1 ~ V6 版本的 9 张业务表、关联外键约束、唯一索引及级联删除规则。
   - 包含针对达梦特性的类型适配：`encrypted_passphrase VARBINARY(4096)`，布尔字段使用原生 `BOOLEAN`。
   - 在已创建的测试用户/模式（如 `GMSSL_TEST`）下，由 DBA 使用 `disql` 或达梦管理工具执行该初始化脚本。

2. **Spring Profile 启用达梦数据源**：
   - 平台已提供专用配置 `application-dm.yml`，通过指定 `SPRING_PROFILES_ACTIVE=dm` 生效。
   - 在 `dm` profile 下，Spring 自动加载达梦官方驱动 `dm.jdbc.driver.DmDriver`，并显式禁用 Flyway 自动迁移（`spring.flyway.enabled: false`）。
   - 连接配置通过环境变量注入：
     - `SPRING_DATASOURCE_URL`
     - `SPRING_DATASOURCE_USERNAME`
     - `SPRING_DATASOURCE_PASSWORD`
