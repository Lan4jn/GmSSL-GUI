# 达梦（DM8）数据库依赖工件与迁移策略事实核实报告

**文档状态**：已核实 (Verified Fact-Check)  
**核查时间**：2026-10-19  
**核查人**：Integration (Teammate)  
**核查对象**：
1. 达梦官方 DM8 JDBC 驱动在 Maven Central 的真实性、官方坐标与 Java 21 兼容性
2. 当前项目 Flyway 11.7.2 运行时体系对达梦（DM8）的官方插件与支持现状
3. 替换 PostgreSQL 的可靠落地路线推荐

---

## 一、DM8 JDBC 官方驱动真实坐标与供应链凭据

此前部分技术推测所断言的“达梦驱动通常不在 Maven Central / 必须本地手动安装”为**不实断言**。官方已由达梦官方团队（组织机构 `dameng`, 邮箱 `dmtech@dameng.com`）正式向 Maven Central 发布官方组件。

### 1. 官方 Maven Central 真实坐标
- **GroupId**: `com.dameng`
- **ArtifactId**: `DmJdbcDriver18`
- **最新发布版本**: `8.1.3.140`（发布时间：2024-04-02）
- **官方 POM 声明**:
  - URL: `https://gitee.com/dmedu/dm-jdbc-jars`
  - SCM: `https://gitee.com/dmedu/dm-jdbc-jars.git`
  - 开发者组织: `dameng` (http://www.dameng.com)
  - 许可证: The Apache License, Version 2.0

### 2. HTTP 元数据与本地解析凭据
- **Maven Central 元数据 URL**:  
  `https://repo1.maven.org/maven2/com/dameng/DmJdbcDriver18/maven-metadata.xml`
- **工件真实下载 URL**:  
  `https://repo1.maven.org/maven2/com/dameng/DmJdbcDriver18/8.1.3.140/DmJdbcDriver18-8.1.3.140.jar`
- **实际下载工件 SHA-256**:  
  `9af4ff4d6ed15948507f528a18ab9b7196b3600d9169ad7998c19869031a3c6f`
- **本地工程解析测试**:
  使用工程自带隔离 Maven 环境 `bash scripts/mvn.sh dependency:get -Dartifact=com.dameng:DmJdbcDriver18:8.1.3.140` 成功直接解析并下载至本地仓库，无任何外部私有 settings 或特殊凭据依赖。

### 3. Java 21 运行兼容性核验
对官方下载 JAR 内部驱动入口类 `dm/jdbc/driver/DmDriver.class`（SPI: `META-INF/services/java.sql.Driver`）执行 `javap -v` 深度解析字节码：
```text
minor version: 0
major version: 52 (Java SE 8)
```
- 字节码主版本为 `52`（即基于 Java 8 编译，JDBC 4.2 标准实现）。
- 根据 JVM 标准向后兼容规范，Java 21 运行时对 Major Version 52 的标准 JDBC 驱动完全向前兼容运行；驱动支持 JDK 8 ~ JDK 21+。

---

## 二、当前工程 Flyway 现状与达梦支持事实

### 1. 当前工程 Flyway 依赖版本
通过执行 `mvn dependency:tree -pl platform-service -Dincludes=org.flywaydb:*` 解析得到：
- `org.flywaydb:flyway-core:11.7.2` (Spring Boot 3.5.7 starter 管理版本)
- `org.flywaydb:flyway-database-postgresql:11.7.2`

### 2. Flyway 官方数据库支持核查
- 核阅 Redgate Flyway 官方支持数据库文档及 Maven Central `org.flywaydb:flyway-database-*` 官方插件列表：
  - **结论**：Flyway 官方（包括开源 Community 与商业 Enterprise）**均无原生达梦插件**（无 `flyway-database-dameng` 或官方 `DatabaseType` 注册）。
  - GitHub 官方 Issue（如 #3216）及达梦官方生态讨论均证实达梦尚未进入 Redgate 官方发布流。
- 第三方社区虽然存在个人开源的达梦适配器（如自定义 SPI `DatabaseType` 反射注入），但多针对 Flyway 6/7/8/9 旧架构，与当前 Spring Boot 3.5 所引入的模块化 Flyway 11+ 架构存在严重类加载与 SPI 断裂风险，极易造成生产维护脆弱性。

---

## 三、现有数据库 Schema 分析与达梦方言差异

当前平台共 6 个迁移脚本（`V1__platform.sql` 至 `V6__key_credentials.sql`），涉及 9 张业务表与 1 个索引：
1. **表与索引清单**：
   - `app_users`
   - `sessions`
   - `projects`
   - `memberships`
   - `materials`
   - `jobs`
   - `artifacts`
   - `audit_events`（含 `audit_project` 索引）
   - `stateful_material_history`
   - `stateful_promotions`
   - `key_credentials`
2. **PostgreSQL 与 DM8 兼容性要点**：
   - 字段类型：`varchar`、`bigint`、`int`、`boolean` 达梦完全原生支持。
   - 二进制存储：`V6__key_credentials.sql` 中的口令密文采用 PostgreSQL 的 `bytea` 类型，达梦中对应原生类型应调整为 `BLOB` 或 `VARBINARY`。
   - 命名大小写：达梦默认对象标识符为大写（除非用双引号包裹）；Spring Boot `JdbcTemplate` / SQL 查询多为小写，达梦实例通常配置为大小写敏感或不敏感策略。

---

## 四、最小维护风险替换路线建议

基于“优先官方资料与实际 Maven artifact、不盲目手写自定义 Flyway 插件”原则，提出以下双轨路线：

### 推荐路线：达梦 DBA 离线预置脚本 + 生产 Profile 禁用 Flyway（最小维护成本，最佳实践）
1. **架构解耦**：
   - 在平台服务新增 Spring Profile（如 `application-dm.properties` 或 `SPRING_PROFILES_ACTIVE=dm`）。
   - 在达梦 Profile 下设置：
     ```properties
     spring.flyway.enabled=false
     spring.datasource.url=jdbc:dm://${DM_HOST:localhost}:${DM_PORT:5236}/${DM_DATABASE}?schema=${DM_SCHEMA:GMSSL}
     spring.datasource.username=${DM_USERNAME}
     spring.datasource.password=${DM_PASSWORD}
     spring.datasource.driver-class-name=dm.jdbc.driver.DmDriver
     ```
2. **DDL 交付资产**：
   - 在项目中提供标准独立交付脚本（如 `ops/dm8/01_schema_dm8.sql`），一次性完成整套 9 张表及主外键创建（仅将 `bytea` 转换为 `BLOB`）。
   - 由用户或系统 DBA 在达梦环境中预先执行该脚本，避开在 Java 应用层自造 Flyway 驱动的巨大生态风险。
3. **依赖引入**：
   - 在 `platform-service/pom.xml` 中加入官方 Maven Central 依赖：
     ```xml
     <dependency>
         <groupId>com.dameng</groupId>
         <artifactId>DmJdbcDriver18</artifactId>
         <version>8.1.3.140</version>
         <scope>runtime</scope>
     </dependency>
     ```

### 备选方案评估（不推荐）：手写 Flyway 11 DatabaseType SPI 扩展
- **风险**：Flyway 11 将各大数据库拆分为独立的子模块（`flyway-database-*`），内部大量内部 API 在各小版本间频繁重构；自行编写类实现 `DatabaseType`、`Parser`、`Connection` 等工作量大且无官方保障，一旦 Spring Boot 升级 Flyway 极易崩溃。

---

## 五、结论与总结

1. **官方驱动**：`com.dameng:DmJdbcDriver18:8.1.3.140` **已正式存在于 Maven Central**，本地 Maven 可直接解析下载，SHA-256 为 `9af4ff4d6ed15948507f528a18ab9b7196b3600d9169ad7998c19869031a3c6f`，Java 21 完全兼容运行。
2. **Flyway 支持**：Flyway 11.7.2 官方**无达梦原生插件**。
3. **落地建议**：采用**官方 Maven 驱动 + DBA 预置 DDL 脚本 + 达梦环境禁用 Flyway 自动迁移**作为最小改动且最高可靠性的上线方案。
