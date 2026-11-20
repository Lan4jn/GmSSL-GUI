# 达梦版本升级机制与证书交付精简计划 (Upgrade and Certificate Delivery Plan)

## 一、方案目标与职责边界

本计划针对用户批准的“两项一起补齐”需求，由 `build-quality` 作为单一 Owner 负责交付可审计的达梦版本升级工具链、版本化 Schema 迁移规范、更新部署模板及最终打包。

### 1. 模块职责边界
- **升级机制 Owner (`build-quality`)**:
  - 新增独立升级工具 `deploy/gmssl-gui-linux-amd64/scripts/upgrade.sh` 及根包装器 `upgrade.sh`；
  - 建立达梦 Schema 版本元数据表与基线化 SQL 目录 `ops/dm8/migrations/` 及 `deploy/artifacts/migrations/`；
  - 维护白名单打包脚本 `scripts/package-linux-amd64.sh`；
  - 编写并执行全量 Mock 回归测试套件 `tests/deployment/test_deployment_upgrade.py`；
  - 更新根目录 `README.md` 与 `deploy/gmssl-gui-linux-amd64/README.md` 的版本升级与回滚运维规范。
- **业务与证书交付协作 (其他队友)**:
  - `platform`: 维护 Java 平台后端业务与 DM 驱动适配（已在 task-35 完成）；
  - `frontend` / `web-verifier`: 证书向导组件增强与前端生产 `web/dist` 构建（task-45 / task-47）；
  - `architecture` / `integration`: 独立审查与实库验证验收。

---

## 二、核心架构决策与关键机制

### 1. 达梦数据库 (DM8) 显式基线与增量版本策略 (Explicit Baseline)
- **拒绝假装 Flyway 支持 DM8**：在 `application-dm.yml` 中继续保持 `spring.flyway.enabled: false`，不臆造或引入未经官方验证的第三方 Flyway DM 插件。
- **现有生产 Schema 零破坏基线策略**：
  - 现有已初始化的生产库**没有版本元数据表**，严禁盲目执行全量脚本或强行假定历史版本；
  - 新建版本控制表规范：
    ```sql
    CREATE TABLE IF NOT EXISTS schema_version (
        version VARCHAR(50) PRIMARY KEY,
        description VARCHAR(200) NOT NULL,
        installed_on TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
        checksum VARCHAR(64) NOT NULL,
        success BIT DEFAULT 1 NOT NULL
    );
    ```
  - 提供显式基线脚本 `00_baseline_v0.1.0.sql`：
    - 仅在全部 10 张核心业务表已存在且 `schema_version` 不存在时，由 DBA 显式登记当前基线版本 `0.1.0`；
    - 不修改现有表结构，不重复创建已有表。
  - 后续新功能增量 DDL 脚本放入 `migrations/` 命名规则明确为 `01_v0.1.0_init.sql`、`02_v0.2.0_feature.sql`。

### 2. 隔离升级而非原位覆盖 (Out-of-Place Upgrade)
- **目录隔离升级模式**：
  - 严禁直接在运行中的旧部署目录下覆盖解压新包；
  - 推荐解压到新目录（如 `/opt/gmssl-v0.2.0`），通过 `upgrade.sh` 将旧目录的配置受控迁移至新目录。
- **持久化卷稳定性保证**：
  - `compose.yaml` 顶级名称固定为 `name: gmssl-gui-release`；
  - 数据卷名全局固定为 `gmssl-gui-release_vault-data`，即使解压目录名称改变，容器重新挂载的依然是同一个数据卷，数据完好保留。

### 3. `upgrade.sh` 工具链设计 (Plan / Check / Apply 三阶段)
- **命令语法**：`./upgrade.sh [--from <old_dir>] [--plan|--check|--apply] [--yes]`
- **阶段 1: Plan / Check（默认只读探测，绝不破坏）**：
  1. 校验目标新目录与旧目录不是同一个物理路径（拒绝危险的原地自覆盖）；
  2. 拒绝软链接、校验目录真实路径，支持路径含空格；
  3. 检查旧目录中 `.env` 是否存在且包含有效的 `GMSSL_VAULT_MASTER_KEY`（若缺少主密钥，**Fail-Closed 立即终止**，杜绝生成新密钥造成历史私钥无法解密）；
  4. 检查新版本 `.env.example` 中是否存在新增配置项，若有则输出差异报告；
  5. 检查版本是否为同版本重入或非法回滚；
  6. 校验未完成冷备确认前禁止直接应用。
- **阶段 2: Apply（用户显式确认后受控执行）**：
  1. 提示用户完成外部达梦数据库备份与当前 `vault-data` 卷冷备；
  2. 复制旧版本 `.env` 与 `credentials.txt` 至新目录，权限严格锁死为 `0600`；
  3. 保留旧主密钥与现有 DB 账密，新配置项仅以注释提示形式补入，绝不随机替换；
  4. 调用旧目录 `./stop.sh` 停止旧服务容器（不销毁数据卷）；
  5. 调用新目录 `./check.sh` 验证环境、ELF 魔数及达梦配置；
  6. 调用新目录 `./start.sh` 启动新版本容器（触发 `docker compose up -d --build`）；
  7. 输出升级成功状态与 DBA 需执行的增量 SQL 清单，指导用户执行 `./scripts/verify-native.sh` 自检。

### 4. 回滚与状态型私钥（Stateful Key）不可逆规约
- 应用回滚与数据库恢复严格解耦；
- 若新版本启动后状态型算法（LMS/HSS/XMSS）签署了新数据，**严禁回滚还原旧数据库或 Vault 快照**，避免一次性私钥索引复用。

---

## 三、实施任务与 TDD 计划

1. **测试先行 (Red Tests)**：
   - 在 `tests/deployment/test_deployment_upgrade.py` 中编写全面测试用例：
     - 测试 1: `upgrade.sh --help` 与 `--plan` 默认只读探测、无副作用；
     - 测试 2: 缺失旧 `.env` 或缺少 `GMSSL_VAULT_MASTER_KEY` 时 Fail-Closed 拦截；
     - 测试 3: 路径含空格、原地相同目录、symlink 目录探测与拦截；
     - 测试 4: 完整配置迁移至新目录后权限严格为 0600，且新旧 Master Key 完全一致；
     - 测试 5: 达梦 `schema_version` 表与 `00_baseline_v0.1.0.sql` 幂等基线逻辑；
     - 测试 6: 增量脚本存在性与 `package-linux-amd64.sh` 打包完整性；
     - 测试 7: 升级流程中无任何秘密打印到 stdout / stderr。
2. **工具链与脚本实现 (Green Implementation)**：
   - 编写 `deploy/gmssl-gui-linux-amd64/scripts/upgrade.sh` 及根目录软链/包装器 `upgrade.sh`；
   - 编写 `ops/dm8/migrations/00_schema_version_and_baseline.sql`，并复制至 deploy artifacts；
   - 更新 `scripts/package-linux-amd64.sh` 将增量 SQL 纳入打包白名单并重新计算校验和；
   - 更新文档：在 `deploy/gmssl-gui-linux-amd64/README.md` 与根目录 `README.md` 增加专属《版本升级与安全运维》指南。
3. **回归核查与收敛 (Refactor & Verify)**：
   - 运行 `python3 -m unittest discover -s tests/deployment -p 'test_*.py' -v` 确保全部测试绿灯；
   - 验证既有受管服务不受任何干扰。
