# 离线部署与更新说明独立核查验收报告

## 一、核查对象与审计基准

- **受审文件 1**：`docs/离线部署说明.md`（129 行）
- **受审文件 2**：`docs/离线更新说明.md`（123 行）
- **核查工具与命令契约**：对照 `deploy/gmssl-gui-linux-amd64` 下 `compose.yaml`、`upgrade.sh`、`load-images.sh`、`init.sh`、`check.sh` 及后端 Spring 源码
- **验收判定**：**PASS（全项达标通过）**

---

## 二、逐项红线核验结论

| 验收维度 | 核心核验指标 | 核验事实与证据 | 判定 |
| :--- | :--- | :--- | :--- |
| **介质与离线前提** | 零外网依赖、镜像缺失即停 | 两文均明确从“离线介质已到场”开始；均显式加粗声明：`gmssl-gui-images-linux-amd64.tar` 必须由交付方随包提供，缺少即停止；明确指出现有源码仓未内嵌该镜像包，不掩饰介质缺口；无跨发行版在线安装臆造命令。 | **PASS** |
| **命令离线隔离** | 无在线 pull/build，无文件校验门禁 | 启动与升级命令均显式包含 `--pull never --no-build --force-recreate`；冷备镜像指定本地旧镜像并显式 `--pull=never`；全文零 `apt-get/yum/docker build/docker pull/curl` 外网指令；未引入强制外部 SHA 校验文件。 | **PASS** |
| **目录与参数契约** | 解压多层目录、现有脚本参数对齐 | 明确指出 `tar -xzf` 解压后自带 `gmssl-gui-linux-amd64/` 目录；`upgrade.sh --from <旧根目录> --plan` 与 `--apply --backup-done` 路径与参数完全吻合；`load-images.sh <tar路径>` 传参正确。 | **PASS** |
| **同 Tag 镜像与回退** | 先提取实际 Image ID 另打 Tag 归档 | 更新说明第 3 节在导入新包前，先通过 `docker inspect --format "{{.Image}}"` 提取当前旧容器的真实 Image ID，打上 `rollback-before-v2` 独立标签并 `docker image save` 归档；随后 load 同 tag 新镜像配合 `--force-recreate` 强制重建容器，彻底解决旧镜像丢失与容器不更新问题。 | **PASS** |
| **数据与密钥持久性** | Compose 项目名、卷名、Master Key 严格保留 | 明确新旧目录锁定 Compose 项目名 `gmssl-gui-release` 与命名卷 `gmssl-gui-release_vault-data`；强调原主密钥严禁重新生成（否则历史材料不可解）；升级脚本自动迁移原 `.env`。 | **PASS** |
| **数据库基线与用户** | 初次建表 vs 既有库升级、旧账户密码不重置 | 初次部署指导执行 `01_schema_dm8.sql` + `00_schema_version_and_baseline.sql`；更新说明严格禁止已有业务库重跑初始化 SQL，仅执行基线检查；明确说明 `.env` 中的 bootstrap 仅在空库生效，已有库绝不重置原用户密码。 | **PASS** |
| **网络会话契约** | HTTP 与 HTTPS Cookie 安全属性明确 | 详细说明内网纯 HTTP 下 `GMSSL_SESSION_COOKIE_SECURE=false`，前置真实 HTTPS 代理时设为 `true`，有效防止现场因 Cookie 丢失导致登录反复 401。 | **PASS** |
| **状态型数据警示** | 状态型密钥与快照回退边界明确 | 更新说明第 8 节专门设立状态型密钥特别约束，明确指出状态推进后若回退快照可能引起一次性状态重复使用风险，禁止盲目倒退。 | **PASS** |

---

## 三、最终验收裁定

两份离线文档条理清晰、命令精确无语法错误，完全符合现场纯离线闭环运维标准，准予正式交付。
