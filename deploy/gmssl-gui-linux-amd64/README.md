# GmSSL GUI Linux (amd64) 独立预编译部署包（达梦 DM8 外部数据库版）

本部署包提供 GmSSL GUI 密码服务与图形工具箱在 Linux x86_64 (amd64) 架构下的独立容器化运行环境，数据层采用**外部达梦数据库 (DM8)** 进行关系型数据存储。

---

## 独立离线说明文档导航

为适应企业内网严格物理隔离环境，本目录包含两份专门面向现场运维与实施人员的极简离线指南（只从内网离线介质已到场开始，零外网依赖，无任何文件哈希门禁）：
- **全新安装**：请直接阅读 [离线部署说明.md](离线部署说明.md)
- **版本更新**：请直接阅读 [离线更新说明.md](离线更新说明.md)

---


## 一、架构特性与交付模式

1. **预编译零源码依赖**：
   - 包含已适配达梦 DM8 官方驱动的 Java 微服务（`engine-service` 与 `platform-service` JAR 包，内置 `com.dameng:DmJdbcDriver18:8.1.3.140`）。
   - 包含通过 Zig 交叉编译生成的 Linux x86_64 ELF 原生二进制执行器 `gmssl-runner`（纯静态 musl libc，无 macOS dylib 依赖，无动态加载器依赖）。
   - 包含已完成编译的前端静态资源（Vue 3 + Vite `web-dist/`）。
   - **目标机器无需安装 JDK、Maven、Node.js、GCC、CMake 或 Zig 等任何开发与编译工具链**。
2. **轻量纯业务运行时容器（移除内置 PostgreSQL）**：
   - 系统全面移除内置 PostgreSQL 容器，避免多余资源消耗：
     - `engine`: 基于 `eclipse-temurin:21-jre-jammy` + `openssl`，非 root (uid:gid 10001:10001) 运行，受控无外网出口。
     - `platform`: 基于 `eclipse-temurin:21-jre-jammy`，激活 `SPRING_PROFILES_ACTIVE=dm`，直连外部 DM8 数据库并集成 Vault 凭据加密引擎。
     - `web`: 官方 `nginx:1.28-alpine` 反向代理与单页应用静态托管。
   - **请确保部署机器能够正常拉取 Docker Hub 官方基础镜像**。
3. **网络与数据库连接模型**：
   - 外部 DM8 数据库由企业集中提供与维护，无需在容器内编排。
   - 容器内 `platform` 微服务通过 JDBC 直连宿主或网络可达的达梦数据库实例。
   - **Docker 容器访问宿主机网络提示**：若达梦数据库部署在运行 Docker 的同一台宿主机上：
     - Linux 宿主机：使用宿主真实物理网卡 IP 或在 Docker 中使用 `172.17.0.1`（docker0 网桥 IP）；
     - 确保宿主机防火墙放行 5236 端口入站连接。
4. **构建与实测边界说明（客观披露）**：
   - 部署包内的 `artifacts/gmssl-runner` 是在 macOS ARM64 宿主上通过 Zig 交叉编译生成的 ELF64 x86_64 二进制（SHA256: `e3d886bb...`）。
   - 宿主机未安装 Linux 内核模拟器（如 QEMU/Podman）及 Docker 守护进程，因此该 Linux x86_64 二进制在打包宿主上仅完成了静态 ELF 头、段结构及符号依赖核验，未在宿主执行容器内的全量算法回归 suite 实跑。

---


### 离线镜像构建与自定义 JRE 基础镜像说明（构建端执行）
若需要在企业外部具有网络与 Docker 的机器上重新构建离线镜像归档：
```bash
# 默认使用官方标准 eclipse-temurin:21-jre-jammy
./build-offline-images.sh

# 支持显式指定企业内部自建或受信私有仓库 JRE 基础镜像：
./build-offline-images.sh --jre-image my.private.registry:5000/base/openjdk:21-jre
# 或通过环境变量传入：
JRE_IMAGE="my.private.registry:5000/base/openjdk:21-jre" ./build-offline-images.sh
```
- **参数优先级**：CLI `--jre-image` > 环境变量 `JRE_IMAGE` > 默认 `eclipse-temurin:21-jre-jammy`，用户显式指定的值绝不自动回退；
- **自定义 JRE 兼容前提**：
  1. 必须为 Linux amd64 架构且 Java 运行环境必须为 **Java 21+**；
  2. `engine` 服务依赖基础镜像具备 `apt` 包管理器以安装 `openssl` CLI，并具备 `groupadd/useradd` 权限创建专用 `gmssl (10001:10001)` 用户；
  3. 纯精简 Alpine/BusyBox/UBI 镜像若缺乏上述依赖，构建时将清晰报错失败，绝不假称任意发行版通用兼容。

---

## 二、部署环境要求

| 组件 | 最低要求 | 检查方式 / 说明 |
|---|---|---|
| **操作系统** | Linux 64 位 (x86_64 / amd64) | `uname -m` 显示 `x86_64` |
| **外部数据库** | 达梦数据库 8 (DM8) | 外部网络可达，默认端口 5236 |
| **Docker Engine** | 24.0.0+ | `docker --version` |
| **Docker Compose** | **Compose V2 (`docker compose`)** | `docker compose version` (仅支持 V2) |
| **OpenSSL CLI** | 1.1.1+ 或 3.0+ | `openssl version` (仅用于一键生成高熵密码) |

---

## 三、快速启动步骤

### 1. 达梦数据库初始化（DBA 执行）
在目标达梦数据库中创建专用模式/用户（如 `GMSSL`），并在该模式下执行本包自带的初始化 DDL 脚本：
```sql
-- 使用达梦管理工具 (DM Management Console) 或 disql 登录目标模式执行：
-- 执行 artifacts/01_schema_dm8.sql 脚本建表
```
- 包含 `app_users`, `sessions`, `projects`, `memberships`, `materials`, `jobs`, `artifacts`, `audit_events`, `key_credentials` 等完整表结构。
- 密码材料采用 DM8 原生 `BLOB` 二进制大对象存储。

### 2. 完整性与环境预检
在部署目录根目录下执行自检脚本，验证目标主机平台、依赖、文件哈希与二进制架构：
```bash
./check.sh
```
- 自动验证当前宿主平台必须为 Linux x86_64。
- 自动验证 `artifacts/gmssl-runner` 为纯 Linux x86_64 ELF。
- 自动核验 `SHA256SUMS` 静态文件发布清单（Fail-Closed 模式）。

### 3. 初始化生成私有环境配置
```bash
./init.sh
```
- 自动生成 `.env` 私有环境变量配置文件（权限设为 `0600`）。
- 自动生成随机 32 字节高熵 Engine Token、Vault Master Key。
- 自动生成初始管理员凭据并保存至 `credentials.txt`（权限设为 `0600`）。
- **编辑 `.env` 填写真实外部达梦数据库连接信息**：
  ```bash
  SPRING_PROFILES_ACTIVE=dm
  SPRING_DATASOURCE_URL=jdbc:dm://192.168.1.100:5236?schema=GMSSL
  SPRING_DATASOURCE_USERNAME=GMSSL
  SPRING_DATASOURCE_PASSWORD=YourSecureDm8Password
  ```
  *注：若 `SPRING_DATASOURCE_URL` 包含未修改的占位符或非 `jdbc:dm://` 地址，启动脚本将立即拦截退出，严禁静默回退到嵌入式 H2。*

### 4. 启动全量容器服务
```bash
./start.sh
```
- 自动检查前置条件与达梦配置，下发后台容器构建及启动请求。
- **关于 Secure Cookie 与登录的重要提示**：
  - 默认配置 `GMSSL_SESSION_COOKIE_SECURE=true` 激活了安全 Cookie 属性，浏览器仅在 HTTPS 连接下保存会话 Cookie。
  - **生产环境**必须前置配置 HTTPS 反向代理（见第四节）。
  - 若仅用于**本地内网临时测试**，可在 `.env` 中显式修改 `GMSSL_SESSION_COOKIE_SECURE=false`。

### 5. 查看运行状态、日志与底层密码算法 KAT 验证
```bash
# 检查容器状态与端口健康响应
./status.sh

# 查看实时服务日志
docker compose logs -f

# 容器启动后，对底层 Linux 纯静态原生密码执行器进行 SM3(abc) 标准向量独立核验
./scripts/verify-native.sh
```

### 6. 停止服务
```bash
./stop.sh
```
- **数据安全保障**：停止脚本执行 `docker compose stop`，绝不会销毁私钥保险箱卷（`vault-data`）。

---

## 四、网络、反向代理与 HTTPS 配置说明

1. **默认绑定说明**：
   - 默认配置监听地址为回环接口 `GMSSL_BIND_ADDRESS=127.0.0.1`，端口 `GMSSL_WEB_PORT=8088`。
   - 默认开启安全 Cookie 标志：`GMSSL_SESSION_COOKIE_SECURE=true`。
2. **生产环境 HTTPS 反向代理配置（标准模式）**：
   在宿主机外部部署 Nginx 或 Caddy 作为 TLS 终止代理，并透传标准代理头：
   ```nginx
   server {
       listen 443 ssl http2;
       server_name gmssl.yourdomain.com;

       ssl_certificate /path/to/fullchain.pem;
       ssl_certificate_key /path/to/privkey.pem;

       location / {
           proxy_pass http://127.0.0.1:8088;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
           proxy_set_header X-Forwarded-Proto https;
           proxy_read_timeout 320s;
       }
   }
   ```

---

## 五、持久化存储与达梦数据库迁移规约

### 1. 独立部署数据存储分布
- **外部达梦 (DM8)**: 用户账号、RBAC 角色、项目成员、审计日志及密码凭据元数据。
- **本地卷 `vault-data`**: 平台私钥保险箱加密数据目录，所有敏感私钥由 `GMSSL_VAULT_MASTER_KEY` 使用 AES-256-GCM 主密钥加密存储。

### 2. 状态型密钥与数据迁移安全规约
- **状态型密钥（Stateful Key）不可迁移**：如 LMS/HSS 等抗量子有状态签名算法，因其叶子节点使用索引（OTS Index）严格绑定特定运行实例状态，严禁跨数据库直接批量导出/恢复旧状态，否则极易导致一次性私钥复用安全灾难。
- **与开发环境 H2 的区别**：严禁尝试将 H2 的 `.mv.db` 文件直接导入达梦；必须使用专用达梦建表脚本并在应用层进行合规导入。
- **Vault 主密钥一致性**：若迁移普通私钥 Vault 密文文件，新旧环境的 `GMSSL_VAULT_MASTER_KEY` 必须逐字节一致，否则无法解密历史私钥材料。

---

## 六、安全运维与一致性备份建议

1. **外部达梦数据库备份安全规约**：
   - 由 DBA 统一规划定时一致性逻辑导出或物理冷备。
   - **严禁**在无安全审计的环境中直接将用户名和密码作为命令行参数传递给 `dexp` 或 `dimp` 工具，避免凭据泄漏至系统进程表 (`ps`) 或 shell 历史。
2. **私钥保险箱卷备份**：
   - 配合停止平台服务后打包备份数据卷：
     ```bash
     ./stop.sh
     # 使用本地已有运行时镜像（如 gmssl-gui/engine 或用户已有本地离线工具镜像），带 --pull=never 避免内网拉网
     docker run --rm --pull=never --entrypoint /bin/tar --user 0:0 -v gmssl-gui-release_vault-data:/source:ro -v "$PWD":/backup gmssl-gui/engine:0.1.0-linux-amd64 czf /backup/vault-cold-backup.tar.gz -C /source .
     ./start.sh
     ```
   - 备份时务必连同当前的 `GMSSL_VAULT_MASTER_KEY` 共同离线妥善封存。
3. **开源许可**：
   - GmSSL 核心密码库基于 Apache License 2.0 开源。
   - 详见 `artifacts/GMSSL-LICENSE`。
---

## 七、版本更新与平滑升级运维规范 (Upgrade & Safe Maintenance)

### 1. 升级核心原则与数据安全保障
1. **持久卷全局固定**：`compose.yaml` 顶级名称固定为 `name: gmssl-gui-release`，私钥保险箱卷全局固定为 `gmssl-gui-release_vault-data`。无论新版本解压至何目录，容器启动时自动挂载同一持久卷，**私钥与托管材料不会因目录变更而丢失**。
2. **隔离解压升级（推荐）**：严禁直接在运行中的旧版本目录下覆盖解压新包；推荐解压至新目录（例如 `/opt/gmssl-v0.2.0`），使用内置 `./upgrade.sh` 工具受控平滑迁移配置。
3. **主密钥一致性要求 (Fail-Closed)**：旧 `.env` 中的 `GMSSL_VAULT_MASTER_KEY` 必须完整保留，**严禁在新版本重新运行 `./init.sh` 生成新密钥**，否则历史加密材料将永久无法解密！
4. **状态型私钥（LMS/HSS）不可逆规约**：若新版本运行中产生了状态型密钥签名消耗，**严禁通过恢复旧数据库或 Vault 快照进行回滚**，否则会导致一次性私钥索引复用安全灾难。

### 2. 标准平滑升级三步走

#### 步骤一：数据库与配置冷备 (Pre-upgrade Backup)
在业务停写或维护窗口期间，停止旧服务并完成一致性冷备：
```bash
cd /opt/gmssl-gui-v1/gmssl-gui-linux-amd64
./stop.sh

# 打包备份本地私钥保险箱卷（使用本地已有镜像并指定 --pull=never，严禁现场拉取外部 alpine 镜像）
docker run --rm --pull=never --entrypoint /bin/tar --user 0:0 -v gmssl-gui-release_vault-data:/source:ro -v "$PWD":/backup gmssl-gui/engine:0.1.0-linux-amd64 czf /backup/vault-pre-upgrade.tar.gz -C /source .

# 由 DBA 使用达梦原生工具（如 dexp 或物理备份）对达梦数据库目标模式执行一致性备份
```

#### 步骤二：达梦数据库基线化与增量迁移（DBA 执行）
1. **已有生产库首次登记基线 (Baseline)**：
   若现有达梦库此前未初始化版本元数据表，请在 DM8 中执行：
   ```sql
   -- 执行 artifacts/migrations/00_schema_version_and_baseline.sql
   -- 脚本内置 PL/SQL 前置核验，严格校验 10 张核心表及 BIT/VARBINARY 类型，验证通过后登记 0.1.0 基线
   ```
2. **执行新版本增量补丁（若新版本存在新字段/表）**：
   DBA 检查 `artifacts/migrations/` 目录下的增量升级 SQL 并在达梦目标模式中执行。

#### 步骤三：使用 `upgrade.sh` 完成应用切换
由于发布归档 `gmssl-gui-linux-amd64.tar.gz` 顶层已包含 `gmssl-gui-linux-amd64` 目录，解压后需进入实际工程子目录：
```bash
# 1. 解压新版本到新隔离路径
mkdir -p /opt/gmssl-gui-v2
tar -xzf gmssl-gui-linux-amd64.tar.gz -C /opt/gmssl-gui-v2
# 准确进入解压后的顶层目录
cd /opt/gmssl-gui-v2/gmssl-gui-linux-amd64

# 2. 预检与配置差异比对 (Plan 模式，纯只读无副作用)
# --from 指向旧版本的实际根目录
./upgrade.sh --from /opt/gmssl-gui-v1/gmssl-gui-linux-amd64 --plan

# 3. 确认无误后执行应用切换 (Apply 模式，自动迁移配置并启动新容器)
./upgrade.sh --from /opt/gmssl-gui-v1/gmssl-gui-linux-amd64 --apply --backup-done

# 4. 验证服务健康与底层算法执行器
./status.sh
./scripts/verify-native.sh
```