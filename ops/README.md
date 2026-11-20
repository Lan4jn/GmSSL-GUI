# 构建、开发与部署

## 当前验收边界

本机 macOS arm64 已验证工作区隔离 Temurin 21.0.12.1+1 / Maven 3.9.16，根 Maven 模型校验通过。Docker CLI 当前缺失，本文 Compose / Dockerfile 为待 Linux 容器验证的部署配置，非已运行的容器结果。业务模块测试由其各自测试报告记录；上游 106/106 测试不是新应用测试。

## 可复现工具链

```sh
bash scripts/bootstrap-tools.sh
scripts/mvn.sh -B -N validate
scripts/mvn.sh -B verify
```

下载、校验、解压都位于 `.tools/`，不修改系统 JAVA_HOME 或 shell 配置。固定 Temurin 21.0.12.1+1，支持 macOS/Linux 的 arm64/x86_64；固定 Maven 3.9.16。脚本的 JDK SHA256 来自 Adoptium 官方元数据，Maven SHA512 来自 Apache 官方摘要；下载后核验硬编码摘要，不凭 TLS 或文件名推断完整性。Maven 缓存隔离 `.tools/m2/repository`。

`source .tools/env.sh` 可为当前 shell 启用 Java/Maven；退出该 shell 即撤销。建议普通构建始终使用 `scripts/mvn.sh`。初次联网下载需要 curl 和 SHA 摘要工具；已下载归档再次执行也重新校验。下载失败保留 `.partial`，下次覆盖该部分文件，不动已有源代码或系统工具。

本机真实证据 `.tools/logs/bootstrap-tools.log`、`.tools/logs/maven-root-validate.log`，不加入版本控制。

工具脚本自测：`python3 ops/test-tooling.py`（私有配置/不覆写、精确进程树终止、跨块秘密脱敏与日志限额），测试fixture只写被忽略的 `.tools/tests/`；最近结果 `.tools/logs/tooling-tests.log`。


## 本地开发

```sh
python3 native/fetch-source.py
cmake -S native -B native/.build -DCMAKE_BUILD_TYPE=Release
cmake --build native/.build --target gmssl-runner --parallel 4
bash scripts/bootstrap-config.sh dev
scripts/dev.sh build
scripts/dev.sh start
scripts/dev.sh status
# web 目录按其 README 启动 Vite；默认 :5173 同源反代 /api 到 :8080
scripts/dev.sh stop
```

如已有固定提交的只读上游：`python3 native/fetch-source.py --source /tmp/gmssl-review.V5gpYG/upstream` 核验后，使用 `cmake -S native -B native/.build -DGMSSL_SOURCE_DIR=/tmp/gmssl-review.V5gpYG/upstream`。native 构建归 integration 模块维护，不重复复制修改上游源码。

`bootstrap-config.sh` 为每次新部署随机生成 token、32 字节 master key、管理员密码及数据库密码，不生成固定默认密码。配置位于 `.env.local`，初始登录位于 `.env.local.credentials`，均为 0600，脚本只输出路径，不输出秘密。已有文件会保留并报错，避免覆盖主密钥。主密钥与数据库/vault 备份必须妥善分别保管。

开发 Java 服务绑定 loopback，仅适合本机调试。日志和精确进程 PID/启动身份位于私有 `.runtime/`；`ops/redact-log.py` 在落盘前流式遮蔽已配置的 engine token、vault master key、bootstrap 与数据库密码，支持跨读取块匹配，每服务最多保留 10 MiB 后继续 drain；不会把全部服务输出转发到共享控制台。停止前校验 PID、启动时间和 jar 路径，并按当次进程快照捕获后代；逐次发信号前再校验启动身份和命令，先 TERM 后对仍存活的已验证进程 KILL，避免按进程名批量停止。脚本不自动展示服务日志；错误时在本机查看私有文件，分享前审查/脱敏。业务不得自行输出 token、密码或明文密钥；脚本不承诺能擦除业务代码主动记录的秘密。启动异常要检查私有日志和健康状态，禁止把脚本返回当作全部功能验收。

## Linux Docker Compose（达梦 DM8 外部数据库版）

本部署架构采用**外部达梦数据库 (DM8)** 提供关系型数据存储，系统不内置 PostgreSQL 容器，避免多余资源消耗并符合企业国产化数据库架构规范。

准备 Docker Engine 与 Compose v2 的 Linux 主机后：

```sh
bash scripts/bootstrap-config.sh server
# 编辑 .env.server 填写外部达梦 (DM8) 数据库真实连接参数与凭据
# 确保在达梦目标 Schema 中已执行 ops/dm8/01_schema_dm8.sql 建表脚本
# Docker 静态校验不要输出展开后的配置，它可能包含 secrets。
docker compose --env-file .env.server config --quiet
docker compose --env-file .env.server build
docker compose --env-file .env.server up -d
docker compose --env-file .env.server ps
# 正常停止服务（持久化 vault-data 保险箱卷不受影响）：
docker compose --env-file .env.server stop
```

默认入口 `127.0.0.1:8088`，web nginx 同源代理 `/api` 到 platform:8080。engine:8081 不向宿主 publish。Java 服务以 uid/gid 10001 非 root 运行，read-only rootfs、私有 tmpfs、drop ALL capabilities、no-new-privileges、有界内存/PID；engine 临时目录为 256 MiB tmpfs。仅通过 `vault-data` 卷保存私钥保险箱加密数据。

服务器给多人访问前应在 HTTPS 反向代理后运行；绑定地址通过私有 env 的 `GMSSL_BIND_ADDRESS` 设置，默认 loopback。服务端配置默认 `GMSSL_SESSION_COOKIE_SECURE=true`，必须在 HTTPS 入口使用。仅本机临时 HTTP 验证时显式设 false；dev bootstrap 默认 false。不要仅暴露 HTTP 后宣称传输已加密。首次登录后修改/轮换 bootstrap 凭据；已有数据库保留用户，bootstrap 变量并非重置 API。

后端网络默认 `internal: true`，engine 默认无外部网络出口，allowlist 仅 `127.0.0.1,::1` 和端口 `14433..14438`（明确列表），`GMSSL_ENGINE_ALLOW_LOOPBACK=true`。内置协议成对测试可用，访问管理者允许的远端节点须使用 `ops/compose.protocol-egress.example.yaml`：

1. 管理员在受控 Docker 主机创建 external 网络 `gmssl-protocol-egress`，并配置该网络出口防火墙，只放行目标 IP/端口；不使用 host 网络。
2. 在 0600 的 `.env.server` 增加 `GMSSL_ENGINE_ALLOWED_HOSTS=10.20.0.10`、`GMSSL_ENGINE_ALLOWED_PORTS=14433,14434`（替换为管理员确认的数字 IP 与非特权端口，不支持域名）。
3. 显式选择 override：`docker compose --env-file .env.server -f compose.yaml -f ops/compose.protocol-egress.example.yaml config --quiet`，随后用同样 `-f` 参数 `up -d`。
4. 验证 allowlist 外目标、link-local/metadata、特权端口仍被应用拒绝；使用主机防火墙提供第二层限制。external 网络不存在/allowlist 未配置时部署报错，不退化为 host 或全网访问。

此例只增加 engine 的管理员受控网络出口，不 publish engine、不允许浏览器任意提供内网扫描目标。只有 frontend 网络的 platform 能连 web；浏览器不直连 engine。Docker 资源限制不取代应用队列/超时/输入输出限额。

Docker build 复用 `native/fetch-source.py` 的固定 commit 校验，runner 静态链接 GmSSL，并在镜像中附 `/app/GMSSL-LICENSE`。x86 native 加速显式关闭依赖 `-march=native` 的分支，避免将构建宿主 ISA 当成分发基线。Java 镜像构建使用 `-DskipTests`，因此交付前须独立 `scripts/mvn.sh verify` 并跑 native/frontend 测试；镜像能构建不等于测试通过。基础镜像和 Postgres tag 目前未固定 digest，生产发布需记录实际 digest、漏洞扫描和 Linux/目标架构容器实测。

## 备份、恢复、轮换

- 外部达梦 (DM8) 数据库应由 DBA 统一执行标准一致性冷备或逻辑备份（严禁在无安全鉴权的环境下把账号密码明文写在命令行参数中）。
- 业务侧配合停止服务后打包备份 `vault-data` 卷，需使用本地已有镜像避免内网拉网，覆盖入口点与 root 权限以具备 tar 及挂载目录写权限：
  ```bash
  docker compose --env-file .env.server stop
  docker run --rm --pull=never --entrypoint /bin/tar --user 0:0 -v gmssl-gui-release_vault-data:/source:ro -v "$PWD":/backup gmssl-gui/engine:0.1.0-linux-amd64 czf /backup/vault-cold-backup.tar.gz -C /source .
  docker compose --env-file .env.server up -d
  ```
- 备份时务必连同当前 `GMSSL_VAULT_MASTER_KEY` 离线安全妥善封存。
- **状态型私钥（Stateful Key，如 LMS/HSS）规约**：一次性私钥索引绑定实例运行状态，严禁跨数据库或通过旧备份随意覆盖恢复已有状态。
- 备份包含私密配置，限制访问并加密；不要把 `.env*`、`.data`、`.runtime`、`.tools` 归档进源码或镜像上下文。
- 恢复到隔离实例后验证项目/角色隔离、材料解密、下载权限和审计，再切流量。原 master key 必须与密文匹配，不可直接替换环境变量当作轮换。
- engine token 可协调两服务同时轮换；vault master key 轮换需要显式重新包裹/迁移方案，当前脚本不会执行数据迁移。
- 升级先备份，核查 Flyway schema，验证 runner commit 与能力目录版本。状态型私钥恢复需遵循应用的 pending/恢复门槛，不以旧备份随意恢复签名状态。