# GmSSL Workspace

面向内网团队的浏览器密码工具箱：Java 微服务后端 + Vue / TypeScript 前端。

首版已完成本机真实服务与浏览器验证，提供 80 项上游软件业务命令及 14 项 C API 扩展工具，交付范围见 [交付说明](docs/DELIVERY.md)。功能可用性以运行时 capability catalog 和测试证据为准，页面入口或 `-help` 成功不代表该操作已通过端到端验证。完整需求与分工见 [实施计划](docs/PLAN.md)，接口见 [contracts](docs/contracts.md)。

快捷表单、加密托管生成与六类证书向导的操作步骤见 [快捷操作指南](docs/QUICKSTART-WORKFLOWS.md)，增量契约见 [UX-SIMPLIFICATION](docs/UX-SIMPLIFICATION.md)，分层验收与部署限制见 [UX 验收报告](docs/review/ux-acceptance.md)。

## 范围

- GmSSL 软件算法与密钥操作、证书/CSR/CRL/OCSP、数字信封、TLS/TLCP/QUIC。
- 用户、角色、项目隔离、加密软件密钥与文件托管、临时执行、异步任务与审计。
- 密钥生成支持 GmSSL 与 OpenSSL 的已适配算法，后续业务执行仍使用固定 GmSSL 后端；SDF/SKF 硬件功能延后。
- LMS/HSS/XMSS/XMSSMT 状态型密钥采用独立的单一权威规则，不开放普通私钥那样的任意备份/复制/导入，详见下文。

## 服务

| 目录 | 职责 |
|---|---|
| `platform-service/` | Spring Boot 管理 API、账号/session/CSRF/RBAC、项目、vault、任务与审计 |
| `engine-service/` | 内部执行 API、类型化参数验证、进程隔离与限额、网络目标策略 |
| `native/` | 固定上游构建、stdin 参数帧 runner、CLI 与额外 C API 操作 |
| `web/` | 中文浏览器界面和动态算法表单 |
| `ops/`、`scripts/` | 隔离工具链、部署配置、启动停止与运维说明 |
| `tests/`、`docs/review/` | 独立验收脚本、证据和覆盖矩阵 |

浏览器只访问平台 API；engine 需要内部 token，服务器部署不直接发布 engine 端口。原生 runner 的实际进程参数不包含密码或算法参数，参数帧从标准输入传递，业务输入在帧后传入。

## 本地开发

前置：Python 3、Git、C/CMake 构建工具；前端需要 Node.js 与 pnpm。Java/Maven 可由脚本下载到工作区 `.tools/`，官方摘要校验，不修改系统配置。

```sh
./scripts/bootstrap-tools.sh
python3 native/fetch-source.py
cmake -S native -B native/.build -DCMAKE_BUILD_TYPE=Release
cmake --build native/.build --target gmssl-runner --parallel 4
./scripts/dev.sh build
./scripts/bootstrap-config.sh dev
./scripts/dev.sh start
```

运行 `./scripts/web-install.sh` 安装锁定依赖，再运行 `./scripts/dev.sh web-start`。浏览器访问 **http://127.0.0.1:5173/**。详细说明见 [web/README.md](web/README.md)。平台端口为 `8080`，内部 engine 为 `8081`，前端开发服务器为 `5173`。部署凭据仅保存在新建的私有 `.env.local`，不要粘贴到对话、日志或版本控制。浏览器使用该文件中的 bootstrap 账号登录；首次登录后由管理员创建团队账号。

```sh
./scripts/dev.sh status
./scripts/dev.sh stop
```

前端可用 `./scripts/dev.sh web-status`、`./scripts/dev.sh web-stop` 单独管理；`stop` 停止受管 Java 服务。所有停止操作核对 PID、启动身份与命令，不按宽泛进程名终止其他应用。

## 服务器部署

见 [ops/README.md](ops/README.md) 及 [deploy/gmssl-gui-linux-amd64/README.md](deploy/gmssl-gui-linux-amd64/README.md)。采用 Linux Docker Compose 结合**外部达梦数据库 (DM8)** 进行关系型数据存储，系统不内置 PostgreSQL 容器，轻量纯业务运行。生产访问应通过 HTTPS 并启用 Secure session cookie。版本升级与运维规约支持隔离解压与平滑升级工具 `./upgrade.sh`，主密钥与持久卷严格保持一致，详见部署包文档。

基础 Compose 默认隔离 engine 外部网络出口。需要协议/HTTP 获取时，由部署管理员配置数字 IP/端口白名单和受控网络 override；这与任意联网不同。当前开发环境没有 Docker CLI，静态配置校验不等于容器实测，实际状态以验收报告为准。

## 密钥与状态型签名

软件材料使用 AES-256-GCM envelope 加密，AAD 绑定项目和材料 id；数据库主要存元数据。私钥口令不进入任务数据库或审计日志；导入材料默认 `UNVERIFIED`，不凭用户给出的算法名称宣称格式正确。

状态型签名会消费私钥状态，首版约束：
- 只允许平台受控 keygen 的精确私钥产物晋升为状态型私钥；同一产物仅能晋升一次。
- 状态型私钥产物和已托管私钥禁止原始下载/复制，公钥可正常导出。
- 同一私钥签名串行化，更新后材料可靠持久化成功才发布签名。
- 故障后的 pending 密钥保持隔离，不自动解除，不接受旧备份覆盖；无可证明的恢复路径时生成新密钥。

这些特殊限制不影响普通 SM2 等软件密钥的授权导入、导出和备份。

## 验证

```sh
./scripts/mvn.sh verify
python3 tests/e2e/native_runner_acceptance.py
```

前端单元测试/构建、真实 HTTP/浏览器验收及完整工具覆盖请参照对应模块 README 与 `tests/e2e/`、`tests/toolbox/`。必须分别报告单元测试、模拟依赖、真实 GmSSL 运行、浏览器操作与容器部署结果，不互相替代。

## 上游身份与许可

上游：<https://github.com/guanzhi/GmSSL>，固定提交 `24ae482701a7b124826c382fffc55c19f76d475d`，版本 `3.3.0-dev.1183`。这不是 README 推荐稳定版 `v3.2.0` 的同一快照。下载脚本校验固定来源与内容身份，原始源码与本项目扩展保持分离。构建通过 `native/apply-overlays.py` 应用 5 项有原始/派生 SHA-256 记录的修复（SCT 序列化与 LogID、X.509 可选时间与 CRL 初始化），不修改原始 checkout。补丁清单及 diff 在 `native/.build/generated/`，运行时 catalog 显示修复身份；本产品不是未经修改的原版 GmSSL 二进制。

GmSSL 采用 Apache-2.0；分发原生 runner 时须随附上游许可证与适用声明。engine 镜像包含 `GMSSL-LICENSE`。其他依赖许可见各依赖自身发行内容与锁文件。此处不替第三方软件另行指定许可证。