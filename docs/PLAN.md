# GmSSL Web Toolbox — 实施计划与决策记录

## 需求确认
用户已明确确认理解一致并授权规划开发。形态为 Java 微服务后端、纯浏览器前端、内网多人。首版覆盖固定 GmSSL 的全部**软件**工具能力：算法、密钥、证书/CSR/CRL/OCSP、TLS/TLCP/QUIC。硬件 SDF/SKF 和 OpenSSL 实现延后，不交付硬件页面/模拟器。后端引擎契约允许未来增加 provider。禁止 git commit/push；不请求 sandbox escalation。

上游基线：guanzhi/GmSSL，24ae482701a7b124826c382fffc55c19f76d475d，版本 3.3.0-dev.1183。README 所述稳定版 v3.2.0 与此开发快照不可混写。上游不直接改写，派生 runner 与源码下载/校验分开。

## 已知环境与基线
- 初始工作区为空，无现存业务需迁移。
- 系统仅发现 Java 8，无 Maven/Gradle/Docker CLI；采用工作区隔离 JDK 21/Maven，不变更系统配置。
- 已有上游只读分析源码 `/tmp/gmssl-review.V5gpYG/upstream`；其 macOS arm64 Release 106/106 CTest 通过，包含 1 个内部 PBKDF2 慢向量跳过；这不是新应用测试结果。
- 本机没有 Docker 时，必须报告 Compose 静态校验与本机服务测试的区别，不假称容器实测。

## 技术与服务边界
- Java 21 LTS，Spring Boot 3.5.7，Maven 聚合工程。
- `platform-service`：浏览器唯一业务入口，账号/session/RBAC、项目、加密密钥与文件、异步任务、审计、调用 engine。
- `engine-service`：内网专用执行服务，GmSSL provider 的能力目录、参数验证、隔离执行、超时/取消、结果收集。只通过内部 token 调用，不直接暴露公网/浏览器。
- `native`：固定上游构建与自有 runner；秘密通过 stdin 帧传给 runner，避免出现在 OS 进程参数。禁止 shell 命令拼接或任意 argv API。
- `web`：Vue 3 + TypeScript + Vite，中文浏览器 UI，同源 `/api`，无外部 CDN。
- PostgreSQL 用于服务器元数据；开发/测试允许 H2 PostgreSQL 模式。软件密钥/文件由独立 vault 以 AES-256-GCM 加密，主密钥从部署 secret 传入、不入库、不入版本控制。
- Linux Docker Compose 交付，管理服务 8080、内部引擎 8081、前端反代。当前 macOS 做实际本地构建和运行验证。

## 完整覆盖的定义
建立版本绑定的机器可读 capability catalog 和 `native/coverage.md`。
1. 从所有非硬件 CLI 命令枚举真实参数、输入输出、密钥类型和操作，不把硬件/help/version当算法。
2. 对照公开 C API 补充 CLI 未覆盖的有用软件能力，明确差额；不得将 CLI 目录冒充全部 C API 覆盖。
3. 每项状态为 implemented / tested / unverified / unavailable，携带原因与证据；未知项不显示虚假成功。
4. 公开 GUI 根据目录渲染表单，支持文件、秘密参数、二进制输出、用户 ID、编码和算法参数。
5. 测试覆盖正向与负向、认证/参数/文件越界、算法已知向量、签验/加解密往返及协议成对握手。
6. 状态型 LMS/XMSS/HSS/XMSSMT 密钥签名会更新密钥：必须串行化同一密钥的操作，成功更新持久化后才交付签名；失败/崩溃策略需显式记录，未解决时不可当普通无状态签名发布。

## 工作分解与责任
- task-4 build-quality：根 pom、工具链引导、部署 scripts/ops/compose、Dockerfiles；不得修改业务模块。
- task-5 integration：native 与 engine-service；先研究 runner 与覆盖清单，按 contracts.md 实施。
- task-6 platform：platform-service，遵守项目与密钥隔离契约。
- task-7 frontend：web，遵守同源认证与类型化表单契约。
- Lead：需求/契约/计划文档、跨模块协调、读关键改动、独立验收与交付，不接手他人模块。
- 后续增加独立审查/端到端测试任务；所有成员 claim / complete，回报路径与真实命令输出。

## 阶段与依赖
1. 环境与功能清单；固定接口契约（当前阶段）。
2. 原生 runner + 管理服务 + 执行服务 + 前端并行开发。
3. 契约联调：登录→项目→上传/密钥→运行真实算法→下载→审计；修复后做跨用户负向验证。
4. 完整非硬件工具目录与测试证据闭合；PKI/状态型签名/网络协议分层测试。
5. Linux 交付配置、恢复/升级/秘密配置文档、独立审查与本机端到端验收。

## 验收门槛
- 所有 Maven 模块编译与测试通过；前端 typecheck/test/build 通过。
- 至少两个用户的越权访问测试；未登录/错误 CSRF/角色不足/文件路径越界均失败且无敏感数据泄漏。
- vault 磁盘无明文私钥与密码；错误主密钥/篡改密文正确失败；秘密不进日志、任务数据库或进程参数。
- 原生 runner 真实执行 SM3 KAT、SM2、SM4 GCM、证书及代表性 PQC；任务资源上限、取消与清理验证。
- 状态型签名持久化有明确策略和测试，不仅做表面成功。
- 网络 server/client 任务有上限和权限限制，退出后不残留监听进程。
- catalog 覆盖分母、已测试数量、残余缺口可机器核验；未完成不得宣布全覆盖。
- 日志不含凭据，私钥仅由授权下载端点返回；UI 对错误和未配置依赖如实显示。
- 硬件/OpenSSL延期明确；Docker未实际运行、缺设备等不得伪报实测。

## 变更与续接
关键决定、命令、问题与证据记录在 docs/ 和团队任务；工具链/生成数据目录不得入版本控制。续接先读本文件、contracts.md、各模块进度及团队任务板，再处理未完成项。


## 最终复审新增门槛：标准fixture不迁就上游缺陷
PKI初轮测试曾按上游错误的SCT timestamp布局签名，并手工为CRL注入固定2035的nextUpdate后称全闭环，Lead已驳回该结论。对照RFC标准构造fixture，修复可复现的派生源构建：tls_uint64_to_bytes补写指针前移，X.509可选时间解析设sentinel并初始化CRL局部结构；原上游固定提交保持不变，补丁/原始与派生hash/manifest分离。标准SCT+篡改timestamp负测、原crlgen缺省/显式nextUpdate→crlverify必须真实通过。原生改变后重跑算法231调用及协议14项，再更新完整覆盖报告。测试只证明与错误实现自洽时不能计入标准正确性通过。
