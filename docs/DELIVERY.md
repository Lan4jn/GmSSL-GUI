# 首版交付说明

## 快捷流程与双引擎生成增量

新操作入口与步骤见 [快捷操作指南](QUICKSTART-WORKFLOWS.md)，范围见 [增量契约](UX-SIMPLIFICATION.md)，最新分层测试与运行产物身份见 [UX 验收报告](review/ux-acceptance.md)。本增量提供 GmSSL/OpenSSL 密钥生成、加密口令托管及六类证书向导；后文首版 OpenSSL 延后等表述为历史基线，增量范围优先于该历史表述。当前收尾状态以 PROGRESS.md 顶部记录为准。

## 首版交付结论与入口

项目位于 `/Users/mewcapoo/Projects/GmSSL-GUI`，采用 Java 21 / Spring Boot 微服务与 Vue 3 / TypeScript 纯浏览器架构。当前本机验收环境为 macOS，平台/引擎使用真实 GmSSL 原生执行器，数据库使用 H2 PostgreSQL 兼容模式。

浏览器试用：**http://127.0.0.1:5173/**。本次交付保持受管 web、platform:8080、engine:8081 启动；状态以 `./scripts/dev.sh status` 为准。Bootstrap 登录账号及随机密码保存在本机私有 `.env.local` / `.env.local.credentials`，此文档不复述秘密。部署后应由管理员为成员创建独立账号。

```sh
./scripts/dev.sh status
./scripts/dev.sh start       # Java 服务
./scripts/dev.sh web-start   # 浏览器开发入口
./scripts/dev.sh web-stop
./scripts/dev.sh stop        # Java 服务
```

首次重建见根目录 README、web/README.md 与 ops/README.md；依赖未安装时运行 `scripts/web-install.sh`。本机 Vite 是开发入口，Linux 服务器交付方案使用 nginx 静态前端反向代理与 Docker Compose，而非把 Vite 当生产服务。

## 已实现范围

- 80 个固定上游非硬件业务命令，以及 14 个 C API 扩展工具。涵盖 SM2/SM3/SM4/SM9、SHA/SHA3/SHAKE、AES、KDF/HMAC、ZUC、EC、后量子/哈希签名与 KEM；具体算法、模式及参数见运行时目录和 native/coverage-api.md。
- 密钥生成、软件材料加密托管、文件导入导出、受控产物晋升、临时文件首任务 CAS 绑定、终态/取消/恢复清理与周期回收。
- 证书、CSR、CRL、OCSP、SCT、CMS 与数字信封；CRL 获取使用有界 Java HTTP 与原生 CRL 解析验证。
- TLCP、TLS 1.2 / 1.3 与 QUIC 成对实验任务；监听与出站目标受精确 IP/端口策略控制。
- 内置用户/session/CSRF、系统与项目 RBAC、用户/项目/文件/任务隔离、审计、异步队列、超时、取消和执行资源限额。
- LMS/HSS/XMSS/XMSSMT 单一权威状态型密钥：仅受控生成产物晋升，禁止普通复制/原始下载与外部状态私钥导入；更新持久化成功后发布签名，故障 pending 保持隔离。
- Linux Compose、外部达梦数据库 (DM8) 适配配置、nginx 与轻量服务镜像、私有配置引导、隔离工具链和精确服务进程管理。

硬件 SDF/SKF、企业 SSO 的实际对接和 OpenSSL provider 实现依约留待后续。本次离线 SCT 独立测试中使用系统 openssl 生成对照 fixture，不代表产品已集成 OpenSSL 后端。

## 固定上游与派生修复身份

上游 commit：`24ae482701a7b124826c382fffc55c19f76d475d`（`3.3.0-dev.1183`）。原始 checkout 未修改；`native/apply-overlays.py` 严格校验源哈希与唯一替换锚点，在构建目录生成派生源、清单及 diff：

1. TLS uint64 序列化补齐写指针前移，修复 SCT timestamp 覆写。
2. X.509 可选时间解析设置缺省 sentinel。
3. CRL 局部结构初始化，消除缺省 nextUpdate 的未初始化状态。
4. SCT 库 LogID 改为 SHA256(DER SubjectPublicKeyInfo)。
5. SCT CLI 同步 LogID 的标准计算。

本机 runner SHA-256：`36a05a0dc780f798677409d36c59c6645ca8aa3242ac44970906c50dccce2b07`。

补丁 manifest SHA-256：`a9067efe6bcbf0d4f14f968e56badbb49f6fc9f60fc9c1e39d7714637d4aca7c`。文件位于 `native/.build/generated/overlays-manifest.json` / `overlays.diff`，运行时 catalog 提供补丁身份。不同平台重建的二进制哈希自然会变化，不能照抄本机 runner 哈希作为跨平台产物预期。

## 验证结果与证据

| 层次 | 实测结果 | 证据 |
|---|---|---|
| Java 全工程 verify | engine 11 + platform 10，全部通过 | `.tools/logs/lead-release-java-verify.log` |
| 前端 | 30 单测、类型检查、生产 build 通过 | `.tools/logs/lead-web-verify.log` |
| 真实 Chrome | 登录→项目→SM3 abc 标准摘要结果通过 | `.tools/logs/lead-browser-smoke-final.log`、`web/tests/artifacts/` |
| 基础/非对称/PQC | 30 复合测试，直接观测 51 个原生工具；含 SM2/SM9 完整双方交换 | `.tools/logs/lead-toolbox-runner.log`、`tests/toolbox/results/` |
| 协议 | 14 测试，覆盖 8 个 server/client 工具 | `tests/toolbox/protocol-results/latest.json` |
| PKI/CMS | 25 条通过记录，覆盖 21 个工具 | `tests/toolbox/pki-results/latest.json` |
| C API 扩展 | 14 工具、231 次调用通过 | `.tools/logs/lead-release-extensions.log` |
| 标准 SCT/CRL overlay | P256/SHA256 SCT、timestamp/LogID 篡改负测、两类 crlgen→verify 共 5 组通过 | `.tools/logs/lead-native-overlays.log` |
| HTTP 多用户与生命周期 | 21 PASS / 0 FAIL / 1 SKIP；skip 为单独重启验证 | `tests/e2e/results/e2e_da8dcd9d89/report.json` |
| 原生 runner 协议 | 14 PASS | `tests/e2e/results/native_089e9379fe/report.json` |
| 状态型故障恢复 | 3 PASS | `tests/e2e/results/restart_18958922c3/report.json` |

51 + 8 + 21 = 80 个原生业务命令的操作覆盖；加上 14 个扩展工具为 94 个目录入口。这是已声明工作流与有限用例覆盖，不是每项 C API、每个算法参数组合、每条协议路径或全库正确性证明。原始上游初次 CTest 106/106 与应用测试分开统计，不混算。

完整矩阵与审查见 `docs/review/tool-coverage.md`、`protocol-coverage.md`、`pki-coverage.md`、`final-review-report.md`；API/DTO/密钥与网络规则见 `docs/contracts.md`。

## 明确的验证边界

- 当前环境没有 Docker CLI，**Linux 容器、外部达梦 DM8 真实库与生产 HTTPS/网络接入尚未实测**；Compose/镜像和运维说明已交付，正式上线前须在目标 Linux 环境执行 ops/ACCEPTANCE.md。
- QUIC 来自固定上游的实验性子集，不等于成熟的国密 QUIC/完整生产 HTTP/3 多流栈；现有证据只覆盖文档声明的实验握手与响应。
- ASan/UBSan 证据仅覆盖扩展 adapter 的插桩构建，上游静态库未全量插桩；不宣称全库零内存错误或长期 fuzz 已完成。
- 状态型重启测试是受控软件故障标记恢复验证，不是物理断电证明；密钥恢复不应通过清除 pending 或覆盖旧备份绕过单一权威规则。
- 软件算法支持不意味着一般 RSA 私钥操作存在于此 GmSSL 基线，也不意味着 PEM/DER/raw 之间的任意转换均已接入。未暴露 API 管理细节列于 native/coverage-api.md。

未创建 Git commit，未执行 push。许可证和派生修改声明随上游及本项目文件保留。