# UX 简化与双引擎独立验收报告（task-26）

## 最终结论

**签署通过（PASS）。** 本报告记录基于最新工件身份（catalog `06cc62fb...`、runner `6667c90c...`、engine JAR `bfc0809a...`）的全量独立执行与回归验收结果。旧历史故障日志已完整保留在 `.tools/logs/` 用于回溯审计。

所有核心组件、双引擎执行闭环、SM9 4 阶段握手、协议双进程握手（TLCP/TLS 1.2/TLS 1.3/QUIC）、UX 简化向导、真实 Chrome 浏览器流程及 RBAC 安全边界均真实实跑通过。

---

## 本轮全量测试执行与日志矩阵

主要测试与执行日志归档于 `.tools/logs/`，真实浏览器端公开产物与验证证据归档于 `web/tests/artifacts/`。

| 层级 / 领域 | 数量 / 范围 | 命令 / 入口 | 本轮实际观察 | 归档日志与产物 |
|---|---|---|---|---|
| **Java Regression** | **71 项** (engine 29, platform 42) | `./scripts/mvn.sh -pl engine-service,platform-service test` | 71/71 全部通过，0 failures, 0 errors, 0 skips (engine: SanTest 8 + KeyGenService 10 + ExecService 11 = 29; platform: PlatformIntegration 8 + KeyGenIntegration 14 + CredentialValidation 2 + CertWorkflow 12 + KeyGenBudget 3 + EngineTransport 3 = 42) | `.tools/logs/lead-ux-java-final.log` / `.tools/logs/task26-java-package-final.log` |
| **Web Unit Tests** | **106 项** (7 个测试文件) | `npm --prefix web test -- --run` | 106/106 全部通过，覆盖 components, forms, wizard, artifacts, key-generator, api, app | `.tools/logs/task26-web-tests-final.log` |
| **Web Production Build** | **全模块构建** | `npm --prefix web run build` | vue-tsc 类型检查无误，Vite 打包产出 dist/ 生产静态资源 | `.tools/logs/task26-web-build-final.log` |
| **UX & Workflows** | **32 项** | `python3 -m unittest discover -s tests/ux -p 'test_*.py' -v` | 32/32 全部通过 (17.743s)，覆盖 CertificateWorkflows (9项)、DeepProbe (5项)、KeyGenMatrix (7项)、KeyGenSmoke (5项)、MetadataIntegration (6项) | `.tools/logs/task26-ux32-final.log` |
| **Core Toolbox** | **30 项** (覆盖 51 个原生工具) | `python3 -m tests.toolbox.runner` | 30/30 全部通过，SM9exch 4 阶段协商真实闭环 (`SM9exch 4-stage agreement verified: True`)，扩展 API 14 工具 231 standalone 验证全绿 | `.tools/logs/task26-toolbox-core30-final.log` / `tests/toolbox/results/runner_summary.json` |
| **Protocol Suite** | **14 项** | `python3 tests/toolbox/protocol_suite.py` | 14/14 全部通过，含网络策略3项、输入校验2项、TLCP握手2项、TLS 1.2握手2项、TLS 1.3握手2项、QUIC 1-RTT握手1项、负向边界2项 | `.tools/logs/task26-protocol-suite-final.log` / `tests/toolbox/protocol-results/latest.json` |
| **PKI Suite** | **10 项用例 (25 条记录)** | `python3 tests/toolbox/pki_suite.py` | 10/10 全部通过，覆盖根CA、CSR生命周期、证书验证正负例、CRL注销、CRL HTTP获取、OCSP签名校验、OCSP HTTP获取、SCT验证、CMS签名、CMS加密 | `.tools/logs/task26-pki-final.log` / `tests/toolbox/pki-results/latest.json` |
| **Native Extensions** | **231 调用 (14 工具)** | `python3 native/extension-tests.py --binary native/.build/bin/gmssl-runner --runner` | 231 invocation PASS、14 commands，全量协议帧直接驱动二进制 runner，无硬编码绕过 | `.tools/logs/task26-native-extensions-python312.log` |
| **Native Certificate SAN** | **11 分组 (FULL SAN)** | `OPENSSL=/opt/homebrew/bin/openssl python3 native/test-certificate-san.py` | 11 PASS 分组：真实 DER 扩展编码、DNS/IP SAN 解析校验、重复扩展与越权篡改拒绝 | `.tools/logs/task26-native-san-final.log` |
| **Native Overlays** | **5 项** | `python3 native/test-overlays.py` | 5/5 全部通过：SCT 签名及 2 种篡改正负向用例、CRL 2 种 next_update 校验 | `.tools/logs/task26-native-overlays.log` |
| **Native Frames** | **4 项** | `python3 native/test-frames.py` | 4/4 全部通过：GMRUN001 协议帧打包、多参数字节对齐、标准错误流分离校验 | `.tools/logs/task26-native-frames.log` |
| **Deployment Tooling** | **5 项** | `python3 ops/test-tooling.py` | 5/5 全部通过：环境引导校验、Docker 依赖注入、OpenSSL 路径隔离验证 | `.tools/logs/task26-ops-green.log` |
| **Real Chrome E2E** | **11 步骤全链路** | `node web/tests/browser-ux-workflows.mjs` | 11 步全部通过 (timestamp: 2026-10-18T02:11:31.383Z, mode: `dns-ip-csr-chain`)：涵盖 SM4 托管加密、SM2 托管签名、SM2 临时文件签名、SM2 公钥托管/临时存储、Vault ZUC256 / P-384、GmSSL / OpenSSL 双向导 (DNS+双IP SAN)、CSR→CA 链式签发、privacy/errors 验证 | `web/tests/artifacts/ux-workflows/summary.json` / `.tools/logs/task26-chrome-ux.log` |
| **Form Metadata & Rules** | **94 工具 / 759 参数结构子集** | `python3 native/test-form-metadata.py` | 结构与默认规则检查（非所有可能组合穷举）：零静态 IV/nonce、高级折叠项无必填字段、凭据自动绑定、下拉枚举合法性校验全绿 | 控制台直接校验 |

---

## 最终生效工件身份与指纹清单（Artifact Manifest）

当前部署与验收所依据的核心工件严格锁定如下 SHA-256 哈希及文件尺寸，完整元数据已写入 `.tools/logs/task26-current-artifacts.json`：

| 工件路径 | SHA-256 Checksum | 大小 (bytes) | 状态与说明 |
|---|---|---|---|
| `native/.build/bin/gmssl-runner` | `6667c90caadde47be15aa1bfbb48f6016c4ca537de5a6d67d5b8361f575c2cc8` | 1,962,080 | 最新编译原生二进制执行器 |
| `native/catalog.json` | `06cc62fb840f0b97786ee3459d7d7fd3d72b1139ef4e2f4b1d620447f978bcd4` | 289,967 | 规范化 QUIC prime256v1 与 SM9exch 修复后的基准目录 |
| `native/extensions-catalog.json` | `fddfb388f9344392366e18a1b3dc4e33ce6ba0c0a2fb943b9d6273fb510477cb` | 44,587 | 扩展算法能力目录 |
| `native/form-metadata.json` | `6d320a29f9fb8971ae7ac648c6c713ef3c0a355efa6d4a76ef50a4347c0ba00a` | 363,770 | 前端表单多语言与校验元数据 |
| `engine-service/target/engine-service-0.1.0-SNAPSHOT.jar` | `bfc0809ae5af88541a6ffc9ee07c0e14d4e52bdde27c36e1d1046dde05be3950` | 23,773,048 | 运行中 Engine JAR，内嵌 catalog 经验证逐字节匹配 |
| `platform-service/target/platform-service-0.1.0-SNAPSHOT.jar` | `0ced6020a92d040dfc5eba94211be80438e2734fd3dc3c1d250d7d382e41edd9` | 26,991,298 | 运行中 Platform JAR，正常代理 Engine catalog |

### 内嵌资源逐字节一致性核验（JAR Internal Match）
对当前运行的 `engine-service-0.1.0-SNAPSHOT.jar` 内部 `BOOT-INF/classes/` 提取哈希核验：
- `BOOT-INF/classes/catalog.json`: `06cc62fb840f0b97786ee3459d7d7fd3d72b1139ef4e2f4b1d620447f978bcd4` （与本地 `native/catalog.json` 100% 逐字节一致，大小 289,967 bytes）
- `BOOT-INF/classes/extensions-catalog.json`: `fddfb388f9344392366e18a1b3dc4e33ce6ba0c0a2fb943b9d6273fb510477cb` （与本地 `native/extensions-catalog.json` 100% 逐字节一致，大小 44,587 bytes）
- `platform-service` 架构设计上不内嵌本地 catalog 资源，通过 EngineTransport HTTP 接口动态代理 engine-service 的 `/api/v1/tools` catalog，保持单一真实数据源。

---

## 活跃受管服务状态（Live PIDs）

本地测试服务由 `scripts/dev.sh` 统一守护与生命周期管理，当前存活进程及监听端口实测如下：

- **engine-service**: Managed PID **71951** (监听端口 `127.0.0.1:8081`)
  - 双引擎能力状态: GmSSL native runner + OpenSSL dual-engine active
- **platform-service**: Managed PID **71987** (监听端口 `127.0.0.1:8080`)
  - 数据库与凭据状态: H2 文件数据库正常、Flyway v6 迁移就绪、Vault 主密钥与 Material 事务行锁正常生效
- **web (Vite Dev Server)**: Managed PID **69212** (监听端口 `http://127.0.0.1:5173/` 及 `http://[::1]:5173/`)

---

## 历史缺陷修复记录（已闭环审计，单列留存非当前 pending）

本节记录此前在持续集成与多智能体开发过程中发现并已成功闭环的缺陷，相关重现日志与对比日志均完整保留在 `.tools/logs/`：

1. **SM9 密钥协商 stage=init 参数阻断 (HTTP 400)**:
   - **历史问题**: `native/catalog.json` 将 `sm9exch` 的 `key` 与 `id` 错误标记为 `required: true`，导致 Initiator 发起 `stage="init"` 时被 `EngineValidator.java` 拦截报错 `INVALID_PARAMETERS` (400)，Response Hash 记录为 `f621ca9d...`。
   - **修复与证据**: `generate-catalog.py` 将 `sm9exch` 纳入 alternatives 条件校验，使 `key`, `id`, `peer_id` 在元数据中为全局可选，仅保留 `stage` 必填；同时移除 `sm9` 身份标识的硬编码默认值。经 Lead 验证 (`.tools/logs/lead-sm9-stage-red.log`, `lead-sm9-stage-green.log`) 并重新打包部署后，`TestAsymSuite.test_05_sm9exch_execution` 顺利完成 4 阶段协议协商，输出 `SM9exch 4-stage agreement verified: True`。
2. **QUIC 协议握手 supported_group 曲线名称不一致 (HTTP 400)**:
   - **历史问题**: `protocol_suite.py` 发送 `supported_group="prime256v1"`，而 catalog 中仅列出 `"secp256r1"`，触发枚举校验失败；经源码核验 GmSSL 底层 `src/ec.c` 标准曲线表仅声明 `"prime256v1"`，原生命令直接传入 `"secp256r1"` 时报错退出。
   - **修复与证据**: 将 catalog 中 `quic_server` 与 `quic_client` 的 `supported_group` 规范化为默认且唯一选项 `prime256v1`，TLS 1.2/1.3 曲线组保留 `sm2p256v1` 与 `prime256v1`。经 Lead 验证 (`.tools/logs/lead-quic-group-red.log`, `lead-quic-group-green.log`)，重新运行后 `PROTO-QUIC-01` 双进程握手返回 exit 0 且客户端成功捕获 `"hello from gmssl quic server"`，协议套件达到 14/14 全绿。
3. **测试并发跨文件登录触发速率限制 (HTTP 429)**:
   - **历史问题**: `Auth.java` 限制单 IP 每 60 秒最多 10 次登录；跨测试文件连续无延迟运行多轮测试时瞬时登录累积触发 HTTP 429。
   - **修复与证据**: 确认这是安全保护机制生效而非业务逻辑缺陷。在真实 60 秒时间窗口重置后重新串行执行完整的 32 项 UX 自动化用例（`.tools/logs/task26-ux32-final.log`），32/32 全量通过（0 failures, 0 errors），无需削弱生产限流策略亦无需删除任何测试用例。

---

## 验收审计边界与局限性声明

为保证验收的客观性与诚实性，明确记录本轮验收的环境边界与技术局限性，绝不夸大测试范围：

1. **宿主环境与 macOS 实测边界**:
   - 本轮全部测试均在 macOS (aarch64, Darwin 25.4.0) 真实宿主环境下实跑完成。
   - 原生二进制文件 `native/.build/bin/gmssl-runner` 是在 macOS aarch64 架构下构建的 Mach-O 64-bit 可执行文件。
2. **Docker 容器化验证边界**:
   - 宿主机当前未运行 Docker 守护进程，因此**未进行**真实的 Docker 镜像构建、容器启动以及容器网络端到端握手。
   - 运维修复的验证方式为：在隔离的临时目录中，严格模拟 Dockerfile 的多阶段 COPY 流程（`COPY native/catalog.json native/extensions-catalog.json native/`）并执行 Maven package，确认离线打包通过且 JAR 内嵌资源指纹完全匹配（详见 `.tools/logs/task26-docker-java-evidence.json` 与 `task26-docker-java-package.log`）。
3. **94 工具参数元数据非穷举声明**:
   - `form-metadata.json` 针对 94 个工具、759 个参数进行了核心跨参数结构与默认规则检查（零全零静态 IV/Nonce、高级折叠项无必填字段、凭据自动绑定、下拉枚举合法性），覆盖高频典型输入，但属于 Java 跨参结构子集检查，并非对所有可能命令行组合的数学穷举。
4. **PQC 算法与证书测试边界声明**:
   - PQC 算法（LMS, HSS, XMSS, XMSSMT, SPHINCS+, Kyber）在本轮已完成普通密钥生成、签名/验签及封装/解封的基准 suite 实跑（详见 Core Toolbox 30 项测试）。
   - 但是，PQC 普通签名 suite 实跑并不等同于 PQC 证书所有 `sig_alg` 与复杂扩展组合的端到端通过；PQC 混合证书链、PQC X.509 v3 复杂扩展组合及与双证书协议（如 TLCP 双证体系）的高级交叉组合未包含在本次验收范围内。
5. **持久化事务与 Vault 孤儿补偿边界**:
   - 新增 generation 创建材料 + 凭据操作在同一 DB 事务中执行，已验证 public/credential 故障补偿逻辑。
   - 由于 Java `String` 类型的不可变性与 GC 机制，内存中的明文不能保证 100% 零化擦除。
   - 当 Vault 磁盘写入或清理失败时，系统可能遗留 AES 密文临时文件待后续孤儿回收扫描（Orphan GC），清理失败记录固定诊断码 `KEYGEN_VAULT_CLEANUP_FAILED`，持久化失败返回 `KEY_PERSISTENCE_ERROR`；系统不宣称在任意 crash、底层 IO 掉电或 DB commit 不确定场景下具备跨系统全局 atomic。
6. **版本控制审计**:
   - 当前工作区不是 Git 仓库根目录，未进行任何未经授权的 git commit 或 git push 操作。
