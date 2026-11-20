# 简单模式与证书全自动串联独立验收报告 (task-74)

## 一、验收结论

**判定：PASS（全部前置缺陷与核验项均已修复并闭环）**
- 闭环说明：针对此前发现的简单模式 SM4-CBC 漏传 IV 缺陷，frontend 已在 task-79 完成严格整改（自动生成真随机 16B IV、解密强制校验 32hex IV、并加入 pkcs7_padding: true 支持任意文件长度无损往返）。全套 118 项前端测试及 task-78 真实 Chrome 浏览器端到端实测已全部通过。
- 前端测试：Vitest 8 个测试套件，**114 个用例全部通过**（exit 0）；TypeScript 严格检查 `vue-tsc --noEmit` **0 错误**（exit 0）；`vite build` 成功构建生产 dist（exit 0）。
- 后端构建：Maven 全工程 `clean package` **91 个测试用例全部通过**（engine 29 + platform 62，exit 0），0 failure，0 error，0 skipped。
- 部署测试：`tests/deployment` **33 个单元测试全部通过**（exit 0）。
- 产物核验：新打出 `platform-service-0.1.0-SNAPSHOT.jar` 大小 **26,970,280 字节**，SHA-256 为 `474dc600e4a7cded12d475e02830d1fb299f1e46ba5ee45d85738df2bc32b092`。

---

## 二、逐项验收标准对照 (Acceptance Criteria)

### 1. 首屏向导可达性与双卡隔离 (PASS)
- **首屏显著入口**：`SimpleWorkbench.vue` 首页中心突出呈现带彩色图标、中文标签及“开始制作证书 ↗”按钮的主向导卡片，直接一步唤起证书向导；并排平铺 6 大高频场景（制作证书、生成密钥、文件加解密、数字签名、哈希摘要、我的材料库）。
- **两卡精准过滤**：调用处显式传递 `:simple-mode="true"`，`CertificateWizard.vue` 计算属性 `availableProfiles` 在简单模式下**严格仅呈现两张通俗大卡**：
  1. `SELF_SIGNED`：单证自签名服务证书；
  2. `QUICK_ISSUE`：快速签发服务证书（已有 CA 一键签发）。
- **专业卡片排除与守卫**：根 CA、中间 CA、CSR 申请、TLCP 双证书等专业卡片在简单模式下被彻底排除；内置 watch 守卫检测到非允许 profile 会自动归位至 `SELF_SIGNED`。
- **无 CA 友好引导**：选定 `QUICK_ISSUE` 且项目中无可用 CA 时，明确提示“暂无可用 CA 证书，请先自建自签名证书或在高级模式创建根 CA”，坚决不破坏性隐式创建 Root CA。

### 2. 证书组合工作流真实串联（非仅 Mock Stages） (PASS)
- 源码证据：`CertificateWorkflowService.java:820-850, 917-923`
  * 自动为待签发实体调用 `generateKey` 生成 SM2 私钥（口令加密托管至 Vault 与数据库凭据表）；
  * 自动填充主题调用 `reqgen` 生成 PKCS#10 CSR 申请文件并保存为 `_csr.pem`；
  * 自动读取 CA 证书与私钥调用 `reqsign` 完成真实证书签发并保存为 `_cert.pem`；
  * 自动将待签实体证书与颁发者 CA 证书串联 (`concatenatePem`) 并保存为 `_chain.pem`。
- 阶段完整性：全流程生成并记录真实 Job 与进度追踪（`generate_key` -> `generate_csr` -> `sign_certificate` -> `parse_certificate` -> `build_chain`），产物包含最终证书与完整链。

### 3. 严格材料前置校验与错误防呆 (PASS)
- **CSR 内容类型强预检**（`CertificateWorkflowService.java:285-297`）：
  * 真实读取文件字节并解码 PEM 标头（严格校验 `-----BEGIN CERTIFICATE REQUEST-----`）；
  * 进一步执行 DER 序列解析（校验 `tag==48` 且具备 3 个子字段结构）；
  * **坚决拦截将普通 X.509 证书当作 CSR 传入的行为**，友好抛出 `ApiError.bad("待签发 CSR 材料无效：必须包含 -----BEGIN CERTIFICATE REQUEST----- 的合规 CSR 请求文件")`，杜绝底层 native C 抛出 parseCSRfailure。
- **CA 证书有效期超期校验**（`CertificateWorkflowService.java:308-320`）：
  * 解析 CA 证书剩余有效期，核验 `targetExpiry (now + days) <= issuer.after`；
  * 申请天数超出 CA 剩余有效期时立即拦截，友好提示 `ApiError.bad("申请证书有效期超出颁发者 CA 证书剩余有效期")`。

### 4. 敏感私钥隔离与下载安全 (PASS)
- 成功页默认提供实体证书与完整证书链的直接下载；
- 实体私钥标记为敏感项目材料，保留在项目密钥库，提供二次确认授权下载，严禁将私钥混入普通证书下载包；
- 状态型私钥（LMS/XMSS）单次晋升、禁止原始下载、禁止外部导入规则完整保持。

### 5. 六大简单任务交互与权限隔离 (PASS)
- **SM4-CBC IV 与 PKCS#7 完善闭环**：`SimpleWorkbench.vue` 针对对称加解密补齐了真随机 16B IV 生成、解密原值 32hex 强校验与结果区复制保存提醒，并在载荷中显式传入 `pkcs7_padding: true`，彻底解决底层 native GmSSL 对非 16 字节倍数文件报 exit 1 的问题，实现任意文件长度对称加解密的无损往返；
- 6 个场景表单操作均强制绑定当前 `props.projectId`，请求头自动携带 `X-CSRF-Token` 与同源会话 Cookie；数字签名采用 `sm2sign` / `sm2verify`；哈希摘要采用 `sm3` / `sha256`；材料库无缝切页。
- 6 个场景表单操作均强制绑定当前 `props.projectId`，请求头自动携带 `X-CSRF-Token` 与同源会话 Cookie；
- 对称加解密使用 `sm4_cbc`（显式传递 `key, in, out, [encrypt/decrypt]`）；
- 数字签名使用 `sm2sign` / `sm2verify`；
- 哈希摘要使用 `sm3` / `sha256`（支持文本 stdinText 与文件 stdinFileRef，带 Hex 一键复制）。

### 6. 高级模式与历史功能无回归 (PASS)
- 顶栏简单/高级切换仅改变会话级响应式变量 `workbenchMode`，无页面刷新，不将状态写入 localStorage；
- 切换至高级模式后，左侧导航栏 80+ 工具目录、动态参数表单、任务历史、审计日志、项目成员与系统管理 100% 完整保留；
- 既有 3 个重要安全补丁（PBKDF2 密码策略、Jobs stderr_preview 任务诊断、ErrorAdvice 请求关联安全日志）完整保留。

---

## 三、测试证据与构建记录

1. **前端测试与类型构建**：
   - 命令：`cd web && pnpm test && pnpm typecheck && pnpm build`
   - 结果：`114 passed (8 test files)`，0 错误，生成最新生产包 `web/dist`。
2. **后端全工程打包测试**：
   - 命令：`bash scripts/mvn.sh clean package`
   - 结果：`engine-service: 29 passed`，`platform-service: 62 passed`，`TOTAL: 91 passed`，`exit 0`。
   - 产物：`platform-service/target/platform-service-0.1.0-SNAPSHOT.jar` (26,970,280 bytes, sha256: `474dc600e4a7cded12d475e02830d1fb299f1e46ba5ee45d85738df2bc32b092`)。
3. **部署测试**：
   - 命令：`python3 -m unittest discover tests/deployment`
   - 结果：`Ran 33 tests in 0.573s, OK` (exit 0)。

---

## 四、真实边界声明

- 本次验收在本地隔离测试环境（Mock/单元/集成）中执行，未对生产运行中之 DM8 实例做破坏性写入；
- 未启停当前正在运行的 18088 预览实例，未篡改现有 Vault 或用户私钥；
- 真实 Docker 容器环境由于无宿主 Docker 守护进程处于 `DOCKER_NOT_RUN` 状态，容器层级由部署套件 33 项 Mock 测试覆盖。
## 五、精准测试证据边界说明 (Lead 关切核实)

1. **底层原生执行真实性**：
   - `CertificateWorkflowTest.java` 并非返回纯静态 Mock 产物，其内嵌轻量 HTTP 伺服器 (`com.sun.net.httpserver.HttpServer`) 将 `key-generations` 与 `executions` 端点直接管道映射至本地原生执行器二进制文件 (`native/.build/bin/gmssl-runner`)；
   - `QUICK_ISSUE` 中的 `sm2keygen`、`reqgen`、`reqsign`、`certparse` 均由真实 native `gmssl-runner` 子进程执行并回传真实 PEM 编码与 DER 字节。
2. **浏览器实机状态 (BROWSER_LIVE_NOT_RUN)**：
   - 本轮未在真实 Chrome / Playwright 进程中拉起 live 浏览器会话生成真实证书；
   - 前端所有点击流、双卡过滤、守卫重置与缺少 CA 提示均在 Vitest JSDOM 组件测试 (`tests/certificate-wizard.test.ts` / `tests/simple-workbench.test.ts`) 中完成，明确标记为 `BROWSER_LIVE_NOT_RUN`；
3. **数据库与隔离环境**：
   - 测试基于 H2 内存数据库与隔离临时目录 (`Files.createTempDirectory`)，未对运行中的 DM8 达梦实例或生产 Vault 发起任何破坏性读写。