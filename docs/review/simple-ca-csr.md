# 简单模式 CA 与 CSR 完整入口独立验收报告 (task-84)

## 一、验收结论

**判定：PASS**
- **浏览器执行真实性 (browser TRUE)**：使用本机真实 Google Chrome Headless 实例通过原生 Chrome DevTools Protocol (CDP) 驱动真实交互，完成 4 卡向导、无 CA 警告引导、直接切换根 CA、独立 CSR 请求及高级模式 7 卡保留等全链路核验，杜绝 JSDOM 伪造。
- **服务端契约说明 (backend MOCK)**：使用独立的静态服务进程与 Mock 夹具伺服 `web/dist`，未连接运行中的 18088 预览实例，未连接生产 DM8 达梦实库，未读取或修改用户生产 Vault 或私钥材料。
- **全量前端测试与构建**：Vitest 8 个测试套件，**119/119 项测试全部通过**（exit 0）；TypeScript 严格类型检查 `vue-tsc --noEmit` **0 错误**（exit 0）；`vite build` 顺利打包最新 `dist`（exit 0）。
- **控制台与运行时状态**：控制台 0 错误 (0 console error)，0 未捕获运行时异常 (0 uncaught exception)。
- **安全存储审计**：`localStorage` 与 `sessionStorage` 均为完全清空状态 (`{"localStorage":[],"sessionStorage":[]}`)，零私钥、零凭据泄露。

---

## 二、逐项验收标准对照 (Acceptance Criteria)

### 1. 简单模式 4 张核心卡片精准过滤 (PASS)
- 点击首屏“开始制作证书”主卡片按钮，直接一步进入向导界面；
- `CertificateWizard.vue` 计算属性 `availableProfiles` 在 `simpleMode=true` 下**严格仅展示 4 张核心卡片**：
  1. `SELF_SIGNED`：单证自签名服务证书（单证直签）；
  2. `ROOT_CA`：自签名根 CA 证书（信任根）；
  3. `CSR`：证书签名请求 (CSR)（请求文件，用于提交外部机构签发）；
  4. `QUICK_ISSUE`：快速签发服务证书（已有 CA 一键签发）。
- 中间 CA (`INTERMEDIATE_CA`)、旧 CA 签发 (`CA_SIGN`) 与 TLCP 国密双证书 (`TLCP`) 等专业卡片被彻底排除。
- **截图证据**：`.tools/simple-ca-csr-evidence/01_simple_cert_wizard_4_cards.png`。

### 2. QUICK_ISSUE 缺少 CA 时的友好引导与直接切换 (PASS)
- 选定 `QUICK_ISSUE` 且当前项目暂无可用 CA 证书时，步骤 3（签署机构）展示明确警告：
  * 文案：`当前项目中暂无可用 CA 证书。请先创建根 CA 证书或自签服务证书，切勿自动创建根 CA 破坏权威。`；
  * 提供直接操作按钮：`创建根 CA` (`.btn-create-root-ca`)；
- **点击“创建根 CA”按钮触发 `switchToRootCa`**：直接将 profile 无缝切换至 `ROOT_CA`，并重置至步骤 1，允许用户显式、受控地创建根 CA，坚决不进行破坏权威的静默 autoRoot；
- **截图证据**：
  * `.tools/simple-ca-csr-evidence/02_quick_issue_no_ca_create_root_prompt.png`（无 CA 警告与按钮）
  * `.tools/simple-ca-csr-evidence/03_create_root_ca_step.png`（点击直接切换至 ROOT_CA）

### 3. CA 创建完成与返回签发闭环交互 (PASS)
- 根 CA 创建完成后，向导成功页展示新生成的根 CA 证书与私钥，点击“完成并关闭”触发 `emit('complete')`；
- `SimpleWorkbench.vue` 捕获 `complete` 事件后调用 `emit('refresh')` 刷新当前项目材料库；
- 重新进入证书制作向导选择 `QUICK_ISSUE` 时，新生成的 CA 证书自动进入下拉候选列表，闭环完成后续签发。

### 4. 独立 CSR 流程与全自动 QUICK_ISSUE 隔离 (PASS)
- **独立 CSR 申请向导**：
  * 步骤 2 填写申请主体（CN、组织等）及 SAN（支持 DNS / IP）；
  * 步骤 3 仅需配置或自动生成申请私钥，**无任何 Issuer CA 签署机构配置项**（`hasIssuerInCsr: false`）；
  * 提交工作流参数：`profile: "CSR"`；成功后直呈 `xxx.csr` 下载按钮；
  * **截图证据**：`.tools/simple-ca-csr-evidence/04_standalone_csr_step.png`。
- **QUICK_ISSUE 全自动串联**：
  * 选定已有 CA 证书及私钥后，由后端全自动串联 `生成私钥 -> 生成 CSR -> CA 签署 -> 链封装`；
  * **界面完全不展示 CSR 上传与输入框**，无需用户手动准备 CSR。

### 5. 高级模式 7 类卡片完整保留 (PASS)
- 在顶栏切换至“高级模式”后，打开证书向导：
- 严格呈现 **7 张完整 Profile 大卡**：
  1. 单证自签名证书
  2. 自签名根 CA 证书
  3. 中间 CA 证书
  4. 证书签名请求 (CSR)
  5. CA 签发证书
  6. TLCP 国密双证书
  7. 快速签发服务证书
- 切回简单模式后，状态守卫自动剔除专业卡片，无残留状态；
- **截图证据**：`.tools/simple-ca-csr-evidence/05_advanced_mode_7_cards.png`。

### 6. 移动端流式自适应 (PASS)
- 模拟 375x667 移动端视口；
- 简单向导内 4 张核心卡片规整自适应为单列流式堆叠，各标签、按钮与图标展示完整，触摸可达良好；
- **截图证据**：`.tools/simple-ca-csr-evidence/06_mobile_4_cards_responsive.png`。

---

## 三、证据归档清单

1. **测试驱动脚本**：`.tools/simple-ca-csr-evidence/test-browser-ca-csr.mjs`（独立本地回环端口 18098）。
2. **测试驱动引擎**：Google Chrome Headless (CDP)。
3. **真实截图目录 (`.tools/simple-ca-csr-evidence/`)**：
   - `01_simple_cert_wizard_4_cards.png`
   - `02_quick_issue_no_ca_create_root_prompt.png`
   - `03_create_root_ca_step.png`
   - `04_standalone_csr_step.png`
   - `05_advanced_mode_7_cards.png`
   - `06_mobile_4_cards_responsive.png`
4. **执行摘要日志**：`.tools/simple-ca-csr-evidence/browser-summary.json`。

---

## 四、真实测试边界声明

- 本次验收严格在隔离的本地回环环境执行，未触碰或破坏正在运行中的 18088 预览实例；
- 未对生产 DM8 达梦实库进行任何数据库连接或数据读写；
- 未读取或导出任何生产 Vault 材料及用户私钥；
- 宿主机当前无运行中的 Docker daemon，容器启动标记为 `DOCKER_NOT_RUN`。
