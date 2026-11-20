# 证书聚焦简单模式收敛与默认拓扑展示独立验收报告 (task-101)

## 一、验收结论

**判定：PASS**
1. **真实浏览器核验 (browser TRUE + backend MOCK)**：
   - 使用本机真实 Google Chrome Headless 实例通过原生 Chrome DevTools Protocol (CDP) 驱动真实交互与截图（共 8 张高清截图保存在 `.tools/certificate-focused-evidence/`）；
   - 测试基于独立的本地内存 Mock 静态服务（端口 18094），未触碰运行中的 18088 预览实例、DM8 实库或用户生产 Vault；
   - 控制台 0 错误 (0 console error)，0 未捕获运行时异常 (0 uncaught exception)；`localStorage` 与 `sessionStorage` 均为完全清空状态。
2. **测试计数核验与前端生产构建**：
   - **用例计数净变动核实 (-3)**：由 134 调整为 131，确认仅移除了被收敛去除的首页非核心算法表单用例（5 项）；而新增了简单模式 4 导航过滤、高级模式 9 导航恢复、非核心页面回退保护及项目切换重置 keysSubTab 等关键路由断言（2 项）；
   - **核心安全与拓扑覆盖无任何回退**：`CertificateTree.vue` 13 项（同名 CA 区分、多级后代、下载保护、防环、筛选）、`CertificateWizard.vue` 29 项（4 Profile、真实 CA 候选、无 CA 引导、私钥隔离）及高级模式全流程 100% 完整保留；
   - **前端全套校验**：Vitest 9 个套件 **131/131 单元测试全部通过**（exit 0）；`vue-tsc --noEmit` **0 错误**（exit 0）；`vite build` 顺利打包生成最新生产静态资源（exit 0）。

---

## 二、逐项验收标准对照 (Acceptance Criteria)

### 1. 简单模式导航与首页功能精准收敛 (PASS)
- **侧边栏导航过滤**：简单模式下仅呈现 4 个核心导航项：`["工作台", "密钥库", "任务历史", "项目与成员"]`；算法工具、证书工具、协议任务、审计日志、用户管理被彻底收敛，无额外新增导航或重命名；
- **首页卡片收敛**：`SimpleWorkbench.vue` 沿用既有布局样式，仅保留首屏居中“制作国密 / X.509 证书”主任务大卡片，以及网格中的“制作证书”和“我的材料库”2 张核心卡片；彻底移除了通用算法卡片与底部收纳抽屉；
- **截图证据**：`.tools/certificate-focused-evidence/01_desktop_simple_mode_cert_focused.png`。

### 2. 证书向导 4 核心 Profile 与无 CA 引导完整保留 (PASS)
- 点击首屏“开始制作证书 ↗”主按钮，直接一步唤起证书向导；
- 简单模式向导内精准呈现 4 张通俗大卡（`单证自签名证书`、`自签名根 CA 证书`、`证书签名请求 (CSR)`、`快速签发服务证书`）；
- `QUICK_ISSUE` 全自动串联私钥、CSR 与 CA 签署，隐藏 CSR 输入框；无可用 CA 时保留“创建根 CA”直接切换通道；
- **截图证据**：`.tools/certificate-focused-evidence/02_simple_cert_wizard_4_cards.png`。

### 3. 密钥库默认呈现 CA 拓扑树与防环机制 (PASS)
- 进入“密钥库”页面，`keysSubTab` 声明默认为 `'tree'`，直接渲染展示“证书库 (按 CA 分组)”拓扑树；
- 允许用户手动点击“全部材料与密钥”切换至扁平表格视图；切换项目（`watch(projectId)`）时，`keysSubTab` 自动重置回 `'tree'`；
- **截图证据**：
  * `.tools/certificate-focused-evidence/03_default_keys_tree_tab.png`（默认直接展示证书树）
  * `.tools/certificate-focused-evidence/04_manual_all_materials_tab.png`（手动切换全部材料）
  * `.tools/certificate-focused-evidence/05_project_switch_resets_to_tree.png`（项目切换自动重置为证书树）。

### 4. 高级模式完整性与非核心页面回退保护 (PASS)
- 切换至“高级模式”后，侧边栏完整展现全部 9 个导航项（基于管理员/经理权限），80+ 底层工具、原始参数抽屉、全量表单完全保留；
- **回退保护实测**：在高级模式下访问非核心页面（如“证书工具”），点击切换回“简单模式”时，`App.vue` 的 watch 机制自动将当前页面重置为“工作台 (dashboard)”，严防非核心内容在简单模式下泄漏；
- **截图证据**：
  * `.tools/certificate-focused-evidence/06_advanced_mode_full_navigation.png`（高级模式 9 导航完整）
  * `.tools/certificate-focused-evidence/07_fallback_to_dashboard_on_simple_switch.png`（切回简单模式自动安全重置为工作台）。

### 5. 移动端流式自适应 (PASS)
- 模拟 375x667 移动端视口；简单工作台与证书向导自适应单列流式排布，卡片按钮与层级清晰；
- **截图证据**：`.tools/certificate-focused-evidence/08_mobile_simple_workbench.png`。

---

## 三、证据归档清单

1. **测试驱动脚本**：`.tools/certificate-focused-evidence/test-browser-focused-simple.mjs`（本地回环端口 18094）。
2. **驱动引擎**：Google Chrome Headless (CDP)。
3. **真实截图清单 (`.tools/certificate-focused-evidence/`)**：
   - `01_desktop_simple_mode_cert_focused.png`
   - `02_simple_cert_wizard_4_cards.png`
   - `03_default_keys_tree_tab.png`
   - `04_manual_all_materials_tab.png`
   - `05_project_switch_resets_to_tree.png`
   - `06_advanced_mode_full_navigation.png`
   - `07_fallback_to_dashboard_on_simple_switch.png`
   - `08_mobile_simple_workbench.png`
4. **测试摘要**：`.tools/certificate-focused-evidence/browser-summary.json`。

---

## 四、真实环境与边界声明

- 本次验收严格在隔离的本地 Mock 环境执行，未触碰运行中的 18088 预览实例；未对达梦 DM8 数据库与用户 Vault 执行任何操作；
- 宿主机当前无运行中的 Docker 守护进程，容器实机启动标记为 `DOCKER_NOT_RUN`。
