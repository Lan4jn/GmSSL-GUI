# 证书 CA 分类树与签发关系可靠性独立验收报告 (task-96)

## 一、验收结论

**判定：PASS**
1. **真实浏览器核验 (browser TRUE + backend MOCK)**：
   - 使用本机真实 Google Chrome Headless 实例通过原生 Chrome DevTools Protocol (CDP) 驱动真实交互与截图（共 7 张截图保存在 `.tools/ca-classification-evidence/`）；
   - 伺服最新 `web/dist` 静态资源，测试进程（PID 97732）与临时回环端口 (18096) 均已干净清理；
   - 未连接生产运行中 18088 预览实例、DM8 实库或用户生产 Vault；
   - 控制台 0 错误 (0 console error)，0 未捕获异常 (0 uncaught exception)；`localStorage` 与 `sessionStorage` 均为完全清空状态。
2. **全量自动化测试套件回归**：
   - **前端套件**：Vitest 9 个套件 **134/134 单元测试全部通过**（exit 0）；`vue-tsc --noEmit` 0 错误；`vite build` 成功打包最新生产 `dist/`；
   - **后端套件**：Maven 全工程 `clean package` **104/104 单元测试全部通过**（engine-service: 29, platform-service: 75，exit 0），最新平台 JAR 大小为 `26,999,329` 字节；
   - **部署套件**：`tests/deployment` **39/39 项测试全部通过**（exit 0）。

---

## 二、逐项验收标准对照 (Acceptance Criteria)

### 1. 材料库 Tab 切换与 CA 拓扑树展现 (PASS)
- 在“密钥库”材料管理页面，顶栏清晰提供分段开关：`[ 全部材料与密钥 ]` 与 `[ 证书库 (按 CA 分组) ]`，无刷新平滑切换；
- 根 CA 与下属证书采用多层折叠树（Root CA -> Intermediate CA -> Leaf Cert）结构展示；
- 根节点条目展示 CN、文件名、序列号、到期时间、状态徽标与“已签发 X 张证书”指示；
- **截图证据**：`.tools/ca-classification-evidence/01_desktop_certificate_tree.png`。

### 2. 签发 CA 独立下拉筛选与同名 CA 精确区分 (PASS)
- 工具栏设置独立“签发 CA”下拉控件 (`select.ca-select`)，绑定 `selectedCaId`；
- 选项以逻辑节点 ID 为值，文本格式为 `CN (文件名 · SN:短序列号)`，同名不同序列号的 Root CA 准确并列区分；
- 继承判断通过 `isDescendantOfCa` 递归比对 `parentRefs`，包含 `visited` Set 防环截断，精准限定所选 CA 及其后代，保留祖先上下文；
- **截图证据**：`.tools/ca-classification-evidence/02_filter_by_specific_ca.png`。

### 3. 多重维度组合搜索与过滤 (PASS)
- **主体 CN 搜索**：支持对 `subjectCN`、文件名、`issuerCN` 与序列号的即时过滤；
- **类型过滤**：支持“仅看根 CA”、“仅看中间 CA”、“由 CA 签发的证书”、“自签名服务证书”、“缺失上级 CA”；
- **有效期过滤**：支持“仅有效”、“已过期”、“未生效”状态筛选；
- 切换项目时，已选 CA 自动重置为 `ALL`，无跨项目状态污染；
- **截图证据**：
  * `.tools/ca-classification-evidence/03_search_cert_by_cn.png` (CN 搜索)
  * `.tools/ca-classification-evidence/04_filter_category_validity.png` (类型与过期组合过滤)。

### 4. 非树节点独立分组隔离 (PASS)
- **自签名服务证书 (`SELF_SIGNED_END_ENTITY`)**：明确标识 `ca=false` 且自签名，单独分组，禁止冒充根 CA；
- **缺失上级 CA (`ORPHAN`)**：项目中未找到有效签发者的外来证书，单独分组提示；
- **证书签名请求 (`CSR`)**：独立聚合展示，并提供直接下载；
- **证书链合辑 (`Bundle`)**：提取各包含证书指纹，避免与单证书节点混杂重复渲染；
- **待解析与异常证书 (`UNSUPPORTED` / `ENGINE_PENDING`)**：独立区域展示，标明解析异常或引擎状态；
- **截图证据**：`.tools/ca-classification-evidence/05_separate_groups_csr_orphan_bundle.png`。

### 5. 向导签署 CA 智能候选过滤 (PASS)
- 打开证书制作向导 (`CertificateWizard`) 选择 `QUICK_ISSUE` 进入签署配置：
- CA 下拉列表严格仅展示具备 `isCa=true && selectableAsIssuer=true` 的有效 CA 材料，展示 CN 与文件名；
- 历史已过期的 CA 证书在树上保留拓扑，但在向导候选列表中被**自动排除**；
- 证书链 Bundle-only 节点因无独立单文件亦被排除；无可用 CA 时保留“创建根 CA”直接切换通道；
- **截图证据**：`.tools/ca-classification-evidence/06_wizard_ca_select_candidates.png`。

### 6. 移动端流式自适应 (PASS)
- 模拟 375x667 移动端视口；
- 证书树工具栏控件流式换行，CA 卡片与子节点层次清晰，文本截断与展开图标排布正常；
- **截图证据**：`.tools/ca-classification-evidence/07_mobile_certificate_tree.png`。

### 7. 后端验签真实性与只读有界缓存 (PASS)
- **真实验签与吊销边界**：`CertificateTreeService` 通过 `Engine.request("POST", "/executions")` 调度原生 `sm2verify`，使用真实公钥对 TBS 与签名执行验签；签发树仅确证本地公钥验签与 BasicConstraints 关系，未引入外部 CRL/OCSP，不宣称完整在线吊销状态，吊销状态明确标为 `UNCHECKED`；
- **杜绝 Job 风暴**：解析与验签结果受项目快照 LRU 内存缓存保护，测试验证连续 **100 次** GET /certificates 查询产生 **0 条数据库 jobs 插入** (jobsBefore == jobsAfter)，不生成临时持久工件；
- **权限与项目隔离**：`GET /api/v1/projects/{pid}/certificates` 受 `auth.project(r, pid, 1)` 严格保护；未登录请求返回 401。

---

## 三、真实环境与边界声明

1. **Docker 守护进程**：当前开发宿主机无运行中的 Docker daemon，实机容器启动状态标记为 `DOCKER_NOT_RUN`；
2. **测试数据隔离**：本次浏览器测试完全基于独立内存 Mock 伺服（18096 端口），未触碰运行中的 18088 达梦预览服务、外部 DM8 实库或用户生产 Vault。
