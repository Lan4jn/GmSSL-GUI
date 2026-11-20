# 公开 CSR 与证书内容匹配双向引用独立验收报告 (task-106)

## 一、验收结论

**判定：PASS**
1. **真实浏览器核验 (browser TRUE + backend MOCK)**：
   - 使用本机真实 Google Chrome Headless 实例通过原生 Chrome DevTools Protocol (CDP) 驱动真实交互与截图（共 4 张截图存入 `.tools/csr-certificate-link-evidence/`）；
   - 测试基于独立的本地内存 Mock 静态服务（端口 18092），未触碰运行中的 18088 预览实例、DM8 实库或用户生产 Vault；
   - 控制台 0 错误 (0 console error)，0 未捕获运行时异常 (0 uncaught exception)；`localStorage` 与 `sessionStorage` 均为完全清空状态。
2. **全量自动化测试套件回归**：
   - **后端全工程**：Maven 全工程 `clean package` **109/109 单元测试全部通过**（engine-service: 29, platform-service: 80，exit 0），最新平台服务 JAR 大小为 `27,003,127` 字节；
   - **前端套件**：Vitest 9 个套件 **134/134 单元测试全部通过**（exit 0）；`vue-tsc --noEmit` **0 错误**（exit 0）；`vite build` 顺利打包最新 `dist/`（exit 0）；
   - **部署套件**：`tests/deployment` **44/44 项测试全部通过**（exit 0）。

---

## 二、逐项验收标准对照 (Acceptance Criteria)

### 1. 真实 SPKI 内存索引与公钥双向匹配 (PASS)
- **非文件名/主体猜测**：`CertificateTreeService.java:397-463` 基于从 X.509 证书与 PKCS#10 CSR 中真实解析提取的 `spkiDer` 进行 SHA-256 哈希比对（`spkiFingerprint`），完全杜绝仅按 CN、文件名或创建时间盲目匹配；
- **主体比对与证据标签**：
  * 当公钥一致且主体 DER 完全一致时，标记为 `KEY_AND_SUBJECT_MATCH`（界面展示“公钥与主体一致”，不宣称 SAN 全一致）；
  * 当公钥一致但主体 DER 不一致时，保守标记为 `KEY_MATCH_DIFFERENT_SUBJECT`（界面展示“公钥一致 (主体不同)”）；
  * 仅代表公开内容与公钥匹配证据，不伪称原始签发血缘（issuedFrom）；
- **CSR 自验签防呆**：`CertificateTreeService.java:484-510` 调用引擎 `sm2verify` 针对 CSR 的 `criDer` 与 `signature` 执行真实公钥验签，验签失败的损坏/伪造 CSR 标记为 `INVALID_CSR`，严禁合法关联任何证书。

### 2. 多对多关联与歧义标记精准性 (PASS)
- **同 Key 多 CSR / 多证书多对多完整映射**：
  * 当同公钥存在多份 CSR 对应 1 张证书时，`ambiguous=true`，界面精准呈现**“多份材料匹配（非唯一来源）”**，避免误报“多证书”；
  * 当 1 份 CSR 对应多张证书时，界面精准呈现**“多张证书匹配（非唯一来源）”**；
  * 未找到匹配证书的孤立 CSR 标记为 `UNMATCHED`（“未找到匹配证书”，不臆断为确定待签发）。

### 3. 证书节点关联展示与直接下载 (PASS)
- 根 CA、中间 CA、CA 签发终端证书、自签服务证书及外部孤立证书卡片均支持展示关联 CSR 徽标与药丸标签；
- CSR 标签展示真实文件名（而非内部 UUID），配备下载按钮通过真实文件引用（`/files/{fileId}/download`）直接下载；
- 截图证据：`.tools/csr-certificate-link-evidence/01_tree_with_linked_csrs.png`。

### 4. CSR 独立分组与反向精确定位 (PASS)
- 独立 CSR 列表区完整展现 7+ 类 CSR 节点（公钥主体一致、公钥一致主体不同、多材料匹配、未匹配、签名无效等）；
- **反向联动定位实测**：在存在类别过滤隐藏目标证书的状态下，点击 CSR 卡片上的“定位”按钮：
  * 自动清空冲突过滤项（恢复为 ALL）；
  * 自动递归展开目标证书所属的全部 CA 祖先分支（带 visited 防环保护）；
  * 页面平滑滚动并对目标证书卡片应用高亮呼吸光晕 (`.highlight-pulse`)；
- 截图证据：
  * `.tools/csr-certificate-link-evidence/02_csr_section_bidirectional_links.png` (CSR 分组展示)
  * `.tools/csr-certificate-link-evidence/03_reverse_locate_expanded_and_highlighted.png` (反向定位展开与高亮)。

### 5. Bundle-Only 证书保护与只读性能 (PASS)
- Bundle 链内证书（无独立单文件）可正常双向关联 CSR，逻辑 ID 与真实文件下载引用严格分离，点击下载给出明确合辑提示，绝不伪造单证下载链接；
- 查询接口纯基于内存有界 LRU 缓存与项目快照计算，测试验证连续 **100 次 GET 查询产生 0 条数据库 jobs 插入**，不残留引擎临时工作目录。

### 6. 移动端流式自适应 (PASS)
- 模拟 375x667 移动端视口；
- 证书卡片内关联 CSR 药丸与独立 CSR 分组自适应单列流式排布，定位按钮与状态徽标排版规整，触摸可达良好；
- 截图证据：`.tools/csr-certificate-link-evidence/04_mobile_csr_tree_responsive.png`。

---

## 三、证据归档清单

1. **测试驱动脚本**：`.tools/csr-certificate-link-evidence/test-browser-csr-link.mjs`（独立本地回环端口 18092）。
2. **驱动引擎**：Google Chrome Headless (CDP)。
3. **真实截图清单 (`.tools/csr-certificate-link-evidence/`)**：
   - `01_tree_with_linked_csrs.png`
   - `02_csr_section_bidirectional_links.png`
   - `03_reverse_locate_expanded_and_highlighted.png`
   - `04_mobile_csr_tree_responsive.png`
4. **执行摘要日志**：`.tools/csr-certificate-link-evidence/browser-summary.json`。

---

## 四、真实环境与边界声明

- 本次验收严格在隔离的本地 Mock 环境执行，未触碰运行中的 18088 预览实例；未对达梦 DM8 数据库与用户 Vault 执行任何操作；
- 宿主机当前无运行中的 Docker 守护进程，容器实机启动标记为 `DOCKER_NOT_RUN`；
- 待发布的 0.1.4 归档为文档修正版，不包含本次 CSR 关联功能；本次双向关联功能将统一纳入后续 0.1.5 版本发布。
