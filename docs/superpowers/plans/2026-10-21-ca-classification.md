# 实施计划：证书按 CA 分类树与拓扑关系识别

依据已批准的 `docs/superpowers/specs/2026-10-21-ca-classification-design.md`，制定前后端最小协作、TDD 与防回归实施计划。

---

## 1. 架构职责分工与防回归边界

- **后端边界 (`platform-service`)**：
  * 提取独立解析器 `X509CertificateParser.java`（复用原有 `Der` 逻辑，解析 subject/issuer DER、SPKI、validity、BasicConstraints、KeyUsage）；
  * 新建 `CertificateTreeService.java`：
    - 维护有界 LRU 内存缓存（最多 100 个项目，每个项目最多 500 个证书节点；材料变更时按项目失效）；
    - 读时计算 `validityStatus`，吊销标记为 `UNCHECKED`；
    - 执行真实公钥验签确证（自身公钥自签且 CA 才是 `ROOT_CA`；自身自签但 CA=false 属于 `SELF_SIGNED_END_ENTITY`；CA 签发需候选 CA 具备 `keyCertSign` 且公钥验签通过）；
    - 孤立证书标为 `ORPHAN`，格式异常标为 `UNSUPPORTED`，跨签支持 `parentRefs` 多父，CSR 独立归组，链 Bundle 指纹去重；
    - 严禁产生持久 Job，不写 `jobs` 表；
  * 在 `MaterialController.java` 增加只读端点 `GET /api/v1/projects/{pid}/certificates`（受 VIEWER+ 及 CSRF 保护）。
- **前端边界 (`web/src`)**：
  * 新建 `web/src/components/CertificateTree.vue`（Thin 组件），在密钥库页面增设 `[ 全部材料 ]` 与 `[ 证书库 (按 CA 分组) ]` Tab；
  * `CertificateWizard.vue` 签署 CA 下拉选项升级为直接消费具备 `isCa=true && selectableAsIssuer=true` 的真实 CA 列表；
  * 保持 4 卡向导、SM4-CBC 随机 IV 与 PKCS#7 填充无回归。

---

## 2. 精确接口契约 (已冻结)

```
1. GET /api/v1/projects/{pid}/certificates (VIEWER+, 遵循只读读取鉴权与CSRF约定)
2. 响应: { nodes: CertificateNode[], csrs: CsrNode[], bundles: BundleNode[] }
3. CertificateNode: {
4.   id: string, fingerprint: string, name: string,
5.   category: "ROOT_CA" | "INTERMEDIATE_CA" | "ISSUED_CERT" | "SELF_SIGNED_END_ENTITY" | "ORPHAN" | "UNSUPPORTED" | "ENGINE_PENDING",
6.   subjectCN: string, issuerCN: string, serialNumber?: string,
7.   validBefore?: string, validAfter?: string, validityStatus: "VALID" | "EXPIRED" | "NOT_YET_VALID",
8.   revocationStatus: "UNCHECKED", isCa: boolean, selectableAsIssuer: boolean,
9.   parentRefs: string[], materialRefs: string[], downloadRef?: string, error?: string
10. }
11. CsrNode: { id: string, name: string, subjectCN: string, createdAt: string }
12. BundleNode: { id: string, name: string, containsCertIds: string[] }
13. 核心规则:
14.  - downloadRef 与 selectableAsIssuer: downloadRef 为独立单证文件的 "file:<id>"；若证书仅存在于 Bundle 链中无独立单文件，downloadRef 为 null 且 selectableAsIssuer 必为 false（禁止把整 chain 盲当单 CA，避免后台工作流无法解析）；
15.  - KeyUsage X.509 语义: KeyUsage 缺省(absent)表示用途不设限(允许签发)；若存在(present)则必须显式包含 keyCertSign 才能作为签发者，未置位则禁止签发；
16.  - 容错与状态: 单项损坏标为 UNSUPPORTED 并附带 error，绝不抛 500 拖垮全列表；自签名终端证书 (ca=false) 标为 SELF_SIGNED_END_ENTITY，不冒充根 CA；
17.  - 纯只读缓存: 纯内存有界 LRU 缓存，绝对严禁写入 jobs 表，未配置 CRL/OCSP 统一标记 revocationStatus="UNCHECKED".
```

---

## 3. TDD 实施步骤

### 阶段一：后端拓扑解析、验签与缓存服务（由 platform 负责，task-94）
- [ ] 1.1 编写单元测试 `X509CertificateParserTest.java`：测试有效 SM2 证书解析、自签名根 CA、自签名服务证书 (CA=false)、中间 CA、CSR 文件解析与异常文件判定。
- [ ] 1.2 编写集成测试 `CertificateTreeServiceTest.java`：
  - 测试自签根 CA 准确识别；
  - 测试根 CA 下发两张证书建立 `parentRefs` 拓扑关系；
  - 测试无 CA 孤立证书判定为 `ORPHAN`；
  - 测试过期 CA 标记为 `selectableAsIssuer=false` 但拓扑树依然保留挂载；
  - 测试连续 50 次请求不产生持久 `jobs` 表记录；
  - 测试材料上传/删除时缓存精准失效。
- [ ] 1.3 实现 `X509CertificateParser.java` 与 `CertificateTreeService.java`（含有界 LRU 缓存与公钥验签调度）。
- [ ] 1.4 在 `MaterialController.java` 增加 `GET /projects/{pid}/certificates` 端点并配置权限拦截。
- [ ] 1.5 运行全工程构建：验证全量 91+ 单元测试全部通过。

### 阶段二：前端证书树与向导智能选择（由 frontend 负责，task-95）
- [ ] 2.1 编写组件测试 `tests/certificate-tree.test.ts`：
  - 测试材料库顶部呈现 `全部材料` 与 `证书库 (按 CA 分组)` 切换 Tab；
  - 测试 CA 树展开、子证书展示、到期状态徽标呈现；
  - 测试多父证书渲染与防环截断；
  - 测试向导中已有 CA 仅展示 `selectableAsIssuer=true` 的真实 CA 候选。
- [ ] 2.2 实现 `web/src/components/CertificateTree.vue`。
- [ ] 2.3 修改 `web/src/App.vue`（挂载证书库 Tab）与 `web/src/components/CertificateWizard.vue`（消费有效 CA 列表）。
- [ ] 2.4 运行前端全套校验：保证 119+ Vitest 用例全部通过，`vue-tsc --noEmit` 0 错误，`vite build` 成功。

### 阶段三：独立验收与归档同步（由 cert-workflows 负责，task-96）
- [ ] 3.1 独立复核前后端代码改动与全量自动化测试（后端 91+，前端 119+，部署 39+）。
- [ ] 3.2 启动无头 Chrome (CDP) 真实验证材料库证书树切换、层级展示与向导联动，保存测试证据。
- [ ] 3.3 输出独立验收报告 `docs/review/ca-classification-acceptance.md`。
