# 证书按 CA 分类树与证书库拓扑设计方案

## 1. 背景与目标
解决用户分不清证书归属哪张 CA 的问题。在不修改 11 表 DDL、不破坏 Vault 卷、不访问私钥、无外网依赖的前提下，构建只读证书拓扑与向导真 CA 筛选。

---

## 2. 核心架构与有界缓存设计
1. **纯内存有界 LRU 缓存（杜绝 Job 风暴）**：
   - 证书内容不可变，解析与验签结果缓存于有界 LRU（最多 100 项目，每项目最多 500 证书节点）；材料增删时项目缓存失效；
   - 绝对严禁每次查询生成持久任务或写入 `jobs` 表；时间状态（VALID / EXPIRED / NOT_YET_VALID）在读取时按当前时钟动态计算；
   - 吊销状态统一标记为 `UNCHECKED`（系统不引入外部 CRL/OCSP，不对外宣称未验证的吊销状态）。
2. **只读公开公钥验签**：
   - 仅对公开证书的 TBS 与 SPKI 执行验签，绝对不解密扫描私钥包（`_keys.pem`）或敏感凭据；
   - 候选过滤：通过扩展名与 mediaType 粗筛，结合真实 PEM/DER 解析；若算法不支持标为 `UNSUPPORTED`，引擎暂不可用标为 `ENGINE_PENDING`。

---

## 3. 证书拓扑推导与严格关系验证规则
1. **自颁发 vs 自签名判定**：
   - 若 `issuerDER == subjectDER`：仅为 Self-Issued 候选；
   - 自身公钥真验签通过，且 BasicConstraints 明确 `ca=true`：确认为 **ROOT_CA**（根 CA）；
   - 自身验签通过但 `ca=false` 或无 CA 标识：分类为 **SELF_SIGNED_END_ENTITY**（自签名服务证书），严禁冒充根 CA。
2. **签发关系确证 (Issued Leaf / Intermediate)**：
   - 候选 CA 必须具备：BasicConstraints 明确 `ca=true`；KeyUsage 若包含扩展则必须置位 `keyCertSign`（若扩展缺省则依 RFC5280 不限制）；
   - 签名确证：使用候选 CA 的公钥验签通过才建立父子边；
   - 跨签多父：`parentRefs` 数组完整记录所有有效父节点，前端按多父并列渲染，递归防环深度截断为 8；
   - 历史过期 CA：拓扑关系仍可在树上展示，但向导签署标记 `selectableAsIssuer=false`；
   - 找不到合法 CA 的归入 **ORPHAN**（孤立证书）。
3. **CSR 与 Bundle 处理**：
   - 独立 CSR（包含 `CERTIFICATE REQUEST`）统一归入 **CSR** 组；
   - 证书链 Bundle（`_chain.pem`）：解析各子证书 DER 并去重，记录 `downloadRef`，避免单证书重复挂载。

---

## 4. 最小前后端契约 (API Specification)
只读接口 `GET /api/v1/projects/{pid}/certificates`（VIEWER+，项目隔离与 CSRF 保护）：
```json
{
  "nodes": [
    {
      "id": "file:f_root", "name": "root_ca.pem", "category": "ROOT_CA",
      "subjectCN": "GmSSL Root CA", "issuerCN": "GmSSL Root CA", "serialNumber": "3a7b...",
      "validBefore": "2026-01-01T00:00:00Z", "validAfter": "2036-01-01T00:00:00Z",
      "validityStatus": "VALID", "revocationStatus": "UNCHECKED",
      "isCa": true, "selectableAsIssuer": true, "parentRefs": []
    },
    {
      "id": "file:f_srv", "name": "server_cert.pem", "category": "ISSUED_CERT",
      "subjectCN": "www.gmssl.local", "issuerCN": "GmSSL Root CA",
      "validityStatus": "VALID", "isCa": false, "selectableAsIssuer": false,
      "parentRefs": ["file:f_root"]
    }
  ],
  "csrs": [{ "id": "file:f_req", "name": "app.csr", "subjectCN": "client.local" }],
  "bundles": [{ "id": "file:f_chain", "name": "server_chain.pem", "containsCertIds": ["file:f_srv", "file:f_root"] }]
}
```

---

## 5. 界面交互与组件设计
1. **材料库 Tab**：密钥库页面提供 `[ 全部材料 ]` 与 `[ 证书库 (按 CA 分组) ]`，展示 CA 折叠树、证书数、到期状态与直接下载。
2. **向导联动**：证书向导 CA 候选过滤为仅选择具备 `isCa=true && selectableAsIssuer=true` 的真实有效 CA，不再盲筛扩展名。

---

## 6. 职责边界与验收标准
- **后端**：提取 `X509CertificateParser` 解析器与 `CertificateTreeService` 内存 LRU 拓扑推导服务，提供 GET 接口。
- **前端**：新建 `CertificateTree.vue` 薄组件，向导下拉框消费结构化合法 CA 列表。
- **验收**：ROOT_CA/自签名终端/多父/孤立/CSR 全覆盖测试；连续刷新 0 持久任务；构建 tests (91后端, 119前端, 39部署) 全绿。
