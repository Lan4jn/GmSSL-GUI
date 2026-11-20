# CSR 与证书公钥关联只读核查与最小增量设计报告 (task-103)

## 1. 事实核查结论 (Fact-Checking)
1. **CSR 解析能力**：`X509CertificateParser.java:271-292` 已完整解析 CSR 根 Sequence，正确提取 `subject` (DER)、`subjectCN` 以及 `spki` (SubjectPublicKeyInfo DER 字节)。证书解析器同样在第 187/240 行暴露完全相同的 `spkiDer`，**公钥 SPKI 比对完全具备代码级零依赖复用条件**。
2. **持久关联证据**：`CertificateWorkflowService` 在 `QUICK_ISSUE` 中分别调用 `reqgen` 和 `reqsign`，两产物作为独立项目文件存入 `files` 表，**元数据无外键关联，也无跨文件持久化 lineage 证据**。
3. **关联定性底线**：严禁伪造唯一签发事实，严禁按文件名、创建时间或 CN 模糊瞎猜；必须且仅能通过 **SPKI SHA-256 指纹** 进行公开公钥比对。

---

## 2. 关联判定分类与多对多歧义模型
- **`CONTENT_CONSISTENT`**：`csr.spkiDer == cert.spkiDer` 且 `csr.subjectDer == cert.subjectDer`（公钥与主体完全一致）。
- **`PUBLIC_KEY_MATCH`**：`csr.spkiDer == cert.spkiDer` 但主体有细微差别（同密钥重申请）。
- **`AMBIGUOUS`**：同公钥存在多份 CSR 或多张证书（如多证书复用同私钥、历史证书更新换代），标注为多对多关联。
- **`UNMATCHED`**：未在本项目中检索到匹配 SPKI 的证书（纯外部签发申请）。

---

## 3. 最小 API 与 DTO 增量设计
- **`CertificateNodeDto` 新增**：
  * `matchedCsrRefs: List<String>`：匹配该证书公钥的 CSR 文件引用列表（`["file:<id>", ...]`）。
- **`CsrNodeDto` 新增**：
  * `spkiFingerprint: String`：CSR 公钥 SPKI SHA-256 十六进制指纹；
  * `matchedCertIds: List<String>`：匹配该 CSR 公钥的证书逻辑 ID 列表（`["cert:<sha256>", ...]`）；
  * `matchKind: String`：`CONTENT_CONSISTENT` | `PUBLIC_KEY_MATCH` | `AMBIGUOUS` | `UNMATCHED`。

---

## 4. 界面呈现设计 (保持现有 CA 树风格)
1. **CA 拓扑树证书节点**：
   - 若 `matchedCsrRefs` 有值，展示 `关联 CSR: <name>` 徽标及下载按钮；
   - 若有多份，展示 `关联 N 份 CSR`，点击展开各 CSR 文件名并支持下载。
2. **独立 CSR 申请分组**：
   - 仍保持独立分组，不挂入 CA 树；
   - 单匹配时展示 `对应证书: <name> (CN)` 并支持点击在 CA 树中高亮定位；
   - 多匹配时展示 `对应多张证书 (共 N 张)`；无匹配时展示 `待签发 / 独立申请`。
3. **Bundle 节点保护**：Bundle 内部证书无单文件 downloadRef 时照常展示匹配 CSR，但证书本身严禁伪造下载入口。
