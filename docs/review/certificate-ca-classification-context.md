# 证书签发关系与按 CA 分类可复用元数据只读事实核验 (task-91)

## 一、现有元数据与持久化关系核验事实

1. **数据库 Schema 无关联字段**：
   - `01_schema_dm8.sql:44-63`：`materials` 表仅包含通用字段（`id, project_id, object_type, name, media_type, byte_size, temporary, generation_provider` 等），**完全不存在** `issuer_cert_id`、`parent_material_id`、`subject_dn`、`issuer_dn`、`serial`、`ski`、`aki` 等证书关系列。
2. **签发流程未持久化父子拓扑**：
   - `CertificateWorkflowService.java:431-441`：`saveFile()` 保存新证书或链时仅调用 `materials.create(pid, "FILE", filename, mediaType, content, Map.of("temporary", "false"))`，签发时传入的 `issuerCertRef` 仅在工作流运行时内存使用，未沉淀为材料关系的持久记录。
3. **文件列表 DTO 字段缺失**：
   - `Materials.java:47-53`（`dto()`）与 `MaterialController.java:22-35`（`GET /projects/{pid}/files`）：对外暴露的字段严格仅有 `id, name, createdAt, size, mediaType, temporary, generationProvider, hasManagedPassphrase`，前端无法从现有文件列表中获知任何证书类型、主体或签发者信息。
4. **前端展示混杂现状**：
   - `App.vue:172`：所有 `FILE`（包含根 CA、服务证书、证书链、CSR、双私钥 pem、普通文本）全部平铺在同一个“输入材料”列表中；
   - `CertificateWizard.vue:221-228`：仅通过后缀（`.crt, .pem, .cer`）与 `mediaType` 字符串粗筛可用 CA 证书，无法感知证书层级。

---

## 二、现有证书解析能力 (`Cert` 类) 事实与差距

- 源码位置：`platform-service/src/main/java/org/gmssl/gui/platform/CertificateWorkflowService.java:1154-1226`
  1. **已有解析字段**：
     - `issuer` (Der 字节块, 行 1177)、`subject` (Der 字节块, 行 1181)；
     - `spki` (Der 公钥结构, 行 1181)、`signature` (byte[], 行 1172)；
     - `before / after` (Instant 有效期, 行 1180)；
     - `ca / pathLen` (BasicConstraints 扩展, 行 1195-1202)；
     - `keyUsage` (扩展, 行 1211)、`eku` (扩展, 行 1212)、`dns / ips` (SAN 扩展, 行 1203-1210)。
  2. **缺失与未解析字段**：
     - **未解析 SKI (OID 551d0e) 与 AKI (OID 551d23)**，扩展循环（行 1186-1213）仅匹配了 `551d13`、`551d11`、`551d0f`、`551d25`；
     - 未提供从 Der 转换为人类可读 X.500 DN 字符串（CN/O/OU/C）的工具方法；
     - `Cert` 结构体为 `private static final`，仅供工作流内部临时预检，未在 `Materials` 服务中复用。
  3. **自颁发 vs 自签名判定界限**：
     - `Arrays.equals(cert.subject.encoded(), cert.issuer.encoded())` 仅能判定 **Self-Issued（自颁发）**；
     - 若要确证 **Self-Signed（自签名）**，必须使用证书自身的 `spki` 公钥对 `tbs` 及 `signature` 执行签名验证；目前工作流通过调度 native `sm2verify` 实现（行 1258），内存解析器尚未内置验签。

---

## 三、按 CA 分类识别依据与推荐方案

1. **识别与分组逻辑依据**：
   - **根 CA (Root CA)**：`ca == true && usage(keyCertSign) == true` 且通过自签名公钥验签通过（或发行者与主体 DER 全等）；
   - **中间 CA (Intermediate CA)**：`ca == true && usage(keyCertSign) == true` 且发行者与主体 DER 不全等；
   - **终端证书 (End-Entity Cert)**：`ca == false`，通过发行者 DN 与 AKI（或父材料指引）关联到对应的 CA；
   - **CSR 文件**：`mediaType == "application/pkcs10"` 或 PEM 标头为 `CERTIFICATE REQUEST`；
   - **无 CA / 孤立证书**：系统中未找到匹配签名公钥或发行者证书的证书。
2. **最小改动涉及范围**：
   - 后端：在 `Materials.java` 或独立辅助类中复用 DER 解析逻辑，在保存证书或查询列表时提取轻量元数据（`certType: ROOT_CA | INTERMEDIATE_CA | CERT | CSR`, `subjectCN`, `issuerCN`, `parentFileId`）；
   - 前端：材料库增加“证书库 (按 CA 层级分类)”树形或卡片式视图，向导选择 CA 时展示树状层级及签发关系。
