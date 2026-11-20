# CSR 与证书公钥双向关联实施计划 (task-104)

依据已批准的 task-103 方案，实现只读公开证书与 CSR 内存公钥双向引用，不建立持久 lineage。

---

## 1. 契约定义与字段规范 (<= 15 行)

```
1. GET /api/v1/projects/{pid}/certificates (VIEWER+)
2. CertificateNodeDto 增量字段:
3.   matchedCsrRefs: string[] (匹配公钥的 CSR 文件引用列表 ["file:<id>", ...])
4.   csrMatchEvidence?: "KEY_AND_SUBJECT_MATCH" | "KEY_MATCH_DIFFERENT_SUBJECT" | "AMBIGUOUS_MATCH"
5. CsrNodeDto 增量字段:
6.   id: string ("file:<id>", 真实文件引用，支持直接下载)
7.   spkiFingerprint?: string (SPKI SHA-256 十六进制指纹)
8.   matchedCertIds: string[] (匹配的证书逻辑 ID 列表 ["cert:<fingerprint>", ...])
9.   matchKind: "KEY_AND_SUBJECT_MATCH" | "KEY_MATCH_DIFFERENT_SUBJECT" | "UNMATCHED" | "INVALID_CSR"
10.  ambiguous: boolean (matchedCertIds.size() > 1 为 true)
11.  error?: string (坏 CSR 错误原因，坏 CSR 严禁关联任何证书)
12. 核心约束与多对多歧义模型:
13.  - 仅基于公开 SPKI SHA-256 指纹比对候选；CSR 侧当 matchedCertIds.size() > 1 或同公钥 CSR 数 > 1 时 ambiguous 必为 true，避免一对一假象；
14.  - 证据匹配强度：若所有匹配对主体 DER 均一致标 KEY_AND_SUBJECT_MATCH；若存在任意一对主体不同则保守标 KEY_MATCH_DIFFERENT_SUBJECT，不夸大一致性；
15.  - CSR 真实性与防呆：坏 CSR 或签名验证未通过的 CSR 标记为 INVALID_CSR，严禁参与任何关联匹配；UNMATCHED 仅代表未找到对应证书，不断言签发；
16.  - 纯内存有界 LRU 缓存，不写入 jobs 表，不修改 DB DDL。
```

---

## 2. 实施与 TDD 计划

1. **X509CertificateParser 增强**：
   - CSR 解析支持真实签名与格式校验，坏 CSR 明确设置 `error`；
   - 提取并暴露 `spkiFingerprint` 与 `spkiDer`。
2. **CertificateTreeService 关联推导**：
   - 构建内存 SPKI 索引，多对多双向映射 `matchedCertIds` 与 `matchedCsrRefs`；
   - 依据主体 DER 精确判定 `KEY_AND_SUBJECT_MATCH` 与 `KEY_MATCH_DIFFERENT_SUBJECT`；
   - 多匹配标记 `ambiguous=true` 及 `AMBIGUOUS_MATCH`，坏 CSR 标记 `INVALID_CSR` 且不关联。
3. **测试覆盖 (CertificateTreeServiceTest)**：
   - 同 Key 证书与 CSR 成功双向关联；
   - 不同 Key 同 CN 不产生误匹配；
   - 同 Key 改名/改主体标记为 KEY_MATCH_DIFFERENT_SUBJECT；
   - 同公钥多 CSR / 多证书多对多关联与歧义标记；
   - 无证书对应的独立 CSR 标记为 UNMATCHED；
   - 损坏 CSR 标记为 INVALID_CSR 且 matchedCertIds 为空；
   - Bundle 链内证书与 CSR 正常双向关联；
   - 缓存增删实时失效验证与全工程 104+ 测试防回归。
