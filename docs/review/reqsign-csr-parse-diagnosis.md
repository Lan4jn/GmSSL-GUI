# 现场 reqsign 任务 CSR 解析失败诊断报告 (Job e3741e0f-db32-4170-afb4-b66f2cbe33bb)

## 1. 现场失败特征与错误根因分析

现场任务日志返回：
```
/tmp/gmssl-review.V5gpYG/upstream/src/pem.c:102:pem_read():
/tmp/gmssl-review.V5gpYG/upstream/src/x509_req.c:350:x509_req_from_pem():
reqsign: parse CSR failure
```

- **路径解析**：`/tmp/gmssl-review.V5gpYG/upstream/...` 是 CMake 编译 runner 时的 C 原生宏 `__FILE__` 路径，**并非运行时用户文件路径**。
- **定位代码**：
  - `pem.c:102`：`pem_read()` 扫描 PEM 文件的起始标签 `-----BEGIN <name>-----`。
  - `x509_req.c:350`：调用 `pem_read(fp, "CERTIFICATE REQUEST", ...)`。
  - **直接判据**：GmSSL 原生实现严格进行字符串字面量精确匹配 `strcmp(name, "CERTIFICATE REQUEST") == 0`。如果输入的 PEM 头不是标准的 `-----BEGIN CERTIFICATE REQUEST-----`（例如是老式/兼容头 `-----BEGIN NEW CERTIFICATE REQUEST-----`，或是错选了证书 `-----BEGIN CERTIFICATE-----`，或是纯 DER 二进制），`pem_read()` 直接在第 102 行返回 0，导致 `x509_req_from_pem` 在第 350 行报错退出，产生完全一致的错误栈。

---

## 2. 现场可能原因排查（三大优先方向）

1. **输入文件类型错选（高概率）**：
   - 在前端证书向导的“CA 签发”步骤中，`待签发的 CSR 请求文件材料` 下拉框展示了项目中所有的 `files`。用户可能无意中选择了生成的 `*_cert.pem`（证书文件）、私钥文件或其它非 CSR 材料。
   - 合成验证：当把 `CERTIFICATE` 作为 `-in` 传入 `reqsign` 时，报错完全复现（`pem.c:102` -> `x509_req.c:350`）。
2. **CSR PEM 标头格式不兼容（中概率）**：
   - 外部通过某些 OpenSSL 版本或第三方工具生成的 CSR 可能包含 `-----BEGIN NEW CERTIFICATE REQUEST-----`。
   - GmSSL 原生不支持带有 `NEW` 字样的头部。合成验证显示该格式同样在 `pem.c:102` 阻断。
3. **文件编码/格式问题（DER 或 BOM/空内容）**：
   - 上传的 CSR 文件为纯 DER 二进制格式而非 PEM 文本格式，或包含特殊字符前缀。

---

## 3. 用户侧排查与自检验证建议（无私钥泄露风险）

请用户在本地终端对该 CSR 文件执行以下标准验证命令（不需要提供私钥，不上传完整身份信息）：

```bash
# 1. 验证 CSR 结构与签名有效性
openssl req -in csr.pem -noout -verify

# 2. 检查 CSR 的 PEM 标头格式（必须是 CERTIFICATE REQUEST）
head -n 1 csr.pem
# 预期输出必须严格为：
# -----BEGIN CERTIFICATE REQUEST-----

# 3. 检查 CSR 主体信息
openssl req -in csr.pem -noout -subject
```

若头部为 `-----BEGIN NEW CERTIFICATE REQUEST-----`，将其文本替换为 `-----BEGIN CERTIFICATE REQUEST-----` 并重新上传即可。
