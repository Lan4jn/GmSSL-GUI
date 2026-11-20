# 实施计划：全站简单模式与证书全自动串联

依据已批准的 `docs/superpowers/specs/2026-10-20-simple-mode-design.md`，制定前后端最小协作与 TDD 落地计划。

---

## 1. 核心架构与职责分工

- **后端边界 (`platform-service`)**：
  - 增强 `CertificateWorkflowService` / `CertificateWorkflowController`：
    * 新增支持 profile: `QUICK_ISSUE`（或扩展已有 `CA_SIGN`）：当未提供 `csrRef` 时，由服务端自动执行 `generateKey (SM2)` -> `reqgen (CSR)` -> `reqsign (签署)` -> 组装并保存 `xxx_cert.pem` 与 `xxx_chain.pem`。
    * 材料有效性与时效预检：真实解析 PEM 标头（严格校验 `CERTIFICATE REQUEST`，拦截将普通证书当作 CSR 传入的行为）；检查申请天数不超过已选 CA 证书剩余有效期。
    * 保持已有 6 个 Profile 契约完全向后兼容；错误响应遵守统一 `{code, message, requestId}` 规范。
- **前端边界 (`web/src`)**：
  - 顶栏模式切换：在 `App.vue` 增加会话级响应式状态 `workbenchMode`（默认 `'simple'`，可选 `'advanced'`），不写 localStorage/cookie。
  - 简单工作台组件：新建 `web/src/components/SimpleWorkbench.vue`（Thin 组件），在首页首屏显著展示“制作证书”主向导卡片（带图标、中文用途及“开始制作证书 ↗”按钮），并平铺六大高频场景（制作证书、生成密钥、文件加解密、签名验签、哈希摘要、我的材料库）。
  - 证书向导交互：包含 4 步清晰步骤条指示器，当前步骤标题、上一步/下一步固定可见；成功页直呈证书与链文件下载按钮；敏感私钥明确独立留存并需二次确认，不自动创建根 CA。

---

## 2. 最小前后端接口契约 (≤ 15 行)

```
1. POST /api/v1/projects/{pid}/certificate-workflows (EDITOR+, X-CSRF-Token)
2. 请求: { profile: "QUICK_ISSUE" | "SELF_SIGNED" | "CA_SIGN" | ..., name: string, days?: number,
3.          subject?: { CN?: string }, sanDns?: string[], sanIps?: string[],
4.          issuerCertRef?: string, issuerKeyRef?: string, issuerPassword?: string,
5.          purpose?: "SERVER" | "CLIENT" | "SIGNING" }
6. 响应: { workflowId: string, status: "SUCCEEDED" | "FAILED", stages: WorkflowStage[],
7.          keys: Key[], files: ManagedFile[], warnings: string[], error?: string }
8. 预检规则:
9.  - 若提供 csrRef: 必须为有效 PEM CSR (严格包含 -----BEGIN CERTIFICATE REQUEST-----);
10. - 若选已有 CA: 检查 days <= CA剩余有效天数, 且 issuerCertRef 必须为合法 CA 证书;
11. - 若未提供 csrRef 且 profile="QUICK_ISSUE": 服务端自动 keygen+reqgen+reqsign+chain;
12. - 成功产物中 files 包含实体证书与完整链 (直接下载); keys 包含新私钥 (敏感隔离/需确认);
13. - 错误返回标准 JSON: { code: "INVALID_MATERIAL" | "EXPIRED_ISSUER" | ..., message, requestId }
```

---

## 3. TDD 实施步骤

### 阶段一：后端自动串联与预检（由平台负责，task-72）
- [ ] 1.1 编写集成测试 `CertificateWorkflowTest.java`：测试 `QUICK_ISSUE` 自动完成密钥生成、CSR 与 CA 签署全流程。
- [ ] 1.2 编写负向预检测试：测试将普通证书作为 CSR 传入被准确拦截返回 400，测试申请天数超过 CA 剩余有效期被拦截。
- [ ] 1.3 在 `CertificateWorkflowService` 实现 `executeQuickIssue` 及 PEM 标头/有效期预检。
- [ ] 1.4 运行 surefire 验证平台全套测试通过。

### 阶段二：前端简单工作台与醒目向导（由前端负责，task-73）
- [ ] 2.1 编写 Vitest 测试 `tests/simple-workbench.test.ts`：
  - 测试首页默认呈现简单模式，首屏居中显著展示“制作证书”大任务卡与开始向导按钮；
  - 测试顶栏“简单 / 高级”模式切换平滑无损；
  - 测试向导 4 步流程切换与上一步/下一步状态；
  - 测试证书自动串联签发成功后展示证书与链文件下载。
- [ ] 2.2 实现 `web/src/components/SimpleWorkbench.vue`（六大场景卡片、首屏醒目入口、轻量向导）。
- [ ] 2.3 修改 `web/src/App.vue`：挂载模式切换开关与 `SimpleWorkbench`，保持高级模式 80+ 工具无回归。
- [ ] 2.4 运行 `pnpm typecheck` 与 `pnpm test` 保证全套测试通过，运行 `pnpm build` 验证生产构建。

### 阶段三：独立验收与发布打包（task-74, task-75）
- [ ] 3.1 独立审查员在测试环境运行端到端与真实浏览器验证。
- [ ] 3.2 同步更新离线操作说明，将最新前端 dist 打包进入预编译发布包。
