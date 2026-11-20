# 标准客户端证书管理（GM Web UI 与测试）交付报告

## 一、概述与任务范围

本任务根据 **task-36（实现两个管理员操作入口）** 的统一规划，专做 **GmSSL-GUI 仓库前端（web 模块）** 的标准客户端证书管理及对应 UI 测试。

- **工作空间范围**：严格限定于 `F:/IdeaProjects/GmSSL-GUI/web` 及其测试用例；
- **边界约束**：
  - 不修改后端代码，不执行 Git commit；
  - 不处理 FM（file-manager）业务代码及相关文件；
  - 不修改团队看板与任务状态；
  - 遵循 TDD 规范，先写短测试（红灯验证），再实现最简代码并跑通全部测试（绿灯验证）。

---

## 二、接口与安全契约实现

标准客户端证书管理接口挂载于平台同源 API 路径：`/api/v1/projects/{pid}/standard-client-certificates`。

### 1. 凭据与 CSRF 安全机制
- **HttpOnly Cookie**：全链路请求继承平台既有 `credentials: 'same-origin'`，凭据不落地浏览器存储；
- **CSRF Token**：`src/api.ts` 中针对所有变动操作（`POST`、`PUT`、`DELETE`、`PATCH`）统一自动注入 `X-CSRF-Token` 内存请求头，`GET` 查询不附加该请求头。

### 2. API 方法封装清单（`src/api.ts`）
| 方法名 | HTTP 动词 | 请求路径 | 参数与请求体 | 返回结构 |
|---|---|---|---|---|
| `listStandardCertificates` | `GET` | `/projects/{pid}/standard-client-certificates` | `?fingerprint=&page=0&size=50` | `{ items: StandardClientCertificate[], total: number }` |
| `issueStandardCertificate` | `POST` | `/projects/{pid}/standard-client-certificates` | `{ requestId, csrPem, deviceLabel }` | `StandardClientCertificate` (单条) |
| `getStandardCertificate` | `GET` | `/projects/{pid}/standard-client-certificates/{id}` | 路径参数 `id` | `StandardClientCertificate` (单条) |
| `revokeStandardCertificate` | `POST` | `/projects/{pid}/standard-client-certificates/{id}/revoke` | 路径参数 `id` | `StandardClientCertificate` (单条) |

### 3. 数据模型定义（`src/types.ts`）
```typescript
export type StandardCertStatus = 'VALID' | 'REVOKED' | 'EXPIRED'

export interface StandardClientCertificate {
  id: string
  projectId: string
  requestId: string
  deviceLabel: string
  fingerprint: string
  serial: string
  expiresAt: number // epoch ms
  status: StandardCertStatus
  certificatePem: string
  chainPem?: string
}

export interface StandardCertPageResult {
  items: StandardClientCertificate[]
  total: number
}

export interface IssueStandardCertRequest {
  requestId: string
  csrPem: string
  deviceLabel: string
}
```

---

## 三、UI 组件设计与关键功能特性（`StandardCertManager.vue`）

组件位于 `src/components/StandardCertManager.vue`，并在 `src/App.vue` 中完成系统导航与视图装配。

### 1. 仅管理员按项目管理
- **系统角色隔离**：导航项 `客户端证书` 及视图仅对 `user.role === 'ADMIN'` 用户可见；普通用户（`USER`）侧边栏不可见、无法越权访问；
- **项目作用域隔离**：所有发证与查询强依赖当前选择的 `projectId`，项目切换时自动清空并拉取对应项目的证书台账。

### 2. 严格安全校验：只接受 CSR，严禁私钥
- **私钥特征前置拦截**：在前端提交前扫描材料，若检测到 `BEGIN PRIVATE KEY`、`BEGIN EC PRIVATE KEY`、`BEGIN RSA PRIVATE KEY` 等私钥头部标记，立即在界面展示红色警告并阻断网络请求：
  > “严禁输入私钥材料！平台仅接受标准客户端证书签名请求（CSR，以 -----BEGIN CERTIFICATE REQUEST----- 或 -----BEGIN NEW CERTIFICATE REQUEST----- 开头）”
- **CSR PEM 格式校验**：严格验证是否具有有效的证书请求头尾边界，拒绝非 PEM 纯文本输入。

### 3. 断线复用 `requestId`
- 当管理员点击签发时，生成全局唯一请求追踪标识 `requestId`；
- 若遇网络闪断、连接中断或服务端报错，表单保留当前的 `requestId`；
- 管理员点击重试签发时，复用该 `requestId` 重新提交，防止服务端因重试签发产生多张重复证书；
- 仅在签发成功后，才重置 `requestId`。

### 4. 防重复点击机制
- 设立 `issuing` 与 `revoking` 状态锁；
- 提交和吊销按钮在请求期间自动添加 `disabled` 属性并切换加载文案，连续快速点击直接阻断，避免触发并发重复请求。

### 5. 复制与下载全覆盖
- **复制指纹与证书**：
  - 支持一键复制 SHA-256 证书指纹；
  - 支持一键复制证书 PEM 文本；
  - 提供轻量反馈提示气泡（“已复制到剪贴板”，停留 2.5 秒后自动消失）；
- **证书与证书链下载**：
  - 点击“下载证书”自动生成 `${deviceLabel}-cert.pem` 文件并触发浏览器下载；
  - 若服务端返回中存在 `chainPem`，展示“下载证书链”按钮，一键下载完整 CA 证书链。

### 6. 吊销确认与安全提示（“吊销 ≠ 本地解绑”）
- 吊销按钮触发二次确认对话框，以突出警示框明确告知管理员：
  > **重要提示：吊销 ≠ 本地解绑**
  > 在服务端完成证书吊销后，该证书将被标记为失效；文件管理器按状态检查策略拒绝设备认证，这不等于 TLS 握手必然失败。但**本操作不会自动清除或解绑客户端本地保存的私钥和证书文件**。如需彻底停用，请同时在客户端设备或本地系统中手动解绑或清理该证书。
- 确认吊销后调用 `/revoke` 接口，并实时更新列表状态为 `已吊销`。

### 7. 过期时间与停服异常处理
- **过期状态识别**：依据 `expiresAt` 时间戳（epoch ms）与当前客户端时间比对，当已过有效期自动标为 `已过期`（红色警示状态）；
- **停服与网络故障友好提示**：捕获 `NETWORK_ERROR`（HTTP 0）或 `HTTP 503` 异常，渲染“服务异常或已停服”警报条，并提供“重试连接”按钮，允许在后端服务恢复后一键刷新。

---

## 四、验证证据

### 1. 专项测试套件（`tests/standard-cert.test.ts`）
包含 16 个测试用例，覆盖 API 契约、输入校验、断线重试、防重点击、复制下载、吊销确认、停服恢复及导航鉴权集成：
```text
 ✓ tests/standard-cert.test.ts (16 tests) 164ms
   ✓ Standard Client Certificate API Contract (4)
     ✓ listStandardCertificates requests correct URL with credentials and query params
     ✓ issueStandardCertificate sends POST with X-CSRF-Token and json body
     ✓ getStandardCertificate requests single certificate by id
     ✓ revokeStandardCertificate sends POST with CSRF to revoke endpoint
   ✓ StandardCertManager UI Component (10)
     ✓ loads and displays standard client certificates for the selected project
     ✓ strictly rejects private key and warns user when pasting private key instead of CSR
     ✓ strictly validates CSR format and rejects empty or invalid PEM
     ✓ reuses requestId upon network failure during retry, and generates new requestId after success
     ✓ prevents double-clicking by disabling submit button and debouncing
     ✓ supports copying fingerprint and certificate with notification
     ✓ supports downloading certificate and chain
     ✓ requires explicit confirmation before revoking and clearly states "吊销≠本地解绑"
     ✓ shows clear error and retry action when server is down or returns network error
     ✓ supports searching by fingerprint and pagination
   ✓ App Workspace Integration for Standard Client Certificates (2)
     ✓ renders "客户端证书" in sidebar for ADMIN users and opens StandardCertManager view
     ✓ hides "客户端证书" navigation completely for regular non-ADMIN users
```

### 2. 全量前端测试套件验证
```text
 RUN  v5.0.5 F:/IdeaProjects/GmSSL-GUI/web

 ✓ tests/api.test.ts (5 tests) 11ms
 ✓ tests/forms.test.ts (15 tests) 7ms
 ✓ tests/key-generator.test.ts (8 tests) 7ms
 ✓ tests/artifacts.test.ts (4 tests) 3ms
 ✓ tests/simple-workbench.test.ts (3 tests) 58ms
 ✓ tests/components.test.ts (40 tests) 187ms
 ✓ tests/certificate-tree.test.ts (16 tests) 208ms
 ✓ tests/standard-cert.test.ts (16 tests) 196ms
 ✓ tests/certificate-wizard.test.ts (29 tests) 262ms
 ✓ tests/app.test.ts (14 tests) 287ms

 Test Files  10 passed (10)
      Tests  150 passed (150)
   Duration  1.36s
```

### 3. 类型检查与生产构建验证
```bash
$ vue-tsc --noEmit && vite build
vite v8.3.4 building client environment for production...
transforming...
✓ 1589 modules transformed.
rendering chunks...
computing gzip size...
dist/index.html                   0.41 kB │ gzip:  0.32 kB
dist/assets/index-yCl9y09s.css   48.53 kB │ gzip: 10.66 kB
dist/assets/index-iTqy_AQl.js   240.10 kB │ gzip: 79.63 kB

✓ built in 314ms
```
TypeScript 严格模式无任何报错，Vite 生产包构建成功。

---

## 五、交付清单与变更文件

1. `src/types.ts`：定义 `StandardClientCertificate`、`StandardCertStatus`、`StandardCertPageResult`、`IssueStandardCertRequest`；
2. `src/api.ts`：封装 `listStandardCertificates`、`issueStandardCertificate`、`getStandardCertificate`、`revokeStandardCertificate`，完全遵循 Cookie + CSRF 规范；
3. `src/components/StandardCertManager.vue`：标准客户端证书管理员界面（签发表单、安全防私钥、防重复点击、断线复用 requestId、复制、下载、吊销确认、停服重试）；
4. `src/App.vue`：管理员导航项与页面挂载，支持简单/高级模式适配与证书工具页快捷跳转；
5. `tests/standard-cert.test.ts`：16 项标准客户端证书管理与 UI 完整测试套件；
6. `docs/review/standard-client-certificates-web-report.md`：本交付报告。
