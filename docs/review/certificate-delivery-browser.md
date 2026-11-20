# 证书成功页交付：独立浏览器验证（task-51）

## 结论与范围

**PASS：真实 Chrome + mock 业务数据。不是实库证书签发验收，也不是用户材料下载验收。**

- 验证时间：2026-10-20T03:28:50.922Z
- 页面入口：http://127.0.0.1:18088/
- 浏览器：Chrome/155.0.8059.85，headless Chrome / 原生 CDP，独立临时 profile。
- 命令：`node --check .tools/dm-local/browser-certificate-delivery.mjs && node .tools/dm-local/browser-certificate-delivery.mjs`。
- 本轮执行：`bash-208c96217d2843ac`，退出码 0。
- MCP 匹配搜索返回 REA browser 工具描述，但 SDK 未注册实际 callable；采用本机真实 Chrome CDP，不以 HTTP 200 替代页面交互。

## 真实与模拟的边界

真实：18088 上已冻结前端的组件渲染、登录、Vue 点击处理、fetch/blob 下载逻辑、浏览器原生确认对话框、App 的 navigate-vault 事件与页面切换。登录、目录和生成能力由预览服务实际返回。

模拟：为避免创建项目/签证/key，CDP Request 阶段仅在隔离 context 内 fulfill 以下请求：

- GET `/api/v1/projects` 和合成项目 `00000051-0000-4000-8000-000000000051` 下只读列表。
- POST `/api/v1/projects/00000051-0000-4000-8000-000000000051/certificate-workflows`，返回 fixture success，**没有转发后端**。
- 仅指定公开 fixture file ID 的 GET download，返回合成、不可用于真实验证的 PEM 形状字节。

所有 fixture interception 均在 summary 标记 `forwarded:false`。其他非登录写请求和非 fixture 下载设有阻断保护，最终 `blocked=[]`；没有真实持久化变更。

首轮登录后当前项目选择为空，按约束停止，没有新建项目；因此后续使用明确标识 `NOT persisted` 的项目 fixture，不推断数据库内容。首轮记录：`.tools/dm-local/browser-certificate-evidence/initial-no-project.json`。

## 实测结果

| 验收项 | 实际观察 |
|---|---|
| 成功页公开材料 | CERT、CSR、CHAIN 三项在普通下载区，name 与各自 fixture ID 一一对应 |
| 下载 URL | `/api/v1/projects/00000051-0000-4000-8000-000000000051/files/{fixture-cert-51,fixture-csr-51,fixture-chain-51}/download` |
| 真实下载点击 | 三个按钮均触发正确 GET → blob anchor；Chrome downloadWillBegin 的 suggestedFilename 为 `browser51_cert.pem`、`browser51_request.csr`、`browser51_chain.pem`；本地仅保存合成公开测试字节 |
| 敏感分组 | `browser51_tlcp_keys.pem` 只在敏感区，显示“包含双私钥密文”；两把 fixture key 只有元数据提示 |
| 确认与取消 | 点击“下载私钥”出现真实 Chrome confirm；取消后请求计数不变，未请求/下载敏感文件 |
| 下载异常 | 仅 fixture-cert-51 第二次下载返回合成 403；错误 banner 显示 mock 提示，关闭后可重试成功 |
| 密钥库导航 | 点击成功页“前往密钥库”，实际 App active nav 变为“密钥库”、向导关闭；App 发起 keys/files 刷新 GET，响应仍为隔离 context fixture，不宣称真实库有 fixture 材料 |
| 错误检查 | runtime exception 0、console error 0、loading failure 0；非预期 HTTP 错误 0。未登录 auth/me 401、故意注入 download 403 已明确分类 |
| 隐私与持久化 | 密码仅进程内读取指定 preview credentials.json 后填登录；没有报告密码/Cookie；localStorage/sessionStorage 均 0；没有创建真实项目/证书/key、没有读取用户私钥/口令 |

## 证据

- 脚本：`.tools/dm-local/browser-certificate-delivery.mjs`，156 行。
- 汇总：`.tools/dm-local/browser-certificate-evidence/summary.json`。
- 成功与分组截图：`.tools/dm-local/browser-certificate-evidence/success-public-vs-sensitive-mock.png`。
- 合成下载错误截图：`.tools/dm-local/browser-certificate-evidence/fixture-download-error.png`。
- 实际 App 导航截图：`.tools/dm-local/browser-certificate-evidence/actual-app-vault-navigation.png`。
- 合成公开下载：`.tools/dm-local/browser-certificate-evidence/downloads/`。截图中 mock 项目、mock workflow/stage 均明确可见，无密码或 Cookie。

浏览器退出后仅清理自有临时 profile。未启动、停止或重启任何服务；18088/18080/18081 预览实例保持给用户使用。未修改生产/UI/release 文件。本次未测试敏感下载的“确认接受”分支，未进行任何真实加密算法/证书签发回归。
