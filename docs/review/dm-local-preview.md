

## task-43：独立真实浏览器验收

- 结果：**PASS**，时间 2026-10-19T12:48:41.698Z；命令 `node .tools/dm-local/browser-preview.mjs`，退出码 0（job `bash-0db069b9b53f4b5e`）。
- 可访问入口：http://127.0.0.1:18088/；新平台 http://127.0.0.1:18080；引擎由启动 owner 提供为 http://127.0.0.1:18081。
- 浏览器：Chrome/155.0.8059.80，真实 headless Chrome / 原生 CDP，单独临时 profile；结束后仅关闭自有浏览器并清理临时 profile，后端服务保持运行。
- 实际 UI：登录、创建一个预览项目（`8eb16674-79e7-460c-b638-37be1ba176eb`）、94 项工具目录、SM3 参数表单、密钥库、密钥生成能力弹窗（只查看）、6 个证书 profile、填写主体与 DNS/IPv4/IPv6 SAN 后进入 provider 页面，未提交生成或签发。
- 路由验证：`.runtime/dm-local/vite.config.mjs` 第 8 行将 `/api` 指向 18080；Chrome 捕获 19 个经 18088 的 API 响应。使用该隔离浏览器会话对 18080 只读查询 projects，返回 200 且包含刚由 UI 新建项目 ID/name，确认不是旧平台数据路径。
- 错误：runtime exception 0、console error 0、API loading failure 0、非预期 HTTP 错误 0。未登录时 `auth/me` 的 401 是正常登录态检查，其后 login 与业务 API 成功。
- 隐私：密码由 owner 提供的唯一 preview credentials.json 在进程内读取并填入；不写报告、不输出 Cookie；截图隐藏密码输入；localStorage/sessionStorage 数量均 0。
- 范围：仅登录和创建 1 个 preview 项目；没有提交密钥生成、加解密、签名、证书工作流或状态型签名，因此本结论不代表全部算法回归。
- MCP：匹配搜索返回 REA browser scenario 描述，但实际 SDK 未注册且 namespace 激活不可用；采用已验证存在的 Chrome CDP 完成真实页面交互，不以 HTTP 健康检查代替浏览器。

证据：
- `.tools/dm-local/browser-preview.mjs`（可复现脚本，105 行）
- `.tools/dm-local/browser-evidence/summary.json`（结构化网络/页面/错误结果）
- `.tools/dm-local/browser-evidence/{login,workspace,project-created,tool-sm3-readonly,vault,keygen-capabilities-only,certificate-profiles,certificate-provider-no-submit}.png`
