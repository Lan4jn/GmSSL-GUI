# 真实浏览器核查简单模式首页与双路径向导独立报告 (task-78)

## 一、验收结论

**判定：PASS**
- **浏览器执行真实性 (browser TRUE)**：使用本机真实 Google Chrome Headless 实例通过原生 Chrome DevTools Protocol (CDP) 驱动真实交互与截图，非 JSDOM 模拟。
- **服务端契约说明 (backend MOCK)**：使用独立的静态服务进程与 Mock 夹具伺服 `web/dist`，未连接运行中的 18088 预览实例，未连接生产 DM8 达梦实库，未读取或修改用户生产 Vault 或私钥材料。
- **控制台与运行时错误**：控制台 0 错误 (0 console error)，0 未捕获运行时异常 (0 uncaught exception)。
- **安全审计**：`localStorage` 与 `sessionStorage` 均为完全清空状态 (`{"localStorage":[],"sessionStorage":[]}`)，零私钥、零密码持久化残留。

---

## 二、逐项交互验收与证据核验

### 1. 简单模式首屏与六大场景卡片 (PASS)
- 登录后默认呈现简单模式工作台 (`.simple-workbench`)；
- 首屏居中突出呈现**制作国密 / X.509 证书大任务卡** (`.primary-cert-card`)，配备醒目的“开始制作证书 ↗”主按钮；
- 首页平铺 **6 大高频场景卡片**（制作证书、生成密钥、文件加解密、数字签名、哈希摘要、我的材料库）；
- **截图证据**：`.tools/simple-mode-evidence/01_desktop_simple_workbench.png`。

### 2. 一步唤起向导与精准双卡呈现 (PASS)
- 点击首屏“开始制作证书”主按钮，直接一步进入证书制作向导 (`.cert-wizard`)；
- 向导通过 `:simple-mode="true"` 严格仅渲染**两张通俗大卡**：
  1. `SELF_SIGNED`：单证自签名证书；
  2. `QUICK_ISSUE`：快速签发服务证书（已有 CA 一键签发）；
- 根 CA、中间 CA、CSR 申请、TLCP 双证书等专业卡片被彻底排除；
- **截图证据**：`.tools/simple-mode-evidence/02_simple_cert_wizard_2_cards.png`。

### 3. QUICK_ISSUE 自动串联与无 CSR 字段 (PASS)
- 选定 `QUICK_ISSUE` 进入步骤 3（签署机构信息）：
  * 页面仅展示“CA 证书文件”与“CA 签署私钥”选择器；
  * **完全隐藏了 CSR 上传/输入框** (`#csr-file` 存在性为 `false`)，无需用户提前制作或上传 CSR；
  * 若未选 CA 证书，提供明确中文防呆引导提示，坚决不 autoRoot；
- **截图证据**：`.tools/simple-mode-evidence/03_step3_quick_issue_no_csr.png`。

### 4. 签发成功直接下载与私钥敏感隔离 (PASS)
- 工作流提交后成功展示完成卡片；
- 界面直接呈现实体证书与完整证书链的独立下载按钮（实测下载按钮数 >= 2）；
- 生成的新私钥明确标记为敏感留存，不混入普通证书下载包；
- 提供“前往材料库”与“完成并关闭”操作；
- **截图证据**：`.tools/simple-mode-evidence/04_cert_success_downloads.png`。

### 5. SM4-CBC 文件加解密 IV 随机生成与原值校验 (PASS)
- **加密操作 (Encrypt)**：
  * 选择对称密钥与输入文件后点击“执行加密”；
  * 前端通过 `window.crypto.getRandomValues` 自动生成 16 字节真随机 IV，转为 32 位十六进制字符串；
  * 实测捕获请求载荷：`{"toolId":"sm4_cbc","parameters":{"key":"key:k1","in":"file:f2","out":"cipher.bin","iv":"1f3c3d22b537ac01d4339f22068cf0da","pkcs7_padding":true,"encrypt":true},"timeoutSeconds":30}`；
  * 连续加密生成的 IV 完全随机且不重复；
  * 结果区直观展示生成的 IV，并提供复制按钮与保存提醒；
  * **截图证据**：`.tools/simple-mode-evidence/05_sm4_encrypt_result_with_iv.png`。
- **解密操作 (Decrypt)**：
  * 切换至解密模式，未填入 IV 时点击执行，前端直接拦截并提示清晰中文错误：`请输入 32 位十六进制初始化向量 (IV)`；
  * 填入合法 32 字符十六进制 IV 后成功提交，载荷包含用户输入的原 IV 与 `pkcs7_padding: true`；
  * **截图证据**：`.tools/simple-mode-evidence/06_sm4_decrypt_iv_validation.png`。

### 6. 高级模式切换平滑无损 (PASS)
- 点击顶栏“高级模式”按钮，平滑切换至高级工作台，左侧 80+ 工具目录完整呈现，无页面重载；
- 点击“简单模式”按钮切回，简单工作台立即恢复，无专业向导或表单残留；
- **截图证据**：`.tools/simple-mode-evidence/07_advanced_mode_dashboard.png`。

### 7. 移动端与小屏幕自适应 (PASS)
- 模拟 375x667 移动端视口 (`mobile: true`)；
- 首屏制作证书大卡片、六大任务网格自适应流式堆叠，各按钮与图标排布规整可点击；
- **截图证据**：`.tools/simple-mode-evidence/08_mobile_simple_workbench.png`。

---

## 三、真实执行证据与产物清单

1. **测试脚本**：`.tools/simple-mode-evidence/test-browser-simple-mode.mjs` (基于 Node.js 原生 WebSocket + CDP，纯本地回环端口 18099 伺服)。
2. **测试环境与版本**：
   - 驱动方式：Google Chrome Headless (CDP)
   - Chrome 版本：`Google Chrome`
   - 静态资源：`web/dist` 最新打包产物
3. **截图清单 (全部 8 张图片保存在 .tools/simple-mode-evidence/)**：
   - `01_desktop_simple_workbench.png`
   - `02_simple_cert_wizard_2_cards.png`
   - `03_step3_quick_issue_no_csr.png`
   - `04_cert_success_downloads.png`
   - `05_sm4_encrypt_result_with_iv.png`
   - `06_sm4_decrypt_iv_validation.png`
   - `07_advanced_mode_dashboard.png`
   - `08_mobile_simple_workbench.png`
4. **摘要日志**：`.tools/simple-mode-evidence/browser-summary.json`。
