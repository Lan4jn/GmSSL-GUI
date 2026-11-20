# 独立验收矩阵

**基线版本**：docs/PLAN.md、docs/contracts.md、upstream commit `24ae482701a7b124826c382fffc55c19f76d475d` (GmSSL v3.3.0-dev.1183)  
**当前 Runner 版本**：commit `36a05a...` (含 5 overlay 原生补丁)  
**更新日期**：2026-10-16  
**审查员**：独立审查员 (teammate `architecture`)  

状态口径：**PASS** 仅限实际执行成功并留存真实机器可读报告；**FAIL** 为已复现缺陷/断言失败；**SKIP** 仅限有独立受控测试套件覆盖或契约豁免项。严禁将 mock、存在性检查或简单帮助信息当作真实算法/业务通过证据。

---

## 1. 验收测试项矩阵与实测通过记录

| 测试编号 | 测试分类 | 核心验证要求与契约边界 | 验收手段 | 最终实测状态 | 证据路径 / 报告 |
|---|---|---|---|---|---|
| **AUTH-01** | 身份认证 | 未登录访问受保护接口一律返回 401 | HTTP | **PASS** | `tests/e2e/results/e2e_da8dcd9d89/report.json` |
| **AUTH-02** | 身份认证 | 双独立真实 USER 账号登录，Cookie 设 HttpOnly/SameSite=Strict，项目空间严格隔离；94 个能力工具完整加载 | HTTP | **PASS** | `tests/e2e/results/e2e_da8dcd9d89/report.json` |
| **AUTH-03** | 身份认证 | CSRF 拦截（缺/错 Token 报 403，合法放行） | HTTP | **PASS** | `tests/e2e/results/e2e_da8dcd9d89/report.json` |
| **AUTH-04** | 会话生命周期 | 注销 (`/auth/logout`) 与账号禁用 (`enabled: false`) 后现有会话立即失效 (401) | HTTP | **PASS** | `tests/e2e/results/e2e_da8dcd9d89/report.json` |
| **RBAC-01** | 访问控制 | 系统角色隔离，保护最后一个项目 OWNER 禁止被移除或降级 (400/403/409) | HTTP | **PASS** | `tests/e2e/results/e2e_da8dcd9d89/report.json` |
| **RBAC-02** | 访问控制 | 项目 VIEWER 允许读列表但禁止提交任务/上传文件/下载私钥；EDITOR 正常执行 | HTTP | **PASS** | `tests/e2e/results/e2e_da8dcd9d89/report.json` |
| **ISO-01/02/03** | 资源隔离 | 用户 A 与项目 A 无法引用项目 B 的密钥/文件 (400/403/404) | HTTP | **PASS** | `tests/e2e/results/e2e_da8dcd9d89/report.json` |
| **ISO-04** | 产物隔离 | 跨项目无法读取或下载他人任务详情与产物文件 (403/404) | HTTP | **PASS** | `tests/e2e/results/e2e_da8dcd9d89/report.json` |
| **INPUT-01** | 参数安全 | 未知参数、路径穿越 (`../`)、绝对路径与畸形 HEX 校验阻断 (400) | HTTP | **PASS** | `tests/e2e/results/e2e_da8dcd9d89/report.json` |
| **FILE-01** | 临时文件 | `temporary=true` 文件 DTO 正确、KEY 类型上传拒绝 (400)、CAS 绑定首个任务（二次消费报 409/400/404）；任务终态后自动物理删除 DB 记录与 vault 密文 (404)；任务排队/运行中取消自动删除临时文件 (404)；普通永久文件保持可用且内容不变 | HTTP | **PASS** | `tests/e2e/results/e2e_da8dcd9d89/report.json` |
| **CRYPTO-01** | 真实算法 | 真实 SM3 "abc" KAT 校验 (`66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0`) | HTTP→runner | **PASS** | `tests/e2e/results/e2e_da8dcd9d89/report.json` |
| **CRYPTO-02** | 真实算法 | 真实 SM4-GCM 128-bit 密钥与 IV 加解密往返，密文单字节篡改后解密失败校验 | HTTP→runner | **PASS** | `tests/e2e/results/e2e_da8dcd9d89/report.json` |
| **CRYPTO-03** | 真实算法 | SM2 生成 PEM 密钥对，受控 Save-Key、加密解密往返、签名验签及错误 ID 验签失败 | HTTP→runner | **PASS** | `tests/e2e/results/e2e_da8dcd9d89/report.json` |
| **STATE-01** | 状态型签名 | 状态型工具拒绝普通私钥和临时文件伪标；前置参数拦截 | HTTP | **PASS** | `tests/e2e/results/e2e_da8dcd9d89/report.json` |
| **STATE-02** | 状态型权威 | 受控 LMS 生成/首签；外部导入/降级复制拒绝；`stateful_promotions` tombstone 防重复晋升 | HTTP | **PASS** | `tests/e2e/results/e2e_da8dcd9d89/report.json` |
| **STATE-03** | 状态型恢复 | 隔离 platform 实例注入未决 pending 与 RUNNING，重启验证原任务转 FAILED、pending 标记跨生命周期持久保留且阻止后续签名产物泄露 (注：软件恢复验证，不等同物理断电证明) | 独立测试套件 | **PASS** | `tests/e2e/results/restart_18958922c3/report.json` |
| **JOB-01** | 任务调度 | 运行中慢任务请求取消，子进程正常终止且终态置为 CANCELLED | HTTP/ps | **PASS** | `tests/e2e/results/e2e_da8dcd9d89/report.json` |
| **JOB-02** | 任务调度 | 慢任务达到超时阈值后自动终止，终态置为 TIMED_OUT，无僵尸进程残留 | HTTP/ps | **PASS** | `tests/e2e/results/e2e_da8dcd9d89/report.json` |
| **JOB-03** | 任务调度 | 单项目/系统线程池与队列容量打满后，超额任务立即拒绝 (429)；排队任务取消与终止校验 | HTTP | **PASS** | `tests/e2e/results/e2e_da8dcd9d89/report.json` |
| **ENGINE-01** | 内部安全 | engine 服务对缺省或错误 `X-Engine-Token` 请求一律返回 401 | 内部 HTTP | **PASS** | `tests/e2e/results/e2e_da8dcd9d89/report.json` |
| **NETWORK-01**| 网络策略 | 阻断内网敏感 IP (169.254/环回)、非白名单端口；监听必须>=1024+allowlist；出站支持1..65535显式白名单授权 | 内部 HTTP | **PASS** | `tests/e2e/results/e2e_da8dcd9d89/report.json` |
| **SECRET-01/02**| 敏感信息 | 接口 DTO/审计脱敏；ps 命令行实时监测无敏感参数；深度扫描 238 个持久化/日志文件无明文密钥 | 审计+扫盘+ps | **PASS** | `tests/e2e/results/e2e_da8dcd9d89/report.json` |
| **RUNNER-01** | 原生协议 | 11 类畸形 magic/version/截断/超长/NUL 协议帧拒绝；禁止任意 OS argv；长任务 stdin 秘密参数在 OS argv 脱敏 (ps 监测) | 原生单测 | **PASS** | `tests/e2e/results/native_089e9379fe/report.json` |
