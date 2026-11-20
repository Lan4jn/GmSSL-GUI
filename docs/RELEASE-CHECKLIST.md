# 本机首版交付检查单

## 已通过

- [x] Java 微服务与纯浏览器方案一致；无桌面容器或 JCEF 依赖。
- [x] 内置账号、session/CSRF、系统/项目 RBAC、双用户/双项目隔离。
- [x] AES-256-GCM 材料托管、临时文件 CAS 首任务绑定、终态/取消/重启清理与失败周期重试。
- [x] 状态型密钥单一权威、唯一产物晋升、禁复制/原始下载、pending 故障隔离与受控软件恢复实测。
- [x] 80 原生工具操作覆盖与 14 扩展工具分列计数；机器集合差集无遗漏，所有源报告具有可追溯产物身份。
- [x] SM2/SM9 完整双方交换、对称/KDF/MAC、PQC、证书/CSR/CRL/OCSP/SCT/CMS 和协议成对工作流。
- [x] 标准 P256/SHA256 SCT 与 timestamp/LogID 篡改负测；真实 crlgen→crlverify，禁止测试迁就上游错误布局。
- [x] 固定上游未修改，5 overlay 可复现生成与 original/derived SHA-256/diff，catalog 声明派生身份。
- [x] 根 Maven verify、前端 30 单测/typecheck/build、真实 Chrome SM3 完整链路。
- [x] 最终 HTTP 21 PASS、原生 runner 14 PASS、独立状态型重启 3 PASS，真实报告已保存。
- [x] Web 本机入口 HTTP200，Java/web 受管进程持续运行；用户凭据不入交付文本。
- [x] Compose、nginx、PostgreSQL、服务镜像和运维说明交付，并明确未实测生产矩阵。
- [x] 无 Git commit/push。

## 正式上线前目标环境验收

- [ ] 目标 Linux 架构上重建 native、Java 与 Web 镜像并核验许可证与 overlay manifest。
- [ ] 使用真实 PostgreSQL 验证 Flyway、事务/并发 CAS、数据卷备份及恢复。
- [ ] 按 ops/ACCEPTANCE.md 验证 Docker Compose、限制/网络隔离/健康检查及重启行为。
- [ ] 配置生产 HTTPS、Secure cookie、管理员自有凭据与主密钥保管/轮换流程。
- [ ] 明确网络任务目标 IP/端口白名单及受控出站 override；不公开内部 engine API。

硬件 SDF/SKF、OpenSSL provider、SSO 实际接入是后续阶段；QUIC 保持上游实验性子集定位。本次验证不声称所有参数组合、完整 C API、全库 ASan/fuzz 或物理断电均已覆盖。
