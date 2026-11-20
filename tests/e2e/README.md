# 独立端到端验收

仅 Python 标准库，不安装全局依赖，不使用 mock 代替 GmSSL。

## 实际 HTTP

启动 platform/engine 与真实 runner 后，在当前私有 shell 环境设置 E2E_ADMIN_USERNAME、E2E_ADMIN_PASSWORD；避免将实际密码写到 argv、共享终端记录或本仓库文件。

~~~sh
python3 tests/e2e/http_acceptance.py --url http://127.0.0.1:8080 \
  --scan-dir /absolute/app-owned/vault --scan-dir /absolute/app-owned/logs
~~~

测试创建随机前缀两个 USER 和两个项目；不会删除他人资源。凭据只存进程内存。结果写 tests/e2e/results/e2e_*/report.json 和 report.txt。HTTP202不算算法成功；等待终态并比对KAT/明文字节。输出不含SECRET值。

默认覆盖登录/cookie、CSRF、RBAC、双用户/项目、跨项目ref/artifact、私钥下载、SM3、SM4-GCM往返和篡改、SM2加密私钥生成/save-key/签验/错误ID/加解密、任务取消/超时和公共DTO/ps泄漏扫描。--scan-dir仅扫描显式指定目录，不扫描home等无关路径。

状态型pending重启恢复为独立门槛；HTTP伪标材料拦截不算恢复测试。证书/PQC/协议全面验证另需真实分层证据，不因本套件通过宣称完整工具覆盖。

## 原生帧与秘密通道

~~~sh
python3 tests/e2e/native_runner_acceptance.py
~~~

真实runner验证畸形/截断/超长/NUL帧、OS argv拒绝、SM3 KAT、秘密在stdin而不出现在OS argv；不影响业务实例。默认结果写 tests/e2e/results/native_*/report.json。

报告保留PASS/FAIL/SKIP，不隐藏未就绪或失败项。首次只编写未运行时按NOT_RUN处理。
