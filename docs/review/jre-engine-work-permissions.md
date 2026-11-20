# JRE 引擎用户与 work tmpfs 属主一致性独立核查报告 (task-88)

## 一、验收结论

**判定：PASS（整改复核通过）**
1. **环境变量优先级与对齐**：`scripts/start-with-jre.sh` 严格实现标准 Compose 优先级：`shell export (若非空) > .env > 默认 10001:10001`；无 `source` 或 `eval`，使用安全文本解析；解析后统一导出 `GMSSL_CONTAINER_USER`，保证容器前检探针与 Docker Compose 消费完全一致。
2. **Fail-Closed 严格属主防呆**：增加严格校验，若 `TARGET_USER != "10001:10001"`（包含非 10001 UID、非 10001 GID、单数字格式或非数字名称），直接报错阻断退出（exit 1），绝不静默放行导致运行时 `/work` 重复触发 EPERM。
3. **自动化测试回归**：`tests/deployment` 增加 test_07、test_08、test_09 针对性边界断言后，全套 36 项测试全部通过（exit 0）。
4. **归档条目与权限确认**：最新重装归档包 `deploy/gmssl-gui-linux-0.1.1.tar.gz` (48,789,592 字节, SHA-256: `e855487d...`) 条目及权限完全达标：
   - `start-with-jre.sh` (0755, wrapper 正确指向 scripts/start-with-jre.sh, `bash -n` exit 0)
   - `scripts/start-with-jre.sh` (0755, `bash -n` exit 0)
   - `compose.jre.yaml` (0644)
   - `platform-service-0.1.0-SNAPSHOT.jar` (0644, 26970280 bytes)
   - `engine-service-0.1.0-SNAPSHOT.jar` (0644, 23773048 bytes)
   - `gmssl-runner` (0755, 8048240 bytes)
   - `manifest.json` (0644, version: 0.1.1)
   - `artifacts/` (0755)
5. **安全与环境边界声明**：未修改 Java 源码吞异常，未向容器添加 `CAP_FOWNER` 或特权模式，未引入破坏性 `chown` 或 `chmod 777`；当前宿主机无 Docker daemon，实机容器标记为 `DOCKER_NOT_RUN`。
