# JRE 与 Nginx 镜像升级参数及停机前预检独立验收报告 (task-90)

## 一、验收结论

**判定：PASS（整改复核通过）**
1. **初期缺陷整改与核实**：
   - 彻底解决旧包在 `--plan` 模式下新解压目录无 `.env` 导致 `start-with-jre.sh --check-only` 报错 exit 1 的阻断；
   - 归档内 `start-with-jre.sh` 确认支持 `--env-file <path>` 参数；`upgrade.sh:248` 在 plan 阶段真实传入 `--env-file "$OLD_ENV"`，实现只读旧配置与 UID 10001 前检，新目录绝不提前落盘 `.env`。
2. **源码与归档一致性 (cmp exit 0)**：
   - `start-with-jre.sh`（源码 vs deploy vs tar 提取）逐字节全等 (cmp exit 0)；
   - `upgrade.sh`（源码 vs deploy vs tar 提取）逐字节全等 (cmp exit 0)；
   - `platform-service` JAR（26,970,280 bytes）逐字节全等 (cmp exit 0)。
3. **隔离目录解压端到端 real --plan 实测**：
   - 使用解压后包内真实脚本与 Mock Docker 验证：`upgrade.sh --plan` 顺利返回 exit 0；
   - 明确断言：新解压目录未生成 `.env`，旧服务未调用 `stop.sh`，未调用 `compose up`。
4. **自动化测试回归**：
   - `tests/deployment` 全套 39 项测试全部通过（`Ran 39 tests in 0.980s, OK`, exit 0）；
   - `test_06` 采用真实 `start-with-jre.sh` 与 mock docker 验证，无整条脚本桩遗漏。
5. **最新发布归档信息**：
   - 文件：`deploy/gmssl-gui-linux-0.1.2.tar.gz`
   - 大小：`48,790,578` 字节（Oct 21 19:26:10 2026）
   - SHA-256：`beec1f0a9f6db40ff0711e4a34e3813798778966de449be7269de45ec6c81c39`
   - 条目权限：`upgrade.sh` (0755), `scripts/upgrade.sh` (0755), `start-with-jre.sh` (0755), `scripts/start-with-jre.sh` (0755), `compose.jre.yaml` (0644), `artifacts/` (0755), 两 JAR (0644), `gmssl-runner` (0755), `manifest.json` (0644, 0.1.2)。
6. **运行环境边界声明**：
   - 当前宿主机无 Docker 守护进程，容器实机标记为 `DOCKER_NOT_RUN`；未修改生产数据库或用户生产 Vault。
