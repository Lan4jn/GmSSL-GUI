# GmSSL GUI Linux (amd64) 独立预编译部署包终审报告

**审查任务**：`task-30` 独立审查预编译 Linux 部署包  
**审查责任人**：`architecture` (独立审查员)  
**审查基准提交/工件**：
- 部署包根目录：`deploy/gmssl-gui-linux-amd64/` (30 个文件，解压约 60MB)
- 发布归档压缩包：`deploy/gmssl-gui-linux-amd64.tar.gz` (46MB)
- 归档外部指纹：`deploy/gmssl-gui-linux-amd64.tar.gz.sha256` (`dcb39d9104300c74a6553e300fd2564271eafc13436f04373bbc93f2781407b5`)
- 打包构建脚本：`scripts/package-linux-amd64.sh`
- 自动化测试套件：`tests/deployment/` (`test_deployment_package.py`, `test_scripts_syntax_and_idempotency.py`)
**审查日期**：2026-10-19  
**审查结论**：**通过 (PASS) - 具备发布与交付条件**

---

## 一、审查背景与目标边界

根据 `task-30` 验收要求，本审查在不修改业务源码、不启停开发环境现有服务、不读取现有私有 `.env*` 文件的前提下，对 `build-quality` 与 `integration` 协作交付的 `deploy/gmssl-gui-linux-amd64` 目录、打包流程、安全基准及管控脚本进行独立复核。

本终审报告以最新自检数组修订（Bash array 路径防切分、`printf '%b'` 二进制帧及启动后 KAT 指令）与重新打包后的全新归档作为最终签字身份。

---

## 二、最终核心工件身份与 SHA-256 审计指纹

| 工件路径 | 规格大小 | 最终 SHA-256 校验和 | 属性与核验证据 |
| :--- | :--- | :--- | :--- |
| `artifacts/gmssl-runner` | 8,048,240 字节 (7.7M) | `e3d886bb77b965ef8bab92245f813bae829e3d3edbfb114980d6487d8592eb2b` | **Linux x86_64 ELF** (musl 静态链接, Release, 关闭汇编分支, 通用便携基线) |
| `artifacts/engine-service-0.1.0-SNAPSHOT.jar` | 23,773,048 字节 (23M) | `bfc0809ae5af88541a6ffc9ee07c0e14d4e52bdde27c36e1d1046dde05be3950` | Spring Boot 3 Engine 引擎微服务 |
| `artifacts/platform-service-0.1.0-SNAPSHOT.jar` | 26,991,298 字节 (26M) | `0ced6020a92d040dfc5eba94211be80438e2734fd3dc3c1d250d7d382e41edd9` | Spring Boot 3 Platform 业务管理服务 |
| `artifacts/web-dist/` | 目录 (包含 index.html & assets) | - | Vite + Vue 3 生产静态构建产物（含最新证书向导生产静态资源） |
| `artifacts/GMSSL-LICENSE` | 11,358 字节 | - | Apache License 2.0 完整授权文本（锁定可靠源） |
| `manifest.json` | 2,752 字节 | `cfd78f4b50c18d45b4bf3cb682fb453fa87900b17161bcfc2a046cfa67123aa2` | 版本及基础镜像清单，已被 `SHA256SUMS` 覆盖 |
| `SHA256SUMS` | 2,217 字节 | - | 覆盖部署包内全部 29 个关键文件，校验一致性 100% |
| `gmssl-gui-linux-amd64.tar.gz` | 46MB | `dcb39d9104300c74a6553e300fd2564271eafc13436f04373bbc93f2781407b5` | 生产发布归档压缩包（最终锁定指纹） |

*指纹演变记录：早期基于宿主加速分支编译的临时工件（6c7d9867...）已作废，上一轮快照归档（8e178aee...）因 verify-native.sh 数组修订已更新，当前最终发布指纹严格锁定为 `dcb39d9104300c74a6553e300fd2564271eafc13436f04373bbc93f2781407b5`。*

---

## 三、独立核验实测证据清单

### 1. 敏感信息排查与源码排除审计 (Zero Secrets & Leaks)
- **实测方法**：递归遍历解压目录与发布 tar 归档内的所有 30 个文件，匹配私有文件、源码扩展名与符号链接。
- **实测结果**：
  - 私有环境变量：**0 个泄漏**（仅包含带有清晰占位符说明的 `.env.example`，无任何真实私有 `.env` 文件）。
  - 凭据文本：**0 个泄漏**（无 `credentials.txt`）。
  - 数据库开发文件：**0 个泄漏**（无任何 `.mv.db` 文件）。
  - 依赖与临时目录：**0 个泄漏**（无 `node_modules`, `.git`, `.tools`, `.runtime`）。
  - 源码与工程清单：**0 个泄漏**（无 `.java`, `.ts`, `.vue`, `.c`, `.h`, `pom.xml`, `package.json`）。
  - 符号链接逃逸：**0 个逃逸**（部署包内无任何指向部署目录外部的软链接）。
- **判定**：**PASS**

### 2. 原生执行器 ELF 结构核验与便携构建基线
- **实测工具**：Python struct 二进制魔数解析、`file` 与 `objdump -f` 检验。
- **实测输出**：
  - `Magic`: `7f 45 4c 46` (`\x7fELF`)
  - `EI_CLASS`: `2` (ELFCLASS64, 64-bit)
  - `EI_DATA`: `1` (ELFDATA2LSB, Little Endian)
  - `e_machine`: `0x3E` (EM_X86_64, Advanced Micro Devices X86-64)
  - `file` 描述：`ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, with debug_info, not stripped`
  - `Mach-O` 辨识：**False**（完全排除开发机 macOS 二进制混入）。
  - 便携基线：遵循 `ops/engine.Dockerfile` 基线，CMAKE_BUILD_TYPE=Release，关闭 SM2_AMD64 / SM3_SSE / SM4_AVX2 等加速分支，Zig + musl 纯静态链接，无 Linux glibc 动态版本符号绑定。
- **判定**：**PASS**

### 3. 微服务 JAR 与 Web 生产静态资源核验
- **实测输出**：
  - `engine-service-0.1.0-SNAPSHOT.jar` 与 `platform-service-0.1.0-SNAPSHOT.jar` 结构完整。
  - `web-dist` 静态资源包含带有哈希命名的 JS/CSS（如 `CertificateWizard-*.js`，包含真实 SAN 多类型输入与 ASCII 安全文件名校验），生产部署开箱即用。
- **判定**：**PASS**

### 4. 校验和闭环与清单完整性
- **实测结果**：
  - `SHA256SUMS` 覆盖 29 个文件（包含 `manifest.json` 本身）。
  - 自动化哈希重算对比：**0 mismatches, 100% 匹配**。
  - 篡改测试证明：修改 `manifest.json` 任一字节即刻导致 `check.sh` 校验失败并拦截，无校验盲区。
- **判定**：**PASS**

### 5. .dockerignore 凭据泄露防护
- **实测核验**：
  - 部署包根目录已包含 `.dockerignore`，默认全屏蔽 (`*`)，仅放行 `docker/`, `config/`, `artifacts/`。
  - 即使后续运维人员在部署根目录下执行 `./init.sh` 生成了包含明文密码的 `.env` 或 `credentials.txt`，在执行 `docker compose build` 时亦绝对不会将敏感密钥传输进 Docker daemon 上下文。
- **判定**：**PASS**

### 6. Compose 架构锁定与 Nginx 版本一致性
- **实测核验**：
  - `compose.yaml` 针对 `postgres`, `engine`, `platform`, `web` 所有 4 个服务显式统一声明 `platform: linux/amd64`，杜绝跨平台拉取或构建异常。
  - `docker/web.Dockerfile` 基础镜像统一声明为 `nginx:1.28-alpine`，保持全工程镜像版本规约一致。
- **判定**：**PASS**

### 7. 容器权限与运行行为范围核验
- **实测核验**：
  - **Java 微服务容器**：`engine` 与 `platform` 的 Dockerfile 均建立专用非 root 用户组：`groupadd --gid 10001 gmssl && useradd --uid 10001 --gid gmssl ...` 并以 `USER 10001:10001` 运行；在 `compose.yaml` 中均声明 `read_only: true`，其中 `engine` 以 tmpfs 挂载 `/work`。
  - **基础组件容器**：`nginx` (`nginx:1.28-alpine`) 与 `postgres` (`postgres:17-alpine`) 均采用各自官方镜像的默认启动用户与标准运行时行为（未生搬硬套 10001 用户，保证官方入口脚本初始化与权限平稳执行）。
  - `compose.yaml` 开启安全基线：`cap_drop: [ALL]`、`security_opt: ["no-new-privileges:true"]`、`pids_limit: 128`、`mem_limit: 1g`。
- **判定**：**PASS**

### 8. check.sh 宿主与自检防护 (Fail-Closed)
- **实测核验**：
  - 缺少 `SHA256SUMS` 文件时，`check.sh` 实行 **fail-closed** 策略：直接输出错误并以返回码 1 退出，绝不静默放行。
  - 宿主系统架构检查：非 Linux x86_64 宿主（例如 macOS 或 aarch64）执行时强制报错拦截，除非显式指定 `ALLOW_CROSS_CHECK=1` 用于测试。
- **判定**：**PASS**

### 9. init.sh 幂等双文件保护与软链防护
- **实测核验**：
  - 独立沙箱测试表明：初次运行生成 `.env` 与 `credentials.txt`，权限严格设为 `0600` (`-rw-------`)。
  - 当 `.env` 或 `credentials.txt` **任一文件已存在**时，`init.sh` 立即输出 `[INFO] Existing configuration retained` 并以状态码 1 退出，**坚决不重新生成新的主密钥**，保护已有数据卷可解密性。
  - 脚本开启 `set -C` (noclobber)，并主动拦截软链接 (`-L`) 攻击，防止通过软链覆写宿主敏感路径。
- **判定**：**PASS**

### 10. start.sh 启动探测与 HTTPS/Secure Cookie 说明
- **实测核验**：
  - `start.sh` 在 `docker compose up -d` 之后调用 `status.sh` 轮询服务就绪状态。
  - 脚本明确提醒：默认开启 `GMSSL_SESSION_COOKIE_SECURE=true`，如果直接通过 HTTP 访问，现代浏览器将拒绝保存 Cookie 导致登录无状态；提示运维人员配置前端 TLS 终止反向代理（推荐），或通过安全上下文（localhost/127.0.0.1）访问。
- **判定**：**PASS**

### 11. stop.sh 持久化卷保留验证
- **实测核验**：
  - `stop.sh` 仅执行 `docker compose stop`，脚本中绝无 `down -v`，绝无 `volume rm`，证明其设计行为严格保证保留 `postgres-data` 与 `vault-data` 两个关键持久化数据卷。
- **判定**：**PASS**

### 12. README 生产备份一致性与 LMS/HSS 状态密钥规约
- **实测核验**：
  - `README.md` 明确严禁热拷贝正在运行的 PostgreSQL 目录（避免物理块撕裂）。
  - 提供规范的冷备方案（`./stop.sh` 后挂载卷 tar）与在线逻辑备份方案（`pg_dump`）。
  - 增补容器启动后的底层密码算法 KAT 验证指令：`./scripts/verify-native.sh`。
  - 详细阐明：抗量子状态型签名算法（LMS/HSS）的一次性私钥索引状态绑定当前实例，严禁跨数据库恢复旧状态；以及开发 H2 数据库文件严禁直接拷贝到 PostgreSQL。
- **判定**：**PASS**

### 13. package-linux-amd64.sh 打包安全与兼容性
- **实测核验**：
  - GMSSL-LICENSE 锁定专用文件路径，去除了对根目录未审查 LICENSE 的不可靠回退。
  - 在清理与复制 `web-dist` 前，采用 `pwd -P` 真实路径判定与 `-L` 软链检查，杜绝穿越逃逸。
  - 检查命令采用 Linux GNU find 与 macOS BSD find 均完全兼容的安全语法，无 `-perm +111` 语法报错。
- **判定**：**PASS**

### 14. 原生 KAT SM3 标准自检脚本与路径空格鲁棒性
- **实测核验**：
  - 部署包包含 `scripts/verify-native.sh`，内置固定测试向量 SM3("abc") 的 GMRUN001 二进制帧，期望哈希 `66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0`。
  - 参数传递全面采用 Bash 数组：`TARGET_CMD=("$@")` 与 `"${TARGET_CMD[@]}"`，彻底消除路径或参数含空格时的切词断裂。
  - 帧字节采用 `printf "%b"` 安全转义输出。
  - 自动化测试覆盖：含空格路径的正向 mock 验证、非零退出码负向拦截、错误输出哈希负向拦截，全部通过。
- **判定**：**PASS**

### 15. 自动化测试套件回归 (tests/deployment/)
- **实测核验**：
  - 运行 `python3 -m unittest discover -s tests/deployment -p 'test_*.py' -v`
  - 实测输出：**13 组测试用例在 1.412s 内全部通过 (exit 0)**。
- **判定**：**PASS**

---

## 四、测试环境边界与运行说明 (Limitations)

为确保交付结论真实严谨，本审查明确记录以下环境事实：
1. **测试机环境状态**：
   - 当前审查执行机为 macOS 开发宿主环境，宿主机未安装/未启用 Docker 守护进程（`docker: command not found`）。
   - **审查充分性说明**：本审查全部基于深度静态审计、二进制 file / readelf / objdump 头部解析、魔数与结构分析、跨架构白盒逻辑测试、沙箱目录幂等模拟运行、SHA256 完整性闭环以及 13 组专用 deployment 测试验证。
   - **实测边界明确记录**：**未在当前测试机进行容器实例化联测**。部署配置面向满足包内 README 要求的 Linux x86_64 与 Compose V2 主机；目标机仍应执行启动、状态检查与 SM3 KAT，真实容器运行结果以目标机验收为准。
2. **首次部署外部依赖披露**：
   - 本部署包采用预编译工件交付（轻量化 46MB），非离线 Fat Image（未内嵌几百兆的通用基础镜像层）。
   - 首次在 Linux 机器上拉起时，需要宿主机网络可连通公共镜像源拉取 `eclipse-temurin:21-jre-jammy`, `postgres:17-alpine`, `nginx:1.28-alpine` 基础镜像，且需安装 `openssl` 用于初次随机令牌生成。该要求已在部署包 `README.md` 中向用户醒目披露。

---

## 五、终审裁定与交接结项

- **终审裁定结论**：**通过 (PASS)**
- **阻塞性问题 (Blockers)**：**0 项**
- **最终发布归档校验指纹**：
  ```
  dcb39d9104300c74a6553e300fd2564271eafc13436f04373bbc93f2781407b5  deploy/gmssl-gui-linux-amd64.tar.gz
  ```
- **结论概述**：
  `deploy/gmssl-gui-linux-amd64` 部署包结构完备、工件真实有效、架构对齐便携规范、零敏感信息残留、Java 微服务权限严格、管控脚本鲁棒且幂等，全套部署自检测试通过，符合独立带走交付标准。
