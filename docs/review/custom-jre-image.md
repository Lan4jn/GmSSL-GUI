# 自定义 JRE 基础镜像与最终应用包同步独立验收报告

**审查任务**：`task-60` 独立核查自定义 JRE 参数与最终应用包同步  
**审查责任人**：`architecture` (系统架构师 / 独立审查员)  
**审查日期**：2026-10-20  
**综合验收裁定**：**分层通过 (SCRIPTS_PACKAGE_PASS, IMAGES_NOT_BUILT)**  
**审查对象**：
1. JRE 基础镜像可变参数支持与 Dockerfile 声明 (`task-59`)
2. 离线制包工具链 `build-offline-images.sh` 参数优先级与参数校验
3. 最终发布归档包工件完整性（新密码平台 JAR、两份离线说明、最新前端 dist）
4. 无文件哈希门禁与内网纯离线运行时约束

---

## 一、Dockerfile 基础 JRE 参数声明核验 (ARG BEFORE FROM)

审查员逐一核对了工程中全部 4 处 Java 运行时 Dockerfile：

| Dockerfile 路径 | ARG 声明位置 | FROM 引用格式 | 阶段属性 |
| :--- | :--- | :--- | :--- |
| `ops/engine.Dockerfile` | 行 23 (`ARG BASE_JRE_IMAGE=eclipse-temurin:21-jre-jammy`) | 行 24 (`FROM ${BASE_JRE_IMAGE}`) | 多阶段构建之运行时阶段 (native/java 构建阶段之后) |
| `ops/platform.Dockerfile` | 行 9 (`ARG BASE_JRE_IMAGE=eclipse-temurin:21-jre-jammy`) | 行 10 (`FROM ${BASE_JRE_IMAGE}`) | 多阶段构建之运行时阶段 (build 阶段之后) |
| `deploy/docker/engine.Dockerfile` | 行 1 (`ARG BASE_JRE_IMAGE=eclipse-temurin:21-jre-jammy`) | 行 2 (`FROM ${BASE_JRE_IMAGE}`) | 预编译独立部署包专用运行时 Dockerfile |
| `deploy/docker/platform.Dockerfile` | 行 1 (`ARG BASE_JRE_IMAGE=eclipse-temurin:21-jre-jammy`) | 行 2 (`FROM ${BASE_JRE_IMAGE}`) | 预编译独立部署包专用运行时 Dockerfile |

**审查实据**：
- 4 处 Dockerfile 均严格遵守 Docker 规范，将 `ARG BASE_JRE_IMAGE` 声明于目标运行时阶段的 `FROM ${BASE_JRE_IMAGE}` 正前方；
- 默认值统一为标准 `eclipse-temurin:21-jre-jammy`（Java 21 JRE, Ubuntu Jammy 底座）；
- 构建命令通过 `--build-arg BASE_JRE_IMAGE=...` 传入自定义镜像时，Docker 引擎可精确解析生效。

---

## 二、离线镜像构建脚本参数规范与优先级审查 (`build-offline-images.sh`)

审查员对 `scripts/build-offline-images.sh` 与 `deploy/gmssl-gui-linux-amd64/build-offline-images.sh` 进行了两份副本一致性比对与逐行代码审查：

### 1. 副本完全一致性 (Zero Diff)
- `diff -u scripts/build-offline-images.sh deploy/gmssl-gui-linux-amd64/build-offline-images.sh` 比对结果返回码为 0，内容 100% 逐字吻合。

### 2. 严格优先级与防隐式回退机制
- **代码实现** (`build-offline-images.sh:71`)：
  ```bash
  EFFECTIVE_JRE="${CUSTOM_JRE:-${JRE_IMAGE:-"eclipse-temurin:21-jre-jammy"}}"
  ```
- **优先级验证**：
  1. CLI 显式参数 `--jre-image <image>` 具有最高优先级；
  2. 未提供 CLI 参数时，降级采用环境变量 `JRE_IMAGE`；
  3. 两者均未指定时，采用默认值 `eclipse-temurin:21-jre-jammy`。
- **无隐式回退**：用户显式指定的任何非空参数（包括私有镜像仓库端口、特定 tag 或 digest）均直接赋给 `CUSTOM_JRE`，脚本绝不静默改写或偷偷回退为默认 Temurin 镜像。

### 3. 构建参数双传值核查
- **代码实现** (`build-offline-images.sh:91-104`)：
  ```bash
  # 1. Engine 服务构建
  docker build --platform linux/amd64 \
    --build-arg BASE_JRE_IMAGE="$EFFECTIVE_JRE" \
    -t "$TAG_ENGINE" \
    -f "$DEPLOY_DIR/docker/engine.Dockerfile" \
    "$DEPLOY_DIR"

  # 2. Platform 服务构建
  docker build --platform linux/amd64 \
    --build-arg BASE_JRE_IMAGE="$EFFECTIVE_JRE" \
    -t "$TAG_PLATFORM" \
    -f "$DEPLOY_DIR/docker/platform.Dockerfile" \
    "$DEPLOY_DIR"
  ```
- **审查结论**：两个 Java 微服务镜像的构建命令均完整传入了 `--build-arg BASE_JRE_IMAGE="$EFFECTIVE_JRE"`，无遗漏且传值完全一致。

### 4. 健壮性与边界异常防御
- **参数缺失拦截**：传递 `--jre-image` 但未提供值时，脚本输出 `[ERROR] Missing value for --jre-image` 并以 exit 1 终止；
- **未知参数拦截**：传递非法参数时，输出 `[ERROR] Unknown argument` 并以 exit 1 终止；
- **复杂镜像引用支持**：支持包含主机端口（如 `my.registry:5000/java:21`）、路径及 digest（`@sha256:...`）的镜像全名，Shell 变量全部采用安全双引号引用，防范空格与参数分词漏洞。

### 5. 依赖前提与兼容性声明客观性
- 脚本帮助信息明确披露兼容性前提：
  - 必须为 **Java 21+ on Linux amd64**；
  - `engine` 运行镜像依赖基于 Debian/Ubuntu 的基础镜像，需具备 `apt` 包管理器以安装 `openssl` CLI 与 `ca-certificates`，以及具备 `groupadd`/`useradd` 工具与对 `/app`、`/work` 的读写权限；
  - 明确提示：精简版 Alpine / BusyBox / UBI 镜像若缺少 `apt` 或用户管理命令，构建阶段将直接清晰报错，**严谨声明不提供未经适配的任意非 Debian JRE 基础镜像的通用兼容**，杜绝过度承诺。

---

## 三、最终发布包工件同步核验 (Artifacts Alignment)

审查员对 `deploy/gmssl-gui-linux-amd64.tar.gz` 内部实际打包文件与工程源文件进行了逐项指纹比对：

### 1. 平台后端 JAR (`platform-service-0.1.0-SNAPSHOT.jar`)
- **源码编译产物** (`platform-service/target/platform-service-0.1.0-SNAPSHOT.jar`)：
  - 字节大小：`26,968,155` 字节
  - SHA-256：`70389ed02ad80aa40012a9374e83e5c46c65ebbfe3589fff3933b84965d6b8d7`
- **部署包解压目录** (`deploy/gmssl-gui-linux-amd64/artifacts/platform-service-0.1.0-SNAPSHOT.jar`)：
  - 字节大小：`26,968,155` 字节
  - SHA-256：`70389ed02ad80aa40012a9374e83e5c46c65ebbfe3589fff3933b84965d6b8d7`
- **发布归档内部文件** (`tarfile extract`)：
  - 字节大小：`26,968,155` 字节
  - SHA-256：`70389ed02ad80aa40012a9374e83e5c46c65ebbfe3589fff3933b84965d6b8d7`
- **核实结论**：
  三处工件字节大小与 SHA 校验和**100% 逐字节对齐**！该 JAR 为最新支持无长度限制 PBKDF2 密码策略的版本（经 `platform-service` 真实实跑 50 项测试全绿验证通过，作者早前口头报告中笔误提及的“46 tests”系历史笔记口径，实测确认为 50 项测试全量通过）。

### 2. 两份独立离线说明入包核验
审查员从发布压缩包 `deploy/gmssl-gui-linux-amd64.tar.gz` 内部解压提取核验：
- `gmssl-gui-linux-amd64/离线部署说明.md`：8,311 字节，确已纳入包根目录；
- `gmssl-gui-linux-amd64/离线更新说明.md`：9,261 字节，确已纳入包根目录。
- 内容核验：两份说明均以“离线介质已经送达现场”为前提，全流程零外网依赖，不含在线制包或外网下载步骤。

### 3. 前端静态资源 (`web-dist`)
- 包含最新的证书快捷向导成功页直接下载、敏感私钥独立确认及前往密钥库真实页面切换功能产物（经 `task-51` 真实无头 Chrome 浏览器验证通过）。

### 4. 彻底消除文件哈希门禁
- 经全包递归扫描，归档内部及发布目录同级彻底无 `SHA256SUMS` 与 `.tar.gz.sha256` 文件，各 Shell 启动脚本与升级脚本均无哈希拦截门禁，100% 遵循用户硬性要求。

### 5. 真实离线镜像胖包状态客观披露 (IMAGES_NOT_BUILT)
- 当前测试与构建宿主机为 macOS ARM64 环境，且宿主机未运行 Docker Engine 守护进程；
- 包含全部三个服务运行镜像的离线归档（`gmssl-gui-images-linux-amd64.tar`）**未在当前测试机物理导出**；
- 验收裁定明确标定为 **`SCRIPTS_PACKAGE_PASS, IMAGES_NOT_BUILT`**，绝不假称离线镜像胖包已在本机物理生成。

---

## 四、全系统回归测试与命令证据 (213 项全绿)

审查员独立运行了全系统各层测试套件，执行命令与退出码实据如下：

1. **部署与 JRE 参数单元测试套件**：
   - 执行命令：`python3 -m unittest discover -s tests/deployment -p 'test_*.py' -v`
   - 结果：**27 组测试全部通过 (0 Failures, 0 Errors, 耗时 0.480s, exit 0)**；
   - 专项覆盖：`test_deployment_jre_selection.py` 包含 5 项核心用例：
     * `test_01_dockerfiles_have_arg_base_jre_before_from`：4 处 Dockerfile 均含 `ARG BASE_JRE_IMAGE` 与 `FROM ${BASE_JRE_IMAGE}`；
     * `test_02_build_script_help_and_syntax`：`bash -n` 语法校验与 `--help` 校验；
     * `test_03_mock_docker_captures_explicit_cli_jre_image`：Mock Docker 捕获显式 CLI 镜像参数完整注入两个 build 命令；
     * `test_04_priority_cli_over_env_over_default`：验证 CLI > ENV > 默认优先级且不回退；
     * `test_05_error_handling_missing_jre_arg_value`：验证参数缺失时报错退出。
2. **后端 Java 单元与集成测试套件**：
   - 平台服务：`scripts/mvn.sh -pl platform-service test`：**50 组测试全部通过 (BUILD SUCCESS, exit 0)**；
   - 引擎服务：`scripts/mvn.sh -pl engine-service test`：**29 组测试全部通过 (BUILD SUCCESS, exit 0)**；
   - 后端合计：50 + 29 = **79 组测试全绿**。
3. **前端 Vitest 单元测试套件**：
   - 执行命令：`pnpm --dir web test:run`：**107 组测试全部通过 (耗时 985ms, exit 0)**。
4. **全工程自动化测试总数**：27 (部署) + 79 (Java) + 107 (前端) = **213 组测试全部通过 (exit 0)**。

---

## 五、终审裁定与交付结论

- **裁定状态**：**分层通过 (SCRIPTS_PACKAGE_PASS, IMAGES_NOT_BUILT)**
- **结论**：
  `task-59` 针对用户自定义 JRE 基础镜像的改动严格规范、接口收敛、前置依赖条件明确无虚假宣传，构建脚本优先级分明且具备严格的异常防御；发布归档文件已完整纳入最新 PBKDF2 密码平台 JAR、两份独立离线说明与最新前端产物，包内外彻底无文件哈希拦截，全工程 213 组测试全部通过，具备交付验收条件。
