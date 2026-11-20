# 本地已有 JRE 镜像离线挂载启动独立审查与验收报告

**审查任务**：`task-77` 独立核查本地 JRE 启动脚本的零构建与运行参数  
**审查责任人**：`architecture` (系统架构师 / 独立审查员)  
**审查日期**：2026-10-20  
**综合验收裁定**：**全项通过 (SCRIPTS_PACKAGE_PASS, IMAGES_NOT_BUILT)**  
**审查对象**：
- 启动脚本：`deploy/gmssl-gui-linux-amd64/scripts/start-with-jre.sh` 与顶层包装器 `start-with-jre.sh`
- 运行时编排模板：`deploy/gmssl-gui-linux-amd64/compose.jre.yaml` 与根目录 `compose.jre.yaml`
- 部署测试套件：`tests/deployment/test_deployment_start_with_jre.py`
- 离线说明文档：`docs/离线部署说明.md` 与 `docs/离线更新说明.md`

---

## 一、方案定位与双轨离线架构核验

### 1. 业务场景背景
在严格物理隔离的涉密或离线生产内网环境中，若交付方尚未提前预制成品全量胖镜像包（`gmssl-gui-images-linux-amd64.tar`），但用户内网私有镜像仓库中已备有现成的 Java 21 JRE 基础镜像和 Nginx 镜像。
为满足“无需临时联网构建、直接挂载已编译独立包运行”的紧急上线诉求，系统引入了**本地 JRE 挂载运行第二轨道（方式二）**。

### 2. 双轨架构对比与依赖边界
- **方式一（标准成品镜像包方式）**：
  - 依赖：交付方打包的 `gmssl-gui-images-linux-amd64.tar`；
  - 流程：`docker load -i` 导入成品镜像 -> `docker compose up -d --pull never --no-build`；
- **方式二（本地 JRE 挂载运行方式）**：
  - 依赖：内网已有的 JRE 21 镜像（如 `temurin:21-jre`）与 Nginx 镜像（如 `nginx:1.28-alpine`）；
  - 流程：直接将应用包内的预编译微服务 JAR、Linux ELF `gmssl-runner` 及 `web-dist` 以只读模式挂载至容器中运行；
  - **解耦确认**：方式二完全脱离对未生成之 `gmssl-gui-images-linux-amd64.tar` 的强制依赖，真正实现内网开箱即用。

---

## 二、脚本实现与运行参数深度技术审查 (File:Line 级实证)

### 1. 真实容器运行镜像 (Run-Time Image) vs 编译参数 (Build-Arg)
- **审查核验**：
  - `compose.jre.yaml:5` 与行 38：
    ```yaml
    services:
      engine:
        image: ${GMSSL_JRE_IMAGE:?Set GMSSL_JRE_IMAGE in environment}
        entrypoint: ["java", "-jar", "/app/service.jar"]
      platform:
        image: ${GMSSL_JRE_IMAGE:?Set GMSSL_JRE_IMAGE in environment}
        entrypoint: ["java", "-jar", "/app/service.jar"]
      web:
        image: ${GMSSL_NGINX_IMAGE:-nginx:1.28-alpine}
    ```
  - `start-with-jre.sh:131` 启动命令为：
    ```bash
    docker compose --env-file .env -f compose.jre.yaml up -d --pull never --no-build --force-recreate
    ```
  - **结论**：指定的 JRE 镜像是容器运行时的 **Direct Base Image**，而非构建期参数；启动参数严格携带 `--pull never` 与 `--no-build`，全过程零网络拉取、零本地 Docker build。

### 2. 二进制工件挂载与路径正确性
- **只读挂载保护** (`compose.jre.yaml:8-11, 41-43, 76-78`)：
  - `./artifacts/engine-service-0.1.0-SNAPSHOT.jar:/app/service.jar:ro`
  - `./artifacts/gmssl-runner:/app/gmssl-runner:ro`
  - `./artifacts/GMSSL-LICENSE:/app/GMSSL-LICENSE:ro`
  - `./artifacts/platform-service-0.1.0-SNAPSHOT.jar:/app/service.jar:ro`
  - `./config/nginx.conf:/etc/nginx/conf.d/default.conf:ro`
  - `./artifacts/web-dist:/usr/share/nginx/html:ro`
  - `vault-data:/data` (读写持久卷挂载)
- **挂载完整性**：所有预编译 JAR、原生执行器、前端静态网页与 Nginx 配置均为只读挂载（`:ro`），有效防御容器内潜在的文件破坏或篡改。

### 3. 数据持久卷与 Compose 项目隔离一致性
- `compose.jre.yaml:1` 固定顶层项目名称为 `name: gmssl-gui-release`；
- `compose.jre.yaml:94` 固定私钥持久卷为 `vault-data: {}`（解析为 `gmssl-gui-release_vault-data`）；
- 网络结构 `frontend` 与内部隔离网络 `backend (internal: true)` 完整保留；
- **结论**：方式二与方式一共享完全一致的 Compose 项目名与持久卷，升级或切换运行方式时私钥保险箱与历史数据完全保留，零数据漂移。

### 4. 安全前检与 Fail-Closed 机制
- **离线存在性预检** (`start-with-jre.sh:93-106`)：
  - 调用 `docker image inspect` 本地检查 JRE 与 Nginx 镜像是否存在；若本地缺失立即报错终止，绝不尝试联网 pull；
- **Java 21 版本探测** (`start-with-jre.sh:108-116`)：
  - 容器外探针：`docker run --rm --pull=never "$TARGET_JRE_IMAGE" java -version`；
  - 正则严格校验必须包含 Java 21 特征（`version 21` / `21.x`）；若版本不达标立即拦截并打印清晰报错，拒绝启动；
- **OpenSSL 密码原语前检** (`start-with-jre.sh:118-124`)：
  - 探针：`docker run --rm --pull=never "$TARGET_JRE_IMAGE" openssl version`；
  - 确认基础镜像中存在可执行的 `openssl` 二进制程序（engine 微服务执行 SM2/SM3/SM4 原生调用前置必须）；缺失则明确报错退出；
- **Fail-Closed 保护**：前检失败直接在当前终端以 exit 1 退出，绝不调用 `stop` 杀灭已有运行实例，绝不静默回退。

### 5. CLI 与环境变量优先级及 Shell 安全
- **参数优先级** (`start-with-jre.sh:50, 57`)：
  - JRE 镜像：`--jre-image` (CLI) > `JRE_IMAGE` (ENV) > `GMSSL_JRE_IMAGE` (ENV)；若均未提供，直接以 exit 1 终止；
  - Nginx 镜像：`--nginx-image` (CLI) > `NGINX_IMAGE` (ENV) > `GMSSL_NGINX_IMAGE` (ENV) > 默认 `nginx:1.28-alpine`；
- **Shell 防御**：
  - 严格校验参数非空（`$# -lt 2 || "$2" =~ ^--` 拦截漏传参数值）；
  - 未知参数统一报错拦截；
  - 变量使用双引号完整包裹，杜绝空格路径与参数注入，无任何 `eval` 危险语句。

---

## 三、文档与指引闭环核验

审查员仔细核对了 `docs/离线部署说明.md` 与 `docs/离线更新说明.md`：
- 两份文档第 5 节与第 6 节均清晰划分了【方式一：成品镜像包方式】与【方式二：本地 JRE 挂载方式】；
- 明确标注方式二命令示例：
  ```sh
  bash ./start-with-jre.sh --jre-image my-registry.local:5000/base/temurin:21-jre --nginx-image nginx:1.28-alpine
  ```
- 明确列明前置条件：必须为 Java 21 与具备 OpenSSL 的 JRE 镜像，Nginx 依赖透明交代；
- 明确指出方式二无需提前准备 `gmssl-gui-images-linux-amd64.tar`，为现场运维提供了完整可执行的应急运行通道。

---

## 四、自动化测试套件与执行证据 (33 组全绿)

审查员独立执行了部署测试套件：
- **执行命令**：`python3 -m unittest discover -s tests/deployment -p 'test_*.py' -v`
- **测试结果**：**全量 33 组测试全部通过 (0 Failures, 0 Errors, 耗时 0.511s, exit 0)**；
- **专项测试覆盖** (`test_deployment_start_with_jre.py` 6 组用例)：
  1. `test_01_script_files_exist_and_syntax`：验证 3 处 `start-with-jre.sh` 脚本存在且通过 `bash -n` 语法校验；
  2. `test_02_compose_jre_yaml_exists_and_valid`：验证 `compose.jre.yaml` 包含必要的 JRE 镜像变量、工件挂载与持久卷；
  3. `test_03_help_flag`：验证 `--help` 完整展示 `--jre-image`、`--nginx-image` 与环境变量用法；
  4. `test_04_missing_jre_image_arg_fails_immediately`：验证缺失 JRE 镜像参数或环境时以非零退出并提示错误；
  5. `test_05_mock_docker_captures_correct_compose_call`：Mock Docker 沙箱实测捕获并验证镜像探测、Java/OpenSSL 探针及 Compose 启动参数（`-f compose.jre.yaml --pull never --no-build --force-recreate`）；
  6. `test_06_package_script_includes_start_with_jre`：验证打包脚本 `package-linux-amd64.sh` 将 `start-with-jre.sh` 与 `compose.jre.yaml` 纳入发布归档。

---

## 五、环境实测限制客观披露 (IMAGES_NOT_BUILT)

- **宿主限制声明**：当前审查宿主机为 macOS ARM64 环境，未安装 Docker Engine，所有 Docker 操作均在独立 Mock 沙箱中进行参数捕获与断言校验；
- **交付包状态声明**：当前归档包含完备的预编译独立运行脚本、编排文件、静态资源与二进制工件，裁定标定为 **`SCRIPTS_PACKAGE_PASS, IMAGES_NOT_BUILT`**，绝不假称已在测试宿主机物理运行真实容器。

---

## 六、终审裁定

- **裁定状态**：**通过 (PASS)**
- **结论**：
  `task-76` 实施的本地 JRE 挂载启动方案设计严密、运行参数规范、前检防御扎实，为完全脱离外网且未预制镜像包的极端内网环境提供了真正零构建、零外网拉取、数据不丢失的生产级启动方案。
