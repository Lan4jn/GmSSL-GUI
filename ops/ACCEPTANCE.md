# task-4 工具链与部署验收

## 交付边界
根 `pom.xml`、`.gitignore`、`.dockerignore`、`scripts/{bootstrap-tools,bootstrap-config,mvn,dev}.sh`、`compose.yaml`、`ops/`。未修改业务模块，未安装系统依赖、未 commit/push。共享服务启动为后续联调，非以下验收的前提。

## 实测
- 系统 `/usr/libexec/java_home -V` 及标准 JVM 路径只有 Corretto8；Maven/Gradle/Docker CLI 缺失。
- 工作区 `.tools/jdk-21.0.12.1+1/Contents/Home/bin/java`：Eclipse Temurin21.0.12.1+1-LTS，macOS arm64。
- `.tools/apache-maven-3.9.16/bin/mvn`：Apache Maven3.9.16；`scripts/mvn.sh` 自动设置环境并隔离 `.tools/m2/repository`。
- JDK mac/aarch64 SHA256 `3623232f33a9c3baadf304480b2535f9a3cba8a58d42ecbb438ba267315d9998`；Maven SHA512 `831a8591fe20c8243b1dbe7d71e3244f31d1665b0804b2e825e38cbbe5ce0cafb8338851f90780735568773e0a6cd07bbec107cda0b896b008b861075358b6f6` 均匹配官方来源。四平台固定资产、摘要及出处见 `ops/toolchain-lock.json`。
- `scripts/mvn.sh -B -N validate`：BUILD SUCCESS，26.071s；离线复测 BUILD SUCCESS，0.384s。
- `python3 ops/test-tooling.py`：3 tests，0 failures/errors，0.751s，验证随机私有配置/0600/禁止覆写、精确进程树终止和保护无关进程、跨读取块秘密脱敏和10MiB日志上限。
- `bash -n scripts/*.sh` 通过。
- Ruby标准库Psych解析 `compose.yaml` 和 `ops/compose.protocol-egress.example.yaml` 通过，断言仅web publish、engine/platform内部端口、backend internal。
- Docker Hub metadata查到 `maven:3.9.16-eclipse-temurin-21` 与 `eclipse-temurin:21-jre-jammy` 存在；未锁digest（生产需记录）。Docker CLI缺失，未执行 Compose schema CLI验证、镜像构建、容器运行或Linux native实测。

## 证据日志（被忽略，不提交）
`.tools/logs/bootstrap-tools.log`、`toolchain-discovery.log`、`toolchain-download.log`、`maven-root-validate.log`、`maven-root-validate-offline.log`、`tooling-tests.log`、`ops-validation.log`。

Maven下载曾两次180s超时（不是摘要错误），最后一次成功且验证；可复现脚本现在使用同版本Maven Central链接和900s有界超时，仍校验已锁Apache SHA512。

## 部署要点
随机token/master/bootstrap/DB密码仅写0600私有env；无默认固定密码；不打印秘密。dev只Java两服务，不启动或停止web；私有服务日志流式脱敏配置秘密且有界；停止验证PID/启动时间/jar及后代身份，不宽泛pkill。

Compose engine不publish、非root、只读rootfs、tmpfs工作目录、capability/PID/内存限额。默认只loopback协议allowlist且backend无外网出口；管理员须显式选择external受控网络override、数字IP/非特权端口白名单并配置出口防火墙，不使用host网络。生产Secure cookie=true，开发HTTP=false；部署到多人内网前准备HTTPS入口。GmSSL runner静态链接并附Apache LICENSE，避免native x86 `-march=native`分发需求。生产数据恢复/主密钥/状态型签名注意事项见 `ops/README.md`。
