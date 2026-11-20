# 本地 JRE 运行 Vault Operation not permitted 只读诊断与最小保数据方案

## 一、现象定位与核心源码行证据

1. **异常抛出源码行**：
   - `platform-service/src/main/java/org/gmssl/gui/platform/Vault.java:37-45`
   ```java
   @PostConstruct
   void init() throws IOException {
     Files.createDirectories(root);
     if (Files.isSymbolicLink(root)) throw new IOException("Vault root symlink forbidden");
     try {
       Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"));
     } catch (UnsupportedOperationException ignored) {
     }
   }
   ```
2. **POSIX 系统调用与异常链**：
   - `Files.setPosixFilePermissions(root, ...)` 调用 Linux 底层 `fchmodat` / `chmod`；
   - Linux POSIX 规范规定：仅文件属主（Owner UID）或拥有 `CAP_FOWNER` 能力的特权进程才允许修改文件权限位（`chmod`）；
   - 当调用者的有效 UID 与目标目录属主不一致时，内核直接返回 **`EPERM`（Operation not permitted）**；
   - Java NIO 将 `EPERM` 封装为 `java.nio.file.FileSystemException: /data/vault: Operation not permitted`（继承自 `IOException`）；
   - `Vault.java:43` 仅捕获了非 POSIX 文件系统的 `UnsupportedOperationException`，未捕获 `FileSystemException`，导致异常抛出到 Spring 容器，应用启动崩溃。

---

## 二、容器与数据卷属主冲突机制

1. **原镜像 vs 自定义 JRE 镜像**：
   - 原打包镜像（`docker/platform.Dockerfile`）中显式创建了 `10001:10001` 并在构建期 `chown -R 10001:10001 /data/vault`；
   - Docker 在首次创建命名数据卷 `vault-data` 时，会将镜像内对应挂载点的属主复制到卷根目录，因此原镜像运行时进程 UID 10001 与卷属主 10001 一致，`chmod` 成功；
   - `compose.jre.yaml` 直接采用外部基础 JRE 镜像，未内建 `10001` 账号与目录模板；若外部镜像以默认 root（UID 0）或镜像自带 UID（如 1000）运行，而旧卷内 `/data/vault` 属主为 10001，且 `compose.jre.yaml` 开启了 `cap_drop: [ALL]`（丢弃了包括 `CAP_FOWNER` 在内的全部权能），导致进程试图对其执行 `chmod 0700` 时触发内核 `EPERM`。
2. **只读文件系统叠加**：
   - 容器开启 `read_only: true`，仅挂载卷 `/data` 与 `/tmp` 可写。

---

## 三、现场最少只读排查命令（严格防泄露，绝不执行危险命令）

请在测试服务器执行以下只读检查，获取实际 UID 与属主映射（不打印 .env，不破坏卷）：

```bash
# 1. 检查 JRE 镜像声明的默认用户与数据卷配置（安全只读 inspect）
docker inspect --format 'Image={{.Config.Image}} ConfigUser={{.Config.User}}' $(docker compose -f compose.jre.yaml ps -q platform)
docker inspect --format 'Mounts={{json .Mounts}}' $(docker compose -f compose.jre.yaml ps -q platform)

# 2. 从临时调试容器以只读方式检查卷内已有目录属主与权限（不改卷、不连库）
docker run --rm --pull=never --entrypoint /bin/sh -v gmssl-gui-release_vault-data:/data:ro ${JRE_IMAGE} -c 'ls -ld /data /data/vault; id'
```

---

## 四、安全修复建议（保数据、保密钥、不 777、不长期 root）

1. **代码防御（推荐）：兼顾安全与非属主兼容**：
   - 在 `Vault.java` 中对 `setPosixFilePermissions` 增加对 `FileSystemException` / `AccessDeniedException` 的受控兼容处理：
     - 若 `setPosixFilePermissions` 抛出 `FileSystemException`（EPERM），但通过 `Files.isReadable(root) && Files.isWritable(root)` 检查已具备完整读写能力，则记录警告日志并继续运行，不因无法变更非本人属主的目录权限位而直接中断业务。
2. **编排对齐**：
   - 在 `compose.jre.yaml` 中显式支持配置 `user: "${GMSSL_CONTAINER_USER:-10001:10001}"`，与历史卷属主对齐；
   - 严禁删除数据卷，严禁 `chmod 777`。
