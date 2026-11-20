# Platform service

Java 21 / Spring Boot 3.5.7 管理入口，HTTP 契约以 `../docs/contracts.md` 为准。浏览器仅访问此服务；原生执行由内部 engine 完成。

## 构建与启动

```bash
scripts/mvn.sh -pl platform-service test
scripts/mvn.sh -pl platform-service package
# 通过部署secret设置下列环境变量后，用隔离Java21启动：
source .tools/env.sh
"$JAVA_HOME/bin/java" -jar platform-service/target/platform-service-0.1.0-SNAPSHOT.jar
```

必须配置 `GMSSL_VAULT_MASTER_KEY`（base64恰好32字节）、`GMSSL_ENGINE_TOKEN`。全新数据库还必须提供 `GMSSL_BOOTSTRAP_USERNAME` / `GMSSL_BOOTSTRAP_PASSWORD`，密码为12..72 UTF-8字节。已有用户时忽略bootstrap凭据；不要将实际值写入命令参数或版本库。engine URL固定来自 `GMSSL_ENGINE_URL`，缺省 `http://127.0.0.1:8081`。主密钥/token没有部署缺省值。

数据库使用 `SPRING_DATASOURCE_URL/USERNAME/PASSWORD`。开发缺省H2文件库、PostgreSQL compatibility mode；生产使用PostgreSQL并保持同步提交、可靠存储。Flyway自动迁移。`GMSSL_VAULT_DIR` 缺省 `./data/vault`；生产独立持久卷。HTTPS部署设置 `GMSSL_SESSION_COOKIE_SECURE=true`。反向代理同源，不配置跨源credential通配。健康探测 `GET /actuator/health`。

## 已实现路径

- 内置BCrypt cost12账号，ADMIN/USER，会话随机token仅SHA-256入库、8小时到期、HttpOnly+SameSite=Strict cookie、会话绑定CSRF、登录每源地址每分钟10次限速。
- 项目OWNER/EDITOR/VIEWER、成员管理和最后OWNER保护、全局管理员操作审计。
- 密钥/文件/产物元数据与授权下载。导入缺省UNVERIFIED；仅PEM前缀自动识别，否则RAW，HEX/DER需显式指定encoding。对称HEX参数仅在目录allowKeyReference时接受SYMMETRIC_KEY，RAW转hex、HEX验字符，不传磁盘路径。
- AES-256-GCM信封加密，随机nonce，AAD绑定项目+对象UUID，磁盘0600材料/0700目录，随机UUID文件名；不把用户文件名作为路径。单文件/总输入/总产物16MiB上限。文件fsync→原子rename→父目录fsync后才提交元数据。失败产生的孤立密文在启动及周期任务中清理，不删除有效对象；缺失或篡改密文明确报VAULT_INTEGRITY。
- 临时文件生命周期管理（Flyway V5）：`POST /projects/{pid}/files?temporary=true` 标记上传文件为临时。严格仅限 FILE（KEY 与 ARTIFACT 拦截 400）。任务提交时采用数据库 CAS 将临时文件原子绑定到 `bound_job_id`，冲突时返回 409 `FILE_BOUND`；提交异常或队列已满时回滚绑定。任务处于 QUEUED 或进入终态（SUCCEEDED/FAILED/CANCELLED/TIMED_OUT）时，自动触发 vault 磁盘与数据库材料清理；活跃任务中的临时文件禁止手动删除；服务崩溃重启在 `recover()` 阶段级联清理；启动与后台每分钟定时扫描回收超过 1 小时未被绑定的孤立临时文件。先删 vault 磁盘再提交数据库删除事务，出现异常记录明确告警，杜绝无引用残留孤儿。
- 真HTTP capability代理与engine执行；线程池2+队列16、每用户最多2任务；参数仅在内存任务存续，数据库不保存参数/stdin/SECRET。执行前重新校验用户enabled/权限；INPUT_FILE按项目和allowedKeyKinds校验。任务有超时；排队/运行取消均记录终态；重启将QUEUED/RUNNING标FAILED。stderr不原样保存；敏感输入/输出或SECRET任务不生成stdoutPreview，stdout本体为加密产物且按权限下载。

## 状态型密钥：单一权威

LMS/HSS/XMSS/XMSSMT的私钥仅允许由平台控制的四个keygen成功任务晋升：未传out时平台补充目录声明的out=`stateful-private.key`，通过该精确输出参数匹配源产物；stdout不作为私钥晋升源。数据库source_artifact唯一tombstone保证同一产物仅晋升一次，删除key后也不重置。用户提交的algorithm/keyKind不决定该受控类型，后端固定algorithm与STATEFUL_PRIVATE_KEY。私钥源产物与stateful key原始字节禁止下载，外部STATEFUL_PRIVATE_KEY导入关闭。只有精确pubout产物可走普通下载/晋升。

签名基于真实catalog.stateful，不信任用户algorithm：只有STATEFUL_PRIVATE_KEY的key引用可用。DB条件更新pending=false→true是跨进程独占；pending在执行前提交且没有过期自动释放。引擎返回updatedInputs必须恰好覆盖已锁key，状态必须变化；文件持久替换成功、产物加密保存成功后，清pending与发布SUCCEEDED在同一数据库事务提交。异常/取消/崩溃保留pending并禁签。HMAC(master派生专用子密钥)历史只作额外材料复用检查，不是长期身份/外部状态防回滚证明。

首版pending故障不提供自动恢复/覆盖上传：隔离该key并生成新key。数据库与vault的备份必须一致；不要把旧数据库/旧vault快照恢复为活动签名权威，也不要运行另一外部副本。底层文件系统必须支持原子rename、文件及目录fsync；该步骤失败则发布失败并保持pending。H2是开发/测试库，不作为多实例生产数据库；生产PostgreSQL与vault持久卷须由运维保证可靠持久化、禁用异步提交及回滚旧快照。

## 测试证据与边界

`PlatformIntegrationTest` 通过真实Spring MockMvc、H2/Flyway与loopback HTTP engine fixture测试认证/CSRF/项目隔离/角色/跨项目引用与产物访问、vault错误主密钥/AAD/密文篡改、失败/取消、排队用户禁用或移除成员、stateful受控晋升/禁止导入导出/锁冲突/失败pending/启动恢复、秘密不进入preview或任务记录。

fixture测试不等于GmSSL算法测试；原生算法与完整服务本机链路由integration/Lead另行实测。PostgreSQL、Linux容器以及断电故障尚需部署环境验证；正常JCE与H2测试不冒充这些验证。
