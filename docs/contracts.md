# HTTP 与跨模块契约 v1

本文为团队实现共享契约，变更先由 Lead 协调。所有 id 为 UUID；时间 ISO-8601 UTC。JSON camelCase。统一错误 `{code,message,requestId}`，无堆栈/秘密。列表暂为 JSON 数组，后续分页不在首轮隐式变更。

本轮新增的快捷/高级表单、GmSSL/OpenSSL密钥生成、加密托管私钥口令与六类证书向导，详见 [UX-SIMPLIFICATION.md](UX-SIMPLIFICATION.md)。该文档是这些新增API/字段的权威契约；原有任务、状态型单一权威与网络规则继续有效。OpenSSL本轮仅新增生成能力，不代表全部业务算法后端已替换。


## 服务与配置
- platform-service :8080，前缀 `/api/v1`；Spring Boot 3.5.7 / Java21 / Spring JDBC + Flyway，H2 dev/test，PostgreSQL server。
- engine-service :8081，前缀 `/internal/v1`；全部执行和目录接口需 `X-Engine-Token`，以恒时比较校验。`/actuator/health`仅健康状态。
- env：`GMSSL_ENGINE_URL`、`GMSSL_ENGINE_TOKEN`、`GMSSL_RUNNER_PATH`、`GMSSL_VAULT_DIR`、`GMSSL_VAULT_MASTER_KEY`（base64 32 bytes）、`GMSSL_BOOTSTRAP_USERNAME`、`GMSSL_BOOTSTRAP_PASSWORD`、`SPRING_DATASOURCE_URL/USERNAME/PASSWORD`、`GMSSL_ENGINE_WORK_DIR`。
- 网络部署配置：`GMSSL_ENGINE_ALLOWED_HOSTS` 默认 `127.0.0.1,::1`，只接受数字IP精确allowlist不接受DNS名；`GMSSL_ENGINE_ALLOWED_PORTS` 默认 `14433,14434,14435,14436,14437,14438`；`GMSSL_ENGINE_ALLOW_LOOPBACK=true`。监听端口必须>=1024且在白名单内；出站连接的目标端口只要1..65535且在白名单内即可（例如管理员显式加入80/443，默认未放行），不把“监听特权端口”与“连接远端80/443”混为一谈。metadata/link-local、多播与广播目标总禁；HTTP获取禁重定向并检查内嵌URI，不把证书URL当可信参数。允许目标只由部署管理员配置。容器默认隔离出口；启用受控网络须显式override，不等同放行任意目标。
- engine URL/runner路径只能由部署配置指定，非用户参数。token/master/password 无部署默认值；dev bootstrap 可由脚本生成私有 `.env.local`（不入git）。生成 secret 不打印到共享日志。
- Web Vite dev :5173 反代 `/api` 到8080；生产 nginx 同源反代，engine不publish端口。

## 登录、权限与项目
- `POST /auth/login` `{username,password}` → `{user:{id,username,role},csrfToken}`，设置 `GMSSL_SESSION` HttpOnly SameSite=Strict（生产HTTPS secure）。会话随机值仅hash入库；登录失败统一错误、有限速；密码BCrypt，12..72 UTF8 bytes。
- `GET /auth/me` → 同上；未登录401。`POST /auth/logout` →204，撤销session。
- 除login外所有修改请求需header `X-CSRF-Token`，绑定当前session；GET不修改状态。会话/secret不存localStorage。禁止跨源credential通配。
- 系统角色 `ADMIN` / `USER`；项目角色 `OWNER` / `EDITOR` / `VIEWER`。ADMIN具备全局管理权限（须审计）；其他用户仅能访问加入项目。VIEWER仅列表/查看非敏感信息，不可运行任务或下载私钥，EDITOR可运行/管理项目内材料，OWNER可管理成员与项目。
- `GET /users`、`POST /users` `{username,password,role}`、`PATCH /users/{id}` `{role?,enabled?,password?}`：ADMIN。用户DTO统一 `{id,username,role,enabled,createdAt}`；登录user可返回同一DTO。项目成员DTO统一 `{userId,username,role}`，这里role为项目角色。
- `GET /projects` → `[{id,name,description,role,createdAt}]`。
- `POST /projects` `{name,description?}` →项目，创建者OWNER。
- `GET /projects/{id}` →项目；`GET /projects/{id}/members`；`PUT /projects/{id}/members/{userId}` `{role}`；`DELETE /projects/{id}/members/{userId}` OWNER/ADMIN，保护最后一个OWNER。
- `GET /projects/{id}/audit` → `[{id,actor,action,resourceType,resourceId,outcome,createdAt}]`，OWNER/ADMIN。只记录动作与无敏感标识，不记录参数原文、密码、key内容和engine stdout。

## 密钥与文件
- key元数据 `{id,projectId,name,algorithm,keyKind,encoding,validationStatus,usage,description,publicFingerprint,createdAt,updatedAt,stateful}`；keyKind `PRIVATE_KEY|PUBLIC_KEY|SYMMETRIC_KEY|MASTER_KEY|STATEFUL_PRIVATE_KEY`，encoding `PEM|DER|RAW|HEX|TEXT`；导入默认validationStatus `UNVERIFIED`，只有真实验证或受控生成后才能标 `VALIDATED`，不能凭用户元数据宣称密钥有效。
- `GET /projects/{pid}/keys` → key数组；`POST .../keys` multipart：`file` + `name,algorithm,keyKind,encoding?,usage?,description?`。encoding缺省时仅识别PEM起始标记，否则RAW；HEX/DER由用户明确指定并做基础格式校验，避免把任意ASCII材料误猜为HEX。原始秘密文件由vault envelope加密，不回传内容；格式/口令正确性可通过明确工具任务验证，未验证文件不得伪报已验证。密码不在key元数据保存。
- `GET .../keys/{kid}` →元数据；`DELETE .../keys/{kid}`；`GET .../keys/{kid}/download` →授权下载原始托管材料，private需要EDITOR+且记录审计，不提供GET明文预览。浏览器不自动预览私钥。
- `POST /projects/{pid}/files` multipart `file` + `temporary?:boolean`（默认false）→ `{id,name,size,mediaType,createdAt,temporary}`；`GET .../files` →数组；`GET .../files/{fid}/download`；`DELETE .../files/{fid}`。temporary仅FILE允许，KEY/ARTIFACT禁止。临时FILE通过数据库CAS持久绑定首个job（同任务可多处引用），不能并发被另一job消费；提交入队失败须回滚绑定，终态后删除DB记录与vault密文。排队取消和重启失败任务也清理其临时文件；不能只在run.finally，因为取消队列未必进入run。未绑定临时文件超过1小时周期回收（启动与定时），检查失败有脱敏告警/重试。所有文件仍加密存放，流量有界（默认16MiB单文件），文件名是显示元数据，不作为磁盘路径。禁止路径跳转、符号链接和覆盖其他对象。
- 输入引用：`key:<uuid>` 或 `file:<uuid>`，平台验证同项目、调用权限、keyKind与操作相容后解析；用户永远不传服务端绝对文件路径。
- key生成通过工具任务完成；`POST /projects/{pid}/jobs/{jid}/artifacts/{artifactId}/save-key` `{name,algorithm,keyKind,encoding?,usage?,description?}` 将已完成结果提升为vault key，原子加密持久化。encoding规则与导入一致；除有确定生成/验证证据的密钥产物外，默认仍UNVERIFIED，不能把任意签名/证书产物自动标记成已验证私钥。
- 临时材料可以随job上传为临时file并在任务终态清理；所有路径与日志均不泄露秘密。vault使用JCE AES-256-GCM、随机nonce、AAD绑定项目/对象id，主密钥不入数据库；元数据和密文写入/删除有失败恢复策略。

## 能力目录
- `GET /capabilities`（platform代理）与engine `GET /capabilities` → `{provider:"gmssl",version,sourceCommit,categories:[...],tools:[ToolDefinition],coverage:{...}}`。
- `ToolDefinition`：`{id,command,title,category,description,parameters:[Parameter],acceptsStdin,stdoutMediaType,stdoutFilename,sensitiveOutput,defaultTimeoutSeconds,maxTimeoutSeconds,adminOnly,stateful,verification:{status,evidence}}`。
- category固定为 `digest|mac|symmetric|asymmetric|kdf|random|pqc|key|certificate|envelope|protocol|utility`。
- `Parameter`：`{name,flag,label,type,required,description,defaultValue?,options?,min?,max?,repeatable?,secret?,allowKeyReference?,allowedKeyKinds?}`。INPUT_FILE若为密钥材料须给allowedKeyKinds（上述KeyKind枚举数组）；平台对key引用校验此字段，不凭参数名key/pubkey猜类型。没有allowedKeyKinds的文件参数仅接受file引用；引擎仍负责格式和算法正确性验证。`secret:true`与类型正交（例如HEX对称密钥仍需秘密处理），所有该类值均不保存/回显；SECRET类型隐含secret:true。仅明确allowKeyReference:true的HEX参数可选SYMMETRIC_KEY引用；平台按encoding将RAW字节转hex或校验HEX文本，再以内存参数传引擎，禁止把文件路径作为HEX密钥。
- type：`BOOLEAN|STRING|INTEGER|ENUM|HEX|SECRET|INPUT_FILE|OUTPUT_FILE`。name为不带`-`的参数标识；flag为精确CLI选项。BOOLEAN true产生一个flag，false省略；其他类型产生flag/value；repeatable允许数组，禁止未声明选项、任意argv或shell片段API。约束条件（互斥/条件必需）需要引擎精确验证，不仅前端判断。
- OUTPUT_FILE仅接受受限basename，落在任务output目录；INPUT_FILE的值为平台引用或engine `input:<token>`。HEX校验长度/偶数/字符并按具体工具约束；SECRET不被表单自动填充或存储。
- status `implemented|tested|unverified|unavailable`，标明证据/原因。目录必须真实，不用所有项静态标tested；硬件不进入首版目录。完整算法/API差额记入coverage，工具help/version可提供版本但不计算法覆盖。
- Native worker如需扩展字段，先在Lead处更新本文，frontend/platform不得各自猜字段。

## 任务（公开）
- `POST /projects/{pid}/jobs` `{toolId,parameters:{...},stdinText?,stdinFileRef?,timeoutSeconds?}` → job（202）。stdinText与stdinFileRef互斥。INPUT_FILE的parameter值使用key:/file:引用；OUTPUT_FILE值为建议basename。
- `GET /projects/{pid}/jobs` → job数组；`GET .../jobs/{jid}` → job详情。
- job：`{id,projectId,toolId,status,createdAt,startedAt,finishedAt,exitCode,durationMs,error?,stdoutPreview?,stderrPreview?,truncated,artifacts:[{id,name,size,mediaType,sensitive,downloadable,promotable,statefulPrivate}]}`。不回显SECRET和完整参数；敏感stdout不生成preview。参数秘密只在执行生命周期内存中存在，不持久化任务JSON。
- status `QUEUED|RUNNING|SUCCEEDED|FAILED|TIMED_OUT|CANCELLED`。queued→running→终态，所有取消/恢复失败有真实记录。进程exit0不等于算法verify成功时需结合具体工具语义，不能伪造成功。
- `POST .../jobs/{jid}/cancel`；`GET .../jobs/{jid}/artifacts/{aid}/download`。产物全部经vault加密保存，只有同项目授权者可取。
- 提供有界线程池/队列、每用户并发和任务超时；超限429。执行失败保留脱敏诊断。重启时原RUNNING任务标失败，禁止伪称完成。
- 协议工具默认ADMIN可执行，任务始终有超时；网络目标/监听端口由部署策略约束。至少限制特权端口、metadata/link-local、广播和非允许目标；允许范围可由管理员部署配置明确给出，不给浏览器任意内网探测API。

## 执行（内部）
- `POST /executions` →同步终态响应。请求 `{id,toolId,parameters:{...},inputs:{token:{name,contentBase64}},stdinBase64?,timeoutSeconds?}`。
- platform先验证引用与权限，再将INPUT_FILE参数转为 `input:<token>`；engine只接受inputs内存在的token，不接受外部路径。文件有界，engine材料只在独立0700任务目录中临时使用。
- 响应 `{id,status,exitCode,stdoutBase64,stderr,durationMs,truncated,artifacts:[{name,mediaType,contentBase64}],updatedInputs:[{token,contentBase64}]}`；updatedInputs只允许经过声明的状态型私钥输入，平台必须在持有该key互斥锁时原子提交更新，之后才发布签名产物。普通输入不得被默默改写。
- `POST /executions/{id}/cancel`：通过当前任务真实process identity取消，终止root及其后代，不能按宽泛名称pkill。
- 任务id重复/并发重入拒绝。finally清理工作区；可保留非敏感trace不保留输入私钥/口令。stdout/stderr分别有上限，持续drain避免死锁。默认timeout30s，上限300s；超时/取消统一执行清理。默认最多2个native进程，输入/输出总量各16MiB（可部署调整）。
- runner进程实际argv不含算法参数或秘密；长度前缀stdin帧有magic/version/count/每项长度/总长上限；读取后再将业务stdin提供给gmssl_cli_main。参数不可通过环境、日志、ps泄露；无shell、无用户动态库路径。C buffer边界与错误路径必须测试。

## 状态型签名门槛
LMS/HSS/XMSS/XMSSMT签名会消费状态。由工具catalog.stateful而非用户提供的algorithm/keyKind决定是否启用保护；将状态型材料伪标普通密钥也必须被拒绝。仅允许vault中的STATEFUL_PRIVATE_KEY、禁止直接临时上传签名；同key全生命周期互斥，更新后的key持久化成功后才使签名可下载。崩溃后该key标为需要恢复/暂禁签名，避免重用索引；须记录非秘密pending标志，不使用超时失效锁假定签名未发生。实现不满足时工具目录须标unavailable并明确原因，而非当普通签名放行；最终全覆盖验收需解决此项。

## 前端
左侧导航：工作台、算法工具、密钥库、证书工具、协议任务、任务历史、项目与成员、审计（权限可见）。算法目录搜索/分类→类型化表单→输入与输出约定→实际任务结果/下载。显示provider/version/verification。密钥导出与删除有确认，SECRET使用password输入，不回显。文本输出插值转义，禁止v-html。错误必须来自真实API，空态可引导但不制造假统计。

## 联调基线
真实登录→项目→SM3 abc KAT→SM4-GCM往返/篡改失败→SM2生成加密key/签验/错误ID→证书生成解析→代表性PQC→协议成对握手→两个用户越权检查。记录命令、端口、日志、残余缺口。除测试fixture外不提交真实密钥或凭据。


## 状态型密钥单一权威（首版具体策略）
状态型签名不同于普通软件密钥：外部导入STATEFUL_PRIVATE_KEY禁用，普通导入可保留材料但不得供状态型签名使用。STATEFUL_PRIVATE_KEY只能由平台受控 `lmskeygen|hsskeygen|xmsskeygen|xmssmtkeygen` 成功任务中明确的私钥输出产物晋升，后端决定算法/类型并在数据库唯一绑定source_artifact_id；同私钥产物仅能晋升一次，删除后也保留非秘密消费tombstone。成功生成后的状态型私钥产物从创建起即不允许下载/普通存key（晋升前后均如此），只有授权的受控晋升操作，公钥产物可正常下载。STATEFUL_PRIVATE_KEY不开放原始下载或复制，防止产生多个独立签名权威。pending故障后禁签，不支持上传旧备份覆盖或自动解锁；首版不交付状态型私钥导出/恢复，明确提示弃用隔离key并生成新key。普通密钥的备份/导入导出不受此特殊规则影响。该限制是正确性门槛，UI须说明，不可偷偷降级为普通key。状态型keygen产物的受控保密由源工具/精确输出参数标记实现，不能仅按可伪造文件名或用户algorithm判定。
