# 快捷流程、默认值与双引擎生成实施契约

## 已确认产品决策

用户已明确选择并确认开始：快捷流程+保留高级参数；GmSSL与OpenSSL两种生成来源；默认加密托管并自动选中，也可仅本次使用；证书覆盖自签名、根CA/中间CA、CSR申请与CA签发、TLCP双证书。进一步确认私钥文件口令也由平台加密保存，后续选择托管密钥免重复输入。现有IPv6监听和mac.sjser.ccwu.cc域名、既有项目/密钥/任务保持不变。

本次OpenSSL接入仅用于实际支持的随机数/密钥对生成，不替换所有业务算法后端。不能把字节随机数当作EC/SM2/SM9/PQC私钥。OpenSSL与GmSSL原生加密PKCS8不直接兼容，必须实际验证并转换为GmSSL可消费格式；不提供表面可选但后续必然失败的provider组合。

## 架构与职责

1. engine：固定类型生成接口，GmSSL现有runner工具；OpenSSL路径由部署配置固定、探测版本/支持能力，命令和参数白名单，无shell、无任意算法/路径。共享执行限额，私有工作区，有界输出/超时/cancel/清理。口令不进argv/env/log，原始私钥只在内存或0700工作目录短暂存在。
2. native bridge：仅私钥格式适配，解析OpenSSL未加密PKCS8 DER并使用GmSSL私钥加密函数重封装；原上游不改。支持SM2/P256/P384真实测试，拒绝不支持类型。keygen本身始终调用对应引擎专用算法。
3. platform：生成权限/项目隔离、加密托管与口令伴随保存、审计、选择密钥自动补口令。生成普通密钥不得走外部有状态私钥导入漏洞。状态型生成仍采用已有job/keygen单次晋升路径。
4. catalog：保留原80+14业务工具并补精确defaultValue/options/中文label/快捷显示提示；值来自固定源码/真实帮助/测试，不猜测枚举。新元数据不能让required字段被折叠后无反馈。
5. web：必要参数在快捷视图，advanced折叠；生成入口按参数类型引导生成对称密钥、专用密钥对或主密钥/用户密钥。默认托管，返回后刷新密钥并自动选择。证书向导保留可见步骤、输出和失败位置，不伪造任务成功。

## API 契约

### 生成能力
- `GET /api/v1/key-generation-capabilities`（已登录）；platform转发`GET /internal/v1/key-generation-capabilities`。
- 返回 `{providers:[{id:"gmssl"|"openssl",available:boolean,version?:string,reason?:string,algorithms:string[]}], algorithms:[{id,kind,bits?:number[],curves?:string[],providers:string[]}]}`。
- 首批跨provider目标：对称随机字节（SM4/SM4-XTS/AES/ZUC/ZUC256/HMAC）与SM2、EC(P256/P384)。SM9与PQC由既有GmSSL专用keygen承接；OpenSSL ML-KEM不能等同旧Kyber格式，未验证的组合明确不提供。

### 生成密钥
- `POST /api/v1/projects/{pid}/keys/generate`，EDITOR以上、CSRF。
- 请求 `{provider,algorithm,name?,bits?,curve?,storage:"MANAGED"|"TEMPORARY",password?}`。
- `password`仅私钥文件口令，缺省时平台生成高熵随机口令；MANAGED模式加密保存。所有密码无固定默认明文。
- response：`{provider,algorithm,storage,reference?:string,key?:Key,publicKey?:Key,temporaryFile?:ManagedFile,temporaryPublicKeyFile?:ManagedFile,valueHex?:string,warnings:string[]}`；公钥参数选择publicKey或temporaryPublicKeyFile，不以私钥引用代替。
- MANAGED对称密钥：vault保存HEX编码文本、keyKind=SYMMETRIC_KEY，响应只metadata+`reference:"key:UUID"`，不返回valueHex。
- MANAGED SM2/EC：GmSSL兼容的加密PKCS8 PEM私钥+PEM公钥，返回两Key metadata，私钥hasManagedPassphrase=true，reference指私钥；公钥也加密保存但无口令。
- TEMPORARY对称密钥：只响应valueHex供当前表单、不默认持久保存。TEMPORARY非对称私钥可创建受现有临时FILE生命周期管理的材料并附加密口令记录、返回file引用，界面清楚提示执行后清理；证书向导默认MANAGED避免生成后丢失私钥。
- engine对应`POST /internal/v1/key-generations`：请求含`requestId,provider,algorithm,bits?,curve?,password?,timeoutSeconds`；响应仅内部使用`{provider,algorithm,keyKind,encoding,valueBase64?,privateKeyBase64?,publicKeyBase64?,warnings:[]}`，private为最终GmSSL兼容加密PEM，不把OpenSSL原生不兼容私钥冒充可用。超限/错误使用现有安全错误schema。
- 如果某算法或provider未通过格式互操作验证，capabilities中明确不支持，不静默替换provider；不得为了凑支持范围生成不兼容密钥。

### 托管口令
- 新DB表`key_credentials`以材料ID关联，密文BYTEA，使用Vault AES-GCM与project/material/purpose AAD绑定；原数据库、任务JSON、DTO、审计、进程参数/环境均无明文。
- Key/临时FILE DTO新增`hasManagedPassphrase?:boolean`、`generationProvider?:string`（未生成/历史可缺省）。
- secret参数可补`credentialKeyParameter?:string`，如pass关联key、capass关联cakey；平台只依据可信catalog映射与同项目材料引用注入口令。用户显式输入可覆盖，不能读取其他项目口令。前端仅在选中hasManagedPassphrase材料时将口令字段显示为“已托管，自动填充”，不要求用户输。
- 生成/导入历史私钥支持`POST /projects/{pid}/keys/{id}/passphrase`设置加密口令，不能由普通更新接口原样回显。
- 为现有加密私钥导出提供显式`POST /projects/{pid}/keys/{id}/reveal-passphrase`（EDITOR+CSRF、审计、禁止有状态私钥），仅该主动操作响应口令，普通metadata永不包含；若实现采用重新设置导出口令亦可，但不得让导出的文件永远无法使用。
- 材料删除同时删除口令记录；临时FILE清理同样清理伴随记录。不为状态型私钥增加复制/导出捷径。

### 证书向导
- 快捷profile：SELF_SIGNED、ROOT_CA、INTERMEDIATE_CA、CSR、CA_SIGN、TLCP。
- 用户提供名称/CN、用途(SERVER/CLIENT/SIGNING)、SAN域名/IP、有效天数与所选发行者证书/私钥；高级项可展开。根CA默认3650天，中间1825，叶证书365；组织等真实身份信息不编造默认值；序列号用安全随机合法正整数Hex。
- 后端`POST /api/v1/projects/{pid}/certificate-workflows`接收`{profile,name,subject:{CN,C?,O?,OU?,...},sanDns?:string[],sanIps?:string[],days?,provider?,keyRef?,keyPassword?,issuerCertRef?,issuerKeyRef?,issuerPassword?,csrRef?,purpose?,advanced?:object}`，EDITOR+CSRF。所有字段白名单，SAN类型验证，advanced不得成为任意CLI注入通道。
- 后端逐步调既有真实jobs与生成服务，返回`{workflowId,status,stages:[{name,jobId?,status}],keys:Key[],files:ManagedFile[],artifacts?:object[],warnings:[]}`；可同步有界执行（总预算与步骤上限）或实现受控异步轮询，但前端必须与实际一致。失败返回可定位阶段及已生成材料引用，不删除用户既有材料、不假成功；每步有审计/任务证据。
- 证书产物保存为项目FILE，默认持久化便于后续链校验和协议使用；不是CERTIFICATE类型私钥。TLCP生成独立签名/加密SM2密钥与证书，保证用途区分和正确证书链顺序，不能复用同一私钥假装双证。
- 所有签发输出做certparse/适当certverify与用途检查。SAN非仅CN，CA basicConstraints/keyCertSign/cRLSign、终端用途与extendedKeyUsage来自实际GmSSL参数。OpenSSL生成的SM2密钥必须经bridge验证可供GmSSL签发后才能在向导中选用。

## 验收门槛

- 双provider随机密钥长度/encoding、GmSSL业务真实加解密；SM2/EC两provider专用keygen→GmSSL签验/证书生成闭环，不仅检测命令存在。
- 私钥口令加密落盘，普通DTO/审计/日志/ps无明文；同项目自动注入成功、跨项目/VIEWER拦截、未知secret参数不注入、删除/临时清理不残留。
- 六类证书profile真实产出、SAN/用途/有效期/链校验正确；TLCP实际双证握手；失败阶段可见且不发布半成品为成功。
- 默认值/枚举全目录有逐项矩阵：有证据才填，未提供默认的字段不谎称有默认。高级视图可还原全功能，必填项始终能找到。
- 中文浏览器实际快捷流程、生成并自动选中、托管口令免重复输入；随机IV/nonce不得填固定零值或全局重用。
- 既有全工具、状态型密钥、RBAC/CSRF、超时/清理、IPv6域名回归；目标Linux/OpenSSL安装与默认缺失行为有部署说明。

## 分工与交付

Lead维护本契约/计划/复审。实现按独立写边界并行，原有高级工具和用户数据不删。先一条SM4生成托管及一条自签名证书真实闭环，再扩矩阵；每阶段产物和测试落盘，禁止只有口头进展。无Git commit/push，不设置sandbox_permissions，不恢复公网隧道。
