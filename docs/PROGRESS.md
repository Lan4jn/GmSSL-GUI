# 实施进度与续接记录


## 当前增量：快捷流程与双引擎生成（已验收交付）

本节优先于下方首版历史交付记录。用户已确认新范围，见 UX-SIMPLIFICATION.md。goal-d9d8d189-66b3-4ee9-b73d-7857809c320b 的实现与独立验收已完成。task20 engine/nativebridge、21目录元数据、22平台口令托管、23现有前端、24证书工作流、25新向导组件、26独立验收、27 SAN/CSR原生扩展。

Lead已独立运行 Java 71 项（engine29/platform42）、Web106项+typecheck/build全部通过；真实 Chrome FULL_SAN 11路径通过，公开叶证书/root链与DNS/IPv4/IPv6 SAN已由Lead另用OpenSSL解析验签。QA新增UX32项、PKI10项/25记录、原生扩展231次、SAN11组、SCT/CRL5组、执行帧4项、部署工具5项通过。旧core30回归先发现SM9算法枚举漏项，再发现SM9 init静态必填错误，已精准修复并真实30/30通过（四阶段交换True）。原native成员连续异常退出无文件修改，task21最后单点由Lead按任务级兜底执行：SM9分阶段全局必填/用户身份默认修正，以及QUIC/TLS曲线输入名称修正。后者原生实证prime256v1成功、secp256r1非法，元数据已红→绿；QA刷新引擎目录后，协议14/14、核心30/30、最终UX32/32全部通过。最终报告 docs/review/ux-acceptance.md 经Lead校正计数与范围后验收通过；六项产物指纹及内嵌目录字节一致，详见 .tools/logs/task26-current-artifacts.json。当前受管 engine71951/platform71987/web69212；Lead最后健康检查UP、IPv6与指定Host200、非白名单Host403，未开启隧道。操作说明见 QUICKSTART-WORKFLOWS.md。

task27由native-algorithms拥有apply-overlays.py与SAN测试/目录，新增certgen/reqsign IP SAN、reqgen DNS+IP extensionRequest与reqsign安全继承CSR SAN。固定upstream保持不改，使用hash与唯一anchor的派生产物。cert-workflows现已真实接入DNS与IP扩展，并验证CSR请求的安全继承、显式覆盖及证书签名。build-quality独立下载证书/CSR解析扩展与用途、真正TLCP握手、真实Chrome生成托管与向导流程，失败断言不删。

服务起停由build-quality统一协调，保持IPv6 ::5173、mac.sjser.ccwu.cc白名单及原项目/密钥，不开启Cloudflare隧道。不git commit/push、不设sandbox_permissions。下方runner与catalog哈希/测试计数仅首版历史值，新最终身份待本轮验收后记录。

## 当前交付状态

首版本机实施与验收已完成，详见 DELIVERY.md、RELEASE-CHECKLIST.md、docs/review/final-review-report.md。Java 微服务 + 纯浏览器 + 内网多人方案已落地；SDF/SKF 硬件、OpenSSL provider 与企业 SSO 实际接入留待后续。

当前浏览入口 http://127.0.0.1:5173/，受管 platform:8080、engine:8081、web:5173 已启动。实际状态用 scripts/dev.sh status 核验，不依据历史 PID；停止前精确核验身份，不终止无关进程。凭据只读本机私有 .env.local / .env.local.credentials，不输出到对话/日志。无 Git commit/push。

## 冻结产物身份

- upstream commit：24ae482701a7b124826c382fffc55c19f76d475d，3.3.0-dev.1183；原始 checkout git status 干净。
- runner SHA256：36a05a0dc780f798677409d36c59c6645ca8aa3242ac44970906c50dccce2b07。
- overlay manifest SHA256：a9067efe6bcbf0d4f14f968e56badbb49f6fc9f60fc9c1e39d7714637d4aca7c。
- native/catalog.json SHA256：02506687593d0c035c7e69fbcd539297692e38e8ecf7ec2cf1093a7bcc8d8e24。
- native/apply-overlays.py 严格源hash+唯一锚点，生成5派生补丁、manifest、diff；不修改原上游。修复TLS uint64写指针、可选X509时间sentinel、CRL初始化及SCT库/CLI标准SPKI LogID。

## 最终真实测试

- Java root verify：engine11 + platform10，均PASS；.tools/logs/lead-release-java-verify.log。
- Web：30单测、typecheck、build PASS；.tools/logs/lead-web-verify.log。
- Chrome：实际登录/项目/SM3 abc KAT PASS，storageEmpty=true，无runtimeErrors；.tools/logs/lead-browser-smoke-final.log及web/tests/artifacts/。
- 80原生工具 = 51基础/非对称/PQC（30复合tests）+8协议（14tests）+21PKI/CMS（10tests/25records）；tests/toolbox/results/unified_80_coverage.json集合差集无遗漏。
- 14个C扩展工具，生产runner 231次调用PASS；Lead在overlay重建后独立复跑，.tools/logs/lead-release-extensions.log。adapter单独ASan/UBSan不是全库插桩。
- 标准P256/SHA256 SCT + timestamp/LogID负测与CRL两类nextUpdate共5组PASS；.tools/logs/lead-native-overlays.log。
- HTTP21PASS/0FAIL/1SKIP（重启另测）；tests/e2e/results/e2e_da8dcd9d89/report.json。
- 原生runner14PASS；tests/e2e/results/native_089e9379fe/report.json。
- 状态型独立软件重启3PASS；tests/e2e/results/restart_18958922c3/report.json。不是物理断电证明。

## 必须记住的复审决策

1. PKI初稿曾按错误SCT布局签名、手工修改CRL再签以获通过，该结论已撤回；最终标准fixture和可复现overlay修复后才算通过。
2. 秘密经GMRUN001 stdin参数帧传输，不进入OS argv；无shell业务执行；按工具类型/允许keyKinds校验，不按参数名猜引用类型。
3. 状态型keygen精确私钥产物受控晋升一次，禁止普通外部stateful导入/复制/原始下载；唯一来源墓碑在删除后保留；pending失败不自动解除。
4. Materials.delete必须事务锁行、验证项目/pending/活跃绑定后才删vault和DB；不得先删vault再抛409。终态绑定临时文件清理失败有周期重试，物理孤儿保留5分钟窗口再回收。
5. CRL HTTP bounded subscriber在接收期限制16MiB，整任务共享deadline并响应cancel，不用完整读完后才限大小。DER树父边界严格验证，不扫描任意OID/IA5字节。
6. 监听port>=1024+allowlist；出站1..65535+显式allowlist（80/443默认未放行）。数字IP精确匹配，metadata/link-local/多播/广播总禁，HTTP无重定向。
7. TLS1.2国密扩展不引用RFC8998；RFC8998仅TLS1.3；QUIC只声明实验性子集。

## 团队归属与续接

全部12项团队任务交付已收口。build-quality管理scripts/ops、测试聚合与共享服务；integration管理native runner/CMake/catalog/engine；platform管理平台及PKI套件；native-algorithms管理扩展及协议套件；web-verifier完成前端（旧frontend曾runtime失败，已替换）；architecture负责独立审查和e2e；Lead只规划/契约/复审/文档。成员inactive不是失败，后续通过send_message唤醒，不重用名字创建。后续需求重新分诊，不继承本轮兜底。

## 上线前仍需环境验证，不伪称已测

当前macOS/H2本机验收完整，Linux Docker/PostgreSQL/HTTPS生产矩阵尚未实际执行（环境无Docker CLI）。部署资产已提供，上线前执行ops/ACCEPTANCE.md。全部工具有操作证据不等于所有C API和所有参数组合通过；raw EC与PEM/DER转换等API级管理差异见native/coverage-api.md。硬件/OpenSSL/SSO后续接入。不可为了让计数更好看而隐去这些边界。
