# DM8 升级基线真实验证（task-49）

## 实测结论

- 实际命令：`python3 tests/dm/run_baseline_probe.py --compile-only`，exit 0；随后 `python3 tests/dm/run_baseline_probe.py --execute`，exit 0。测试 JVM 已退出，无服务启停操作。
- 真实目标经 JDBC getSchema/getUserName 双重限定为 `GMSSL_TEST`，唯一凭据输入为用户指定 `.env.dm-test`；不读取 preview 私有环境、主密钥或 Vault。
- 执行脚本：`ops/dm8/migrations/00_schema_version_and_baseline.sql`，SHA-256 **8a1dfcd8b4d947806a2168dcafdb66fb930b1e1ddb2c315d3bad856825788cee**。原 b604cad… 版本仅审查，未执行。
- 解析为 **2 个完整 JDBC 语句块**：CREATE TABLE DDL 与 DECLARE…END; PL/SQL。只去除整行注释及末尾 SQL 客户端 `/`，没有按分号盲拆 PL/SQL。
- 首次执行前 schema_version 不存在；真实 DM8 CREATE TABLE IF NOT EXISTS 与完整原始 PL/SQL 均通过，留下新表及一行 `version=0.1.0 / success=1 / checksum=32d422f198c02819ed54710a17eac363b4487e63b0f33261c6d7777349c799da`。元数据保留，未 DROP/DELETE/UPDATE。
- 再执行同一 DDL 与完整 PL/SQL，比较 schema_version 的 version/description/installed_on/checksum/success 全字段，精确不变，没有重复登记或改写原记录。

## 真实元数据与只读负例

- 实存 **11 张核心业务表**：app_users、sessions、projects、memberships、materials、jobs、artifacts、audit_events、stateful_material_history、stateful_promotions、key_credentials；新增 version 后识别表数为 12。此前 9/10 张说法不作为依据。
- materials.pending/temporary：BIT、JDBC COLUMN_SIZE=1；key_credentials.encrypted_passphrase：VARBINARY、COLUMN_SIZE=4096。各业务表索引名称/列/唯一属性已通过 DatabaseMetaData 读取，详见脱敏日志。基线 SQL 仅核表集合及两项关键列契约，不等于全部列、外键、CHECK、索引和约束的完整一致性核验。
- JDBC table/column 名称返回小写，但原 SQL uppercase IN predicate 真实匹配 11，本实例未出现大小写比较失败。
- 五个负例使用原 PL/SQL 的**独立只读派生副本**：将 INSERT 段替换 NULL，禁 INSERT/UPDATE/DELETE/CREATE/DROP/ALTER；只替换查询值或校验谓词，不改任何表、列或已有 version 记录。
- 既有 success=0 模拟：实际错误码 **-20010**；既有 checksum 不匹配模拟：**-20011**；缺表谓词模拟：**-20001**；BIT 类型不符模拟：**-20002**；VARBINARY 长度不足模拟：**-20003**。未吞错误报成功，任一码不符会使 helper exit 1。
- 这些是读取真实元数据并注入查询/谓词的分支验证，不声称在数据库中制造过失败行、缺表或错误列类型。负例前后 version 全字段再次精确不变。

## 业务数据与运行态边界

- SQL 审查及执行块仅写 schema_version；测试 helper 对 11 业务表只做 SELECT COUNT/metadata/index 读取。未读取材料正文、Vault、用户口令、私钥；未启动/停止 preview。
- 辅助行数前后相同：app_users=3、sessions=5、projects=2、memberships=2、materials=7、jobs=3、artifacts=3、audit_events=56、stateful_material_history=0、stateful_promotions=0、key_credentials=1。行数比较不等同内容校验或不存在并发，亦不作为业务数据逐字节不变证明。
- 协调时序缺口：已向 integration 发送短窗口只写 version 的预告，但 Lead 要求“写入前等 integration 明确回执”的消息到达前实测已完成；未等明确回执的事实已及时回报，未伪称独占确认。之后不再连库。
- preview 18088 运行恢复由 integration task-50 独立处理，本任务不读其 runtime/privateenv，不声称由本任务恢复或验证其在线状态。

## 可复核证据

- 新增测试源码：`tests/dm/DmBaselineProbe.java`、`tests/dm/run_baseline_probe.py`；只新增测试，不修改 ops/release。
- 初始只读日志：`.tools/logs/dm-upgrade-metadata.log`；真实执行日志：`.tools/logs/dm-upgrade-execution.log`（0600，仅固定前缀脱敏输出，无 URL/password/原始 SQLException）。
- 执行日志末尾通用 `RESULT PASS READ_ONLY_METADATA` 为 helper 复用的静态标签，**不是本轮只读的声明**；本轮确已执行获准的 schema_version DDL/登记，真实 `DDL PASS / PLSQL_REGISTER PASS / REPEAT... / NEGATIVE... / EXIT 0` 为判定依据。
- 当前归档 4ece0d49a549019781e91c6897976a0286f4af7ecd60c90cc803f4c764573fd4 由 build-quality 提供，属于升级中间候选；本任务未把它宣称为最终发布身份，也未改包。

## 最新离线版差异实测（4964 bytes，取代旧版门禁结论）

- 已只读比对 source、deploy 目录副本与 tar 内同路径 SQL，三处逐字节一致，均 4964 bytes；source mtime `2026-10-20T11:31:54.458347+08:00`，deploy mtime `2026-10-20T11:32:14.346840+08:00`。不要求用户提供或校验文件 hash。
- 实际命令仍为 `python3 tests/dm/run_baseline_probe.py --compile-only`、`python3 tests/dm/run_baseline_probe.py --execute`，均 exit 0。helper 已更新为本次差异范围；上述旧版实测段仅为历史事实，不冒充新版结果。
- 新版无 checksum 比较门禁；已有记录先检查 success，再无条件检查 11 表、BIT、VARBINARY 长度，最后才允许成功 RETURN（源码行 55/64/76 先于 81–83）。
- 完整原同文两块 CREATE TABLE IF NOT EXISTS 与 DECLARE…END; 在现存版本上重入通过；执行前后 schema_version 全部五字段精确相同。原 0.1.0 / success=1 / checksum=32d422… 旧值完整保留，不置空、不覆盖、不删除。
- 四个只读派生副本均删除 INSERT 为 NULL，并禁 DML/DDL：success=0 注入实际 -20010；已有成功记录下缺表谓词模拟 -20001、BIT 不符模拟 -20002、VARBINARY 长度不足模拟 -20003，证明已有成功记录不会绕过结构校验。未制造错误表/版本行，不再测试已移除的 checksum 门禁。
- 新脱敏日志 `.tools/logs/dm-upgrade-nohash-reentry.log`（0600）：`RESULT PASS NOHASH_REENTRY_AND_FOUR_READONLY_NEGATIVES`、`EXIT 0`。旧日志保留未覆盖。
- 本次不写任何业务表，不改旧 metadata，不操作 preview、账号或 Vault；实时会话/审计计数较历史可能变化，不将其归于基线或声称没有并发。仅验证必要差异，不新增用例，结束后不再连库。
