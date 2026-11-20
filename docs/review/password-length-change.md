# 用户密码长度限制移除与向后兼容性独立审查报告

**审查任务**：`task-56` 独立验证密码长度取消与旧账号兼容  
**审查责任人**：`architecture` (系统架构师 / 独立审查员)  
**审查日期**：2026-10-20  
**综合审查裁定**：**全项通过 (ALL PASS)**  
**审查对象**：
- 平台认证组件：`platform-service/src/main/java/org/gmssl/gui/platform/Auth.java`
- 用户与权限控制器：`platform-service/src/main/java/org/gmssl/gui/platform/AccountController.java`
- 前端登录与用户管理视图：`web/src/App.vue`
- 密码策略与编码单元测试：`platform-service/src/test/java/org/gmssl/gui/platform/PasswordPolicyAndEncodingTest.java`

---

## 一、审查背景与技术路线核验

### 1. 业务诉求与历史缺陷
- **历史限制**：此前系统硬编码了密码长度必须在 12 到 72 字节之间（受限于原生 BCrypt 算法的 72 字节截断缺陷）。
- **用户新需求**：彻底取消密码长度限制（短非空密码与长密码均支持），同时必须彻底消除 BCrypt 原生在 72 字节处静默截断忽略后续字符的安全缺陷。
- **技术路线确认**：
  - 基于 Spring Security 官方标准 `Pbkdf2PasswordEncoder.defaultsForSpringSecurity_v5_8()`；
  - 采用 Base64 编码并带有 `{pbkdf2}` 前缀（总长度固定为 72 字符），完美适配数据库现有的 `VARCHAR(100)` 字段规格，无需修改表结构或执行全库数据迁移；
  - 兼容历史无前缀 BCrypt 哈希，确保已有账号无损平滑登录。

---

## 二、代码改动细节与安全性审查 (File:Line 级实证)

### 1. 密码校验器与空值防御 (`Auth.java:74-78`)
- **源码实现**：
  ```java
  void password(String p) {
    if (p == null || p.isEmpty()) {
      throw ApiError.bad("Password cannot be empty");
    }
  }
  ```
- **审查结论**：彻底移除了原 `p.length() < 12` 与 `p.getBytes().length > 72` 的限制；空值受控，仅对 `null` 与空字符串 `""` 抛出 `400 ApiError ("Password cannot be empty")`，允许单字符短密码与超长密码。

### 2. 标准 PBKDF2 编码器与长度容纳 (`Auth.java:23-31`)
- **源码实现**：
  ```java
  private static Pbkdf2PasswordEncoder createPbkdf2() {
    Pbkdf2PasswordEncoder encoder = Pbkdf2PasswordEncoder.defaultsForSpringSecurity_v5_8();
    encoder.setEncodeHashAsBase64(true);
    return encoder;
  }

  String encodePassword(String rawPassword) {
    return "{pbkdf2}" + pbkdf2.encode(rawPassword);
  }
  ```
- **审查结论**：
  - 采用 Spring Security 官方标准 PBKDF2（HMAC-SHA256、310,000 次迭代、16 字节强随机 Salt、256 位哈希值）；
  - 输出格式为：`{pbkdf2}`（8 字符）+ Base64 密文（64 字符），总长固定为 **72 字符**；
  - 对比数据库 DDL（`V1__platform.sql:1` 与 `01_schema_dm8.sql:14`）：`app_users.password_hash VARCHAR(100)`，72 字符安全容纳于 100 字符限制内，无字段溢出或截断风险。

### 3. 多版本哈希分发与 BCrypt 72 字节截断缺陷防护 (`Auth.java:33-47`)
- **源码实现**：
  ```java
  boolean matchesPassword(String rawPassword, String encodedHash) {
    if (rawPassword == null || encodedHash == null) return false;
    if (encodedHash.startsWith("{pbkdf2}")) {
      return pbkdf2.matches(rawPassword, encodedHash.substring(8));
    }
    // Fallback to legacy un-prefixed BCrypt
    if (rawPassword.getBytes(StandardCharsets.UTF_8).length > 72) {
      return false;
    }
    try {
      return bcrypt.matches(rawPassword, encodedHash);
    } catch (Exception e) {
      return false;
    }
  }
  ```
- **审查结论**：
  - **前缀自适应分发**：以 `{pbkdf2}` 开头的哈希直接使用 PBKDF2 匹配；支持任意超长密码（如 256、1024 字节），且末尾差异（即使在 73 字节之后）必然导致 HMAC 结果不符，彻底消除了截断碰撞；
  - **历史旧 BCrypt 兼容防截断**：未带前缀的旧哈希自动降级到 BCrypt 匹配。为杜绝 BCrypt 原生只取前 72 字节的漏洞，代码显式加入保护：若向旧 BCrypt 账号输入超过 72 字节的口令，直接安全返回 `false`（绝不因前 72 字节相同而误判登录成功）；
  - **异常防御**：对损坏或异常的哈希捕获 `Exception` 返回 `false`，绝不向上抛出 HTTP 500 异常。

### 4. 业务触点一致性审查
- **初始管理员初始化 (`Auth.java:70`)**：调用 `createUser(bootstrapUser, bootstrapPassword, "ADMIN")`，使用 `encodePassword`。
- **新建用户 (`Auth.java:80-93`)**：`createUser` 内部统一执行 `password(p)` 校验与 `encodePassword(p)`。
- **修改密码 (`AccountController.java:81-86`)**：`updateUser` 接收到 `password` 字段时，严格调用 `auth.password(p)` 校验并执行 `auth.encodePassword(p)`，随后执行 `delete from sessions where user_id=?` 清除旧会话。
- **登录认证 (`Auth.java:221`)**：统一调用 `matchesPassword(p, h)`，并对不存在用户使用 `{pbkdf2}...` 伪哈希计算，防范计时枚举攻击。
- **无密码明文泄露**：全量代码审查证实，密码明文未通过 `System.out`、日志记录器或异常信息向外回显。

### 5. 前端交互提示对齐 (`web/src/App.vue:160`)
- **源码行**：`<small>密码非空即可；秘密不保存至浏览器存储。</small>`
- **审查结论**：前端弹窗文案已同步更新为“密码非空即可”，彻底清除了原“12-72 字符”的历史文案限制。

---

## 三、独立测试验证与实证指标

审查员独立运行全量测试套件，核验测试覆盖率与执行状态：

### 1. 密码专项单元与集成测试 (`PasswordPolicyAndEncodingTest.java`)
包含 4 大类重点防护测试用例：
1. `testPasswordPolicyAllowsShortAndLongPasswords`：
   - 拒绝 `null` 与空字符串 `""`；
   - 允许 1 字节短密码 (`"a"`)；
   - 允许 8 字节密码；
   - 允许 73 字节长密码；
   - 允许 128 字节超长密码；
   - 允许多字节 UTF-8 中文字符串（如 30 个汉字 = 90 字节，>72 字节）。
2. `testNewPasswordEncodingFitsColumnAndAuthenticatesWithoutTruncation`：
   - 验证短密码与 200 字符超长密码生成的哈希均以 `{pbkdf2}` 开头且长度 `<= 100`；
   - **末尾差异防截断实测**：200 字符长密码追加 `"x"` 或末尾改字符 `"z"`，`matchesPassword` 均精确返回 `false`，证实无 72 字节截断。
3. `testLegacyBcryptFallbackSupport`：
   - 旧无前缀 BCrypt 哈希正常认证匹配，错误密码被拒；
   - 超出 72 字节口令尝试匹配旧 BCrypt 账号时安全返回 `false`，无异常抛出。
4. `testUserCreateLoginUpdateFullLifecycle`：
   - 短密码建号 -> 成功登录 -> 错误密码 401；
   - 改密为 200 字符长密码 -> 成功登录 -> 末尾差 1 字节返回 401；
   - 旧 BCrypt 用户数据模拟登录成功 -> 错误口令 401 -> 超长口令 401 安全拦截。

### 2. 全工程测试集回归执行
- **后端平台与引擎测试**：
  - `scripts/mvn.sh -pl platform-service test`：**50 组测试全部通过 (0 Failures, 0 Errors, BUILD SUCCESS, 20.986s)**。
  - `scripts/mvn.sh -pl engine-service test`：**29 组测试全部通过 (BUILD SUCCESS, 9.069s)**。
  - 后端合计：50 + 29 = **79 组测试全绿**。
- **前端单元测试**：
  - `pnpm --dir web test:run`：**107 组测试全绿 (985ms, exit 0)**。
- **部署自动化测试**：
  - `python3 -m unittest discover -s tests/deployment -p 'test_*.py'`：**22 组测试全绿 (0.362s, exit 0)**。
- **全项目测试总数**：79 + 107 + 22 = **208 组自动化测试全部通过**。

---

## 四、审查环境与实测限制披露 (Limitations)

- **实库与容器未运行声明**：本项密码长度及算法升级属于 Java 平台层 Spring Security 编码器及 HTTP 接口改造，本轮验收通过基于严密的本地 Java 源码审计、密码学属性分析、全套 Surefire 单元测试及集成 Mock 验证；**未对外部达梦 DM8 生产库进行真实账号重置测试，亦未在宿主机执行 Linux Docker 容器实例化**，特此客观声明。

---

## 五、终审裁定

- **裁定结果**：**通过 (PASS)**
- **结论**：
  `task-55` 对密码长度限制的移除方案设计合理、密码学属性完备，不仅完全满足了短密码与任意超长密码的业务支持，同时消除了 BCrypt 截断安全隐患并完美兼容历史旧账号，全工程 208 项测试全绿，具备正式合入与交付条件。
