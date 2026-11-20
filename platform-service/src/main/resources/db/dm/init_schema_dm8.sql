-- 达梦数据库 (DM8) 初始化 DDL 脚本
-- 适用版本：DM8 (DaMeng Database 8)
-- 包含内容：对齐平台 V1 ~ V6 所有数据表结构、约束、索引与列属性
-- 执行约束：
-- 1. 建议在独立的空模式 (例如 GMSSL_TEST) 下由 DBA 预先执行
-- 2. 字段类型适配说明：
--    - encrypted_passphrase 采用 VARBINARY(4096) 适配 AES-256-GCM (12B nonce + 512B UTF-8 plaintext + 16B tag + padding)
--    - 布尔类型适配：DM8 原生不支持 BOOLEAN 关键字 (错误码 -6119)，采用标准 BIT 类型 (0/1) 映射，驱动层透明映射为 java.lang.Boolean
--    - 所有 VARCHAR 长度按原系统最大字符/字节规格定义

-- 1. 用户与认证
CREATE TABLE app_users (
  id VARCHAR(36) PRIMARY KEY,
  username VARCHAR(100) NOT NULL UNIQUE,
  password_hash VARCHAR(100) NOT NULL,
  role VARCHAR(10) NOT NULL,
  enabled BIT NOT NULL,
  created_at VARCHAR(40) NOT NULL
);

CREATE TABLE sessions (
  token_hash VARCHAR(64) PRIMARY KEY,
  user_id VARCHAR(36) NOT NULL REFERENCES app_users(id),
  csrf VARCHAR(100) NOT NULL,
  expires_at BIGINT NOT NULL
);

-- 2. 项目与成员关系
CREATE TABLE projects (
  id VARCHAR(36) PRIMARY KEY,
  name VARCHAR(200) NOT NULL,
  description VARCHAR(2000) NOT NULL,
  created_at VARCHAR(40) NOT NULL
);

CREATE TABLE memberships (
  project_id VARCHAR(36) NOT NULL REFERENCES projects(id),
  user_id VARCHAR(36) NOT NULL REFERENCES app_users(id),
  role VARCHAR(10) NOT NULL,
  PRIMARY KEY (project_id, user_id)
);

-- 3. 材料与密钥库 (含 V5 临时文件与 V6 generation_provider)
CREATE TABLE materials (
  id VARCHAR(36) PRIMARY KEY,
  project_id VARCHAR(36) NOT NULL REFERENCES projects(id),
  object_type VARCHAR(20) NOT NULL,
  name VARCHAR(200) NOT NULL,
  media_type VARCHAR(120) NOT NULL,
  byte_size BIGINT NOT NULL,
  algorithm VARCHAR(100),
  key_kind VARCHAR(40),
  encoding VARCHAR(10),
  usage_text VARCHAR(500),
  description VARCHAR(2000),
  fingerprint VARCHAR(64),
  stateful BIT NOT NULL,
  pending BIT NOT NULL,
  created_at VARCHAR(40) NOT NULL,
  updated_at VARCHAR(40) NOT NULL,
  temporary BIT DEFAULT 0 NOT NULL,
  bound_job_id VARCHAR(36),
  generation_provider VARCHAR(20)
);

-- 4. 任务作业与执行产物 (含 V3/V4 状态型标记)
CREATE TABLE jobs (
  id VARCHAR(36) PRIMARY KEY,
  project_id VARCHAR(36) NOT NULL REFERENCES projects(id),
  user_id VARCHAR(36) NOT NULL REFERENCES app_users(id),
  tool_id VARCHAR(100) NOT NULL,
  status VARCHAR(20) NOT NULL,
  created_at VARCHAR(40) NOT NULL,
  started_at VARCHAR(40),
  finished_at VARCHAR(40),
  exit_code INT,
  duration_ms BIGINT,
  error_text VARCHAR(300),
  stdout_preview VARCHAR(8000),
  stderr_preview VARCHAR(8000),
  truncated BIT NOT NULL
);

CREATE TABLE artifacts (
  id VARCHAR(36) PRIMARY KEY REFERENCES materials(id),
  job_id VARCHAR(36) NOT NULL REFERENCES jobs(id),
  sensitive BIT NOT NULL,
  stateful_private BIT DEFAULT 0 NOT NULL,
  stateful_source BIT DEFAULT 0 NOT NULL
);

-- 5. 审计事件
CREATE TABLE audit_events (
  id VARCHAR(36) PRIMARY KEY,
  project_id VARCHAR(36),
  actor VARCHAR(36) NOT NULL,
  action VARCHAR(100) NOT NULL,
  resource_type VARCHAR(30) NOT NULL,
  resource_id VARCHAR(36),
  outcome VARCHAR(30) NOT NULL,
  created_at VARCHAR(40) NOT NULL
);

CREATE INDEX audit_project ON audit_events(project_id, created_at);

-- 6. 状态型密钥防重与晋升 (V2, V3)
CREATE TABLE stateful_material_history (
  digest VARCHAR(64) PRIMARY KEY,
  material_id VARCHAR(36) NOT NULL,
  created_at VARCHAR(40) NOT NULL
);

CREATE TABLE stateful_promotions (
  source_artifact_id VARCHAR(36) PRIMARY KEY,
  key_id VARCHAR(36) NOT NULL,
  created_at VARCHAR(40) NOT NULL
);

-- 7. 托管密钥凭据 (V6)
-- 达梦中使用 VARBINARY(4096) 存储 AES-256-GCM 加密口令密文
CREATE TABLE key_credentials (
  material_id VARCHAR(36) PRIMARY KEY REFERENCES materials(id) ON DELETE CASCADE,
  encrypted_passphrase VARBINARY(4096) NOT NULL,
  created_at VARCHAR(40) NOT NULL,
  updated_at VARCHAR(40) NOT NULL
);
