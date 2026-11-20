-- SPDX-License-Identifier: Apache-2.0
-- GmSSL Web Toolbox: Dameng DM8 Database Schema Versioning & Baseline Script
-- Target DBMS: Dameng Database 8 (DM8)
--
-- 说明与执行约束：
-- 1. 本脚本用于为【已有且结构完整的生产库】显式登记 0.1.0 版本基线；
-- 2. 严禁盲目给结构缺失、类型不匹配的库标记版本！
--    本脚本使用 DM8 PL/SQL 块在登记前执行严格前置核验：
--    - 优先检查已有版本元数据状态：若存在 0.1.0 且 success != 1，立即抛出 -20010 异常阻断；
--    - 执行核心物理结构核验：
--      * 必须完整存在 11 张核心业务表 (app_users, sessions, projects, memberships, materials, jobs, artifacts, audit_events, stateful_material_history, stateful_promotions, key_credentials)；
--      * 必须核验 materials.temporary 列类型为 BIT；
--      * 必须核验 key_credentials.encrypted_passphrase 列类型为 VARBINARY 且长度 data_length >= 4096；
--      若任意前置物理校验不通过，立即抛出异常并中止，绝不标上错误的基线版本，也不在重入时掩盖 schema 漂移；
--    - 物理结构完全达标后：
--      * 若已有 0.1.0 记录且 success = 1，则视为基线已成功登记，打印提示并幂等退出（不重复插入）；
--      * 若尚无 0.1.0 记录，则安全插入基线记录。
-- 3. 首次全新空库部署请执行 artifacts/01_schema_dm8.sql，勿使用本脚本伪造基线。

-- 1. 创建版本元数据表 (若已存在则忽略)
CREATE TABLE IF NOT EXISTS schema_version (
    version VARCHAR(50) PRIMARY KEY,
    description VARCHAR(200) NOT NULL,
    installed_on VARCHAR(40) NOT NULL,
    checksum VARCHAR(64),
    success BIT DEFAULT 1 NOT NULL
);

-- 2. 深度前置校验并安全登记 0.1.0 基线
DECLARE
    v_table_count INT := 0;
    v_mat_bit_type INT := 0;
    v_cred_bin_type INT := 0;
    v_existing_count INT := 0;
    v_existing_success INT := 0;
BEGIN
    -- 1. 检查 schema_version 中是否已有 0.1.0 记录，若有且失败则立即阻断
    SELECT COUNT(*) INTO v_existing_count FROM schema_version WHERE version = '0.1.0';
    IF v_existing_count > 0 THEN
        SELECT success INTO v_existing_success FROM schema_version WHERE version = '0.1.0';
        IF v_existing_success != 1 THEN
            RAISE_APPLICATION_ERROR(-20010, 'DM8 Baseline Verification Failed: Existing 0.1.0 record marks success=0 (failed previous run). Manual resolution required.');
        END IF;
    END IF;

    -- 2. 深度物理结构核验：核查 11 张核心业务表是否存在于当前模式中
    SELECT COUNT(DISTINCT table_name) INTO v_table_count 
    FROM user_tables 
    WHERE table_name IN (
        'APP_USERS', 'SESSIONS', 'PROJECTS', 'MEMBERSHIPS', 
        'MATERIALS', 'JOBS', 'ARTIFACTS', 'AUDIT_EVENTS', 
        'STATEFUL_MATERIAL_HISTORY', 'STATEFUL_PROMOTIONS', 'KEY_CREDENTIALS'
    );

    IF v_table_count < 11 THEN
        RAISE_APPLICATION_ERROR(-20001, 'DM8 Baseline Verification Failed: Missing required tables in current schema. Found: ' || v_table_count || '/11');
    END IF;

    -- 3. 深度物理结构核验：核验 materials.temporary 列是否为 BIT 类型
    SELECT COUNT(*) INTO v_mat_bit_type 
    FROM user_tab_columns 
    WHERE table_name = 'MATERIALS' AND column_name = 'TEMPORARY' AND data_type = 'BIT';

    IF v_mat_bit_type = 0 THEN
        RAISE_APPLICATION_ERROR(-20002, 'DM8 Baseline Verification Failed: MATERIALS.TEMPORARY is not BIT type. Please align schema first.');
    END IF;

    -- 4. 深度物理结构核验：核验 key_credentials.encrypted_passphrase 是否为 VARBINARY 类型且长度 >= 4096
    SELECT COUNT(*) INTO v_cred_bin_type 
    FROM user_tab_columns 
    WHERE table_name = 'KEY_CREDENTIALS' 
      AND column_name = 'ENCRYPTED_PASSPHRASE' 
      AND data_type = 'VARBINARY'
      AND data_length >= 4096;

    IF v_cred_bin_type = 0 THEN
        RAISE_APPLICATION_ERROR(-20003, 'DM8 Baseline Verification Failed: KEY_CREDENTIALS.ENCRYPTED_PASSPHRASE is not VARBINARY or length < 4096.');
    END IF;

    -- 5. 物理结构完全达标后，若已有 0.1.0 成功记录，则幂等跳过
    IF v_existing_count > 0 AND v_existing_success = 1 THEN
        PRINT 'SUCCESS: Verified existing valid 0.1.0 baseline (physical schema and success=1 verified). Skipping redundant insertion.';
        RETURN;
    END IF;

    -- 6. 物理结构完全达标且尚无版本记录，安全记录基线
    INSERT INTO schema_version (version, description, installed_on, checksum, success)
    VALUES (
        '0.1.0', 
        'Base Schema v0.1.0 (Verified: 11 tables, BIT booleans, VARBINARY(4096) encrypted passphrases)', 
        '2026-10-19T08:00:00Z', 
        '32d422f198c02819ed54710a17eac363b4487e63b0f33261c6d7777349c799da', 
        1
    );

    PRINT 'SUCCESS: Existing DM8 database verified and registered as v0.1.0 baseline in schema_version.';
END;
/
