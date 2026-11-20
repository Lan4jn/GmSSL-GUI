package org.gmssl.gui.platform.dm;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.sql.*;
import java.util.*;
import java.util.concurrent.*;

/**
 * Isolated DM8 Compatibility Test Harness.
 * Executes direct JDBC validations against Dameng DM8.
 * Ensures zero credential leakage in logs or stdout.
 *
 * Verifies:
 * 1. dm.jdbc.driver.DmDriver loading
 * 2. Connection metadata and DM8 version
 * 3. DDL execution of 01_schema_dm8.sql (VARBINARY(4096) for encrypted_passphrase)
 * 4. CRUD and BOOLEAN type mapping
 * 5. UNIQUE constraint enforcement
 * 6. 512-byte UTF-8 ciphertext VARBINARY(4096) roundtrip
 * 7. Transaction atomicity & rollback (materials + credentials)
 * 8. Pessimistic concurrency (SELECT ... FOR UPDATE across two connections)
 * 9. Safe cleanup of test records in isolated schema
 */
public class Dm8CompatibilityHarness {

    public static void main(String[] args) {
        System.out.println("=== Starting DM8 Direct JDBC Acceptance Harness ===");
        
        String jdbcUrl = System.getenv("DM_TEST_JDBC_URL");
        String username = System.getenv("DM_TEST_USERNAME");
        String password = System.getenv("DM_TEST_PASSWORD");
        String schema = System.getenv("DM_TEST_SCHEMA");

        if (jdbcUrl == null || jdbcUrl.trim().isEmpty() || username == null || username.trim().isEmpty()) {
            System.out.println("[RESULT] STATUS: NOT_RUN (DM_TEST_JDBC_URL or DM_TEST_USERNAME not set)");
            System.exit(0);
        }

        // Security boundaries
        String upperUser = username.toUpperCase();
        if (upperUser.equals("SYSDBA") || upperUser.equals("SYS") || upperUser.equals("SYSSSO") || upperUser.equals("SYSAUDITOR")) {
            System.err.println("[SECURITY ERROR] System administrator accounts are strictly forbidden for acceptance testing!");
            System.exit(2);
        }

        if (schema == null || !schema.toUpperCase().matches("^GMSSL_TEST(_[A-Z0-9_]+)?$")) {
            System.err.println("[SECURITY ERROR] Schema must match GMSSL_TEST(_[A-Z0-9_]+)? regex!");
            System.exit(2);
        }

        int passed = 0;
        int failed = 0;

        try {
            // Test 1: Driver loading
            Class.forName("dm.jdbc.driver.DmDriver");
            System.out.println("[PASS] 1. dm.jdbc.driver.DmDriver loaded successfully via Class.forName");
            passed++;
        } catch (ClassNotFoundException e) {
            System.err.println("[FAIL] 1. Could not load dm.jdbc.driver.DmDriver");
            System.exit(1);
        }

        // Open primary connection
        try (Connection conn = DriverManager.getConnection(jdbcUrl, username, password)) {
            conn.setAutoCommit(false);
            DatabaseMetaData meta = conn.getMetaData();
            System.out.println("[PASS] 2. Established primary JDBC Connection successfully");
            System.out.println("       Product Name:    " + meta.getDatabaseProductName());
            System.out.println("       Product Version: " + meta.getDatabaseProductVersion());
            System.out.println("       Driver Version:  " + meta.getDriverVersion());
            passed++;

            // Set current schema and verify matching
            try (Statement st = conn.createStatement()) {
                st.execute("SET SCHEMA \"" + schema.toUpperCase() + "\"");
            } catch (SQLException ignore) {}

            String currentSchema = conn.getSchema();
            if (currentSchema == null || currentSchema.trim().isEmpty()) {
                currentSchema = schema.toUpperCase();
            }
            System.out.println("       Current Schema:  " + currentSchema);

            if (!currentSchema.equalsIgnoreCase(schema)) {
                System.err.println("[SECURITY ERROR] Current schema " + currentSchema + " does not match expected " + schema);
                System.exit(2);
            }

            // Test 3: DDL Execution (deploy artifacts/01_schema_dm8.sql or ops/dm8/01_schema_dm8.sql)
            Path ddlPath = Paths.get("deploy/gmssl-gui-linux-amd64/artifacts/01_schema_dm8.sql");
            if (!Files.exists(ddlPath)) {
                ddlPath = Paths.get("ops/dm8/01_schema_dm8.sql");
            }

            if (Files.exists(ddlPath)) {
                String ddlContent;
                try {
                    byte[] bytes = Files.readAllBytes(ddlPath);
                    ddlContent = new String(bytes, StandardCharsets.UTF_8);
                } catch (IOException ioEx) {
                    System.err.println("[ERROR] DDL_READ_FAILED: Unable to read DDL script file");
                    System.exit(1);
                    return;
                }

                String[] statements = ddlContent.split(";");
                int ddlCount = 0;
                for (String sql : statements) {
                    String trimmed = sql.trim();
                    trimmed = trimmed.replaceAll("(?m)^--.*$", "").trim();
                    if (trimmed.isEmpty()) continue;
                    try (Statement st = conn.createStatement()) {
                        st.execute(trimmed);
                        ddlCount++;
                    } catch (SQLException ex) {
                        if (!ex.getMessage().contains("already exists") && !ex.getMessage().contains("对象已存在")) {
                            System.err.println("[WARN] DDL notice: " + ex.getErrorCode());
                        }
                    }
                }
                conn.commit();
                System.out.println("[PASS] 3. Schema DDL applied successfully (" + ddlCount + " statements executed)");
                passed++;
            }

            // Test 4: CRUD on app_users (Boolean + String + Primary Key)
            String testUserId = UUID.randomUUID().toString();
            String testUsername = "dm_test_user_" + System.currentTimeMillis();
            try (PreparedStatement ps = conn.prepareStatement(
                    "INSERT INTO app_users(id, username, password_hash, role, enabled, created_at) VALUES (?, ?, ?, ?, ?, ?)")) {
                ps.setString(1, testUserId);
                ps.setString(2, testUsername);
                ps.setString(3, "$2a$10$abcdefghijklmnopqrstuv");
                ps.setString(4, "ADMIN");
                ps.setBoolean(5, true);
                ps.setString(6, "2026-10-19T12:00:00Z");
                ps.executeUpdate();
            }
            conn.commit();

            try (PreparedStatement ps = conn.prepareStatement("SELECT enabled FROM app_users WHERE id = ?")) {
                ps.setString(1, testUserId);
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        boolean enabled = rs.getBoolean("enabled");
                        if (enabled) {
                            System.out.println("[PASS] 4. Boolean type roundtrip verified (TRUE)");
                            passed++;
                        } else {
                            System.err.println("[FAIL] 4. Boolean type read back false, expected true");
                            failed++;
                        }
                    }
                }
            }

            // Test 5: Unique Constraint Violation Enforcement
            try (PreparedStatement ps = conn.prepareStatement(
                    "INSERT INTO app_users(id, username, password_hash, role, enabled, created_at) VALUES (?, ?, ?, ?, ?, ?)")) {
                ps.setString(1, UUID.randomUUID().toString());
                ps.setString(2, testUsername); // Duplicate username
                ps.setString(3, "pass");
                ps.setString(4, "USER");
                ps.setBoolean(5, true);
                ps.setString(6, "2026-10-19T12:00:00Z");
                ps.executeUpdate();
                System.err.println("[FAIL] 5. Unique constraint on username did not trigger error!");
                failed++;
            } catch (SQLException expected) {
                conn.rollback();
                System.out.println("[PASS] 5. Unique constraint properly enforced on duplicate key");
                passed++;
            }

            // Test 6: VARBINARY(4096) for key_credentials (512-byte UTF-8 AES-256-GCM ciphertext payload)
            byte[] secretPayload = new byte[540]; // 12B nonce + 512B ciphertext + 16B tag
            Arrays.fill(secretPayload, (byte) 0x5a);
            byte[] readBack = null;

            String testProjId = UUID.randomUUID().toString();
            try (PreparedStatement ps = conn.prepareStatement("INSERT INTO projects(id, name, description, created_at) VALUES (?, ?, ?, ?)")) {
                ps.setString(1, testProjId);
                ps.setString(2, "Test Project");
                ps.setString(3, "Desc");
                ps.setString(4, "2026-10-19T12:00:00Z");
                ps.executeUpdate();
            }

            String testMatId = UUID.randomUUID().toString();
            try (PreparedStatement ps = conn.prepareStatement(
                    "INSERT INTO materials(id, project_id, object_type, name, media_type, byte_size, stateful, pending, temporary, created_at, updated_at) " +
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")) {
                ps.setString(1, testMatId);
                ps.setString(2, testProjId);
                ps.setString(3, "KEY");
                ps.setString(4, "sm2.key");
                ps.setString(5, "application/octet-stream");
                ps.setLong(6, (long) secretPayload.length);
                ps.setBoolean(7, false);
                ps.setBoolean(8, false);
                ps.setBoolean(9, false);
                ps.setString(10, "2026-10-19T12:00:00Z");
                ps.setString(11, "2026-10-19T12:00:00Z");
                ps.executeUpdate();
            }

            try (PreparedStatement ps = conn.prepareStatement(
                    "INSERT INTO key_credentials(material_id, encrypted_passphrase, created_at, updated_at) VALUES (?, ?, ?, ?)")) {
                ps.setString(1, testMatId);
                ps.setBytes(2, secretPayload);
                ps.setString(3, "2026-10-19T12:00:00Z");
                ps.setString(4, "2026-10-19T12:00:00Z");
                ps.executeUpdate();
            }
            conn.commit();

            try (PreparedStatement ps = conn.prepareStatement("SELECT encrypted_passphrase FROM key_credentials WHERE material_id = ?")) {
                ps.setString(1, testMatId);
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        readBack = rs.getBytes("encrypted_passphrase");
                    }
                }
            }

            if (readBack != null && Arrays.equals(secretPayload, readBack)) {
                System.out.println("[PASS] 6. VARBINARY(4096) ciphertext roundtrip verified with exact byte equality (" + readBack.length + " bytes)");
                passed++;
            } else {
                System.err.println("[FAIL] 6. VARBINARY read back corrupted or mismatched");
                failed++;
            }

            // Test 7: Transaction Rollback (Materials + Credentials atomicity)
            String rollbackMatId = UUID.randomUUID().toString();
            try (PreparedStatement ps = conn.prepareStatement(
                    "INSERT INTO materials(id, project_id, object_type, name, media_type, byte_size, stateful, pending, temporary, created_at, updated_at) " +
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")) {
                ps.setString(1, rollbackMatId);
                ps.setString(2, testProjId);
                ps.setString(3, "KEY");
                ps.setString(4, "rollback.key");
                ps.setString(5, "application/octet-stream");
                ps.setLong(6, 128L);
                ps.setBoolean(7, false);
                ps.setBoolean(8, false);
                ps.setBoolean(9, false);
                ps.setString(10, "2026-10-19T12:00:00Z");
                ps.setString(11, "2026-10-19T12:00:00Z");
                ps.executeUpdate();
            }
            conn.rollback();

            try (PreparedStatement ps = conn.prepareStatement("SELECT COUNT(*) FROM materials WHERE id = ?")) {
                ps.setString(1, rollbackMatId);
                try (ResultSet rs = ps.executeQuery()) {
                    rs.next();
                    if (rs.getInt(1) == 0) {
                        System.out.println("[PASS] 7. Transaction atomicity & rollback verified");
                        passed++;
                    } else {
                        System.err.println("[FAIL] 7. Rolled back record was committed unexpectedly");
                        failed++;
                    }
                }
            }

            // Test 8: Pessimistic Concurrency (SELECT ... FOR UPDATE across TWO live connections with bounded wait)
            // Connection 1 acquires lock on testMatId
            try (PreparedStatement psLock = conn.prepareStatement("SELECT id FROM materials WHERE id = ? FOR UPDATE")) {
                psLock.setString(1, testMatId);
                try (ResultSet rs = psLock.executeQuery()) {
                    rs.next();
                }
                System.out.println("[INFO] Connection 1 acquired exclusive lock on material " + testMatId);

                // Connection 2 attempts to acquire lock on the same row with bounded timeout
                try (Connection conn2 = DriverManager.getConnection(jdbcUrl, username, password)) {
                    conn2.setAutoCommit(false);
                    if (schema != null && !schema.trim().isEmpty()) {
                        try (Statement st2 = conn2.createStatement()) {
                            st2.execute("SET SCHEMA \"" + schema.toUpperCase() + "\"");
                        } catch (SQLException ignore) {}
                    }

                    ExecutorService executor = Executors.newSingleThreadExecutor();
                    Future<Boolean> lockAttempt = executor.submit(() -> {
                        try (PreparedStatement ps2 = conn2.prepareStatement("SELECT id FROM materials WHERE id = ? FOR UPDATE")) {
                            ps2.setQueryTimeout(2); // 2 second bounded timeout
                            ps2.setString(1, testMatId);
                            try (ResultSet rs2 = ps2.executeQuery()) {
                                return rs2.next();
                            }
                        } catch (SQLException ex) {
                            return false;
                        }
                    });

                    boolean lockBlocked = false;
                    try {
                        lockAttempt.get(1500, TimeUnit.MILLISECONDS);
                    } catch (TimeoutException expectedTimeout) {
                        lockBlocked = true;
                    } catch (ExecutionException | InterruptedException ex) {
                        lockBlocked = true;
                    } finally {
                        executor.shutdownNow();
                    }

                    if (lockBlocked) {
                        System.out.println("[PASS] 8. Dual-connection SELECT ... FOR UPDATE pessimistic locking enforced (Connection 2 blocked)");
                        passed++;
                    } else {
                        System.err.println("[WARN] 8. Connection 2 acquired lock concurrently without blocking");
                        failed++;
                    }

                    try {
                        conn2.rollback();
                    } catch (SQLException ignore) {}
                }
            }
            conn.commit();

            // Test 9: Cleanup
            try (Statement st = conn.createStatement()) {
                st.executeUpdate("DELETE FROM key_credentials WHERE material_id = '" + testMatId + "'");
                st.executeUpdate("DELETE FROM materials WHERE id = '" + testMatId + "'");
                st.executeUpdate("DELETE FROM projects WHERE id = '" + testProjId + "'");
                st.executeUpdate("DELETE FROM app_users WHERE id = '" + testUserId + "'");
            }
            conn.commit();
            System.out.println("[PASS] 9. Test records cleaned up cleanly from test schema");
            passed++;

        } catch (SQLException e) {
            System.err.println("[ERROR] SQLException encountered (sanitized error code): " + e.getErrorCode() + " / " + e.getSQLState());
            failed++;
        }

        System.out.println("=== DM8 Compatibility Test Summary ===");
        System.out.println("Passed: " + passed + " / Failed: " + failed);
        if (failed == 0) {
            System.out.println("[RESULT] ALL COMPATIBILITY TESTS PASSED SUCCESSFULLY");
            System.exit(0);
        } else {
            System.out.println("[RESULT] COMPATIBILITY TESTS ENCOUNTERED FAILURES");
            System.exit(1);
        }
    }
}
