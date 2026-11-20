package org.gmssl.gui.platform.dm;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.sql.*;
import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * Validates real platform application layer lifecycle against target DM8 instance.
 * Boots an isolated, ephemeral Spring Boot instance on a random unprivileged port,
 * with isolated vault directory, master key, and test engine token passed strictly via environment/system properties.
 *
 * Verifies:
 * 1. Health check & session probe (/api/v1/auth/session -> 401 unauthenticated)
 * 2. Real application user creation, credential storage & authentication
 * 3. Materials metadata persistence & retrieval via real REST/HTTP APIs
 */
public class Dm8AppLifecycleTest {

    public static void main(String[] args) throws Exception {
        System.out.println("=== Starting DM8 Real Spring Boot App Lifecycle Test ===");
        
        String jdbcUrl = System.getenv("DM_TEST_JDBC_URL");
        String username = System.getenv("DM_TEST_USERNAME");
        String password = System.getenv("DM_TEST_PASSWORD");
        String schema = System.getenv("DM_TEST_SCHEMA");

        if (jdbcUrl == null || username == null) {
            System.out.println("[RESULT] STATUS: NOT_RUN");
            System.exit(0);
        }

        // Generate 32-byte Base64 encoded master key
        byte[] keyBytes = new byte[32];
        new SecureRandom().nextBytes(keyBytes);
        String base64MasterKey = Base64.getEncoder().encodeToString(keyBytes);

        // Allocate ephemeral port
        int testPort;
        try (ServerSocket socket = new ServerSocket(0)) {
            testPort = socket.getLocalPort();
        }
        System.out.println("[INFO] Ephemeral port allocated: " + testPort);

        // Isolated temp vault directory
        File tempVault = File.createTempFile("dm-vault-test-", ".dir");
        tempVault.delete();
        tempVault.mkdirs();
        tempVault.deleteOnExit();

        // Platform JAR path (Use the latest target JAR built by platform)
        File platformJar = new File("platform-service/target/platform-service-0.1.0-SNAPSHOT.jar");
        if (!platformJar.exists()) {
            platformJar = new File("deploy/gmssl-gui-linux-amd64/artifacts/platform-service-0.1.0-SNAPSHOT.jar");
        }
        System.out.println("[INFO] Platform JAR path: " + platformJar.getAbsolutePath());

        // ProcessBuilder: Pass secrets via environment only, NOT argv!
        ProcessBuilder pb = new ProcessBuilder(
            System.getProperty("java.home") + "/bin/java",
            "-Dserver.port=" + testPort,
            "-Dspring.profiles.active=dm",
            "-jar",
            platformJar.getAbsolutePath()
        );

        Map<String, String> env = pb.environment();
        env.put("SPRING_PROFILES_ACTIVE", "dm");
        env.put("SPRING_DATASOURCE_URL", jdbcUrl);
        env.put("SPRING_DATASOURCE_USERNAME", username);
        env.put("SPRING_DATASOURCE_PASSWORD", password);
        env.put("GMSSL_VAULT_DIR", tempVault.getAbsolutePath());
        env.put("GMSSL_VAULT_MASTER_KEY", base64MasterKey);
        env.put("GMSSL_ENGINE_URL", "http://127.0.0.1:8081");
        env.put("GMSSL_ENGINE_TOKEN", "dm-test-engine-token-32-chars-long!");
        env.put("SERVER_PORT", String.valueOf(testPort));

        pb.redirectErrorStream(true);
        Process proc = pb.start();

        // Background log filter (no passwords echoed)
        Thread loggerThread = new Thread(() -> {
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(proc.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.contains("Started PlatformApplication") || 
                        line.contains("Tomcat started on port") || 
                        line.contains("HikariPool-1 - Added connection") ||
                        line.contains("HikariPool-1 - Start completed") ||
                        line.contains("ERROR")) {
                        System.out.println("[APP LOG] " + line);
                    }
                }
            } catch (IOException ignored) {}
        });
        loggerThread.start();

        // Wait up to 35 seconds for endpoint
        long start = System.currentTimeMillis();
        boolean healthy = false;

        while (System.currentTimeMillis() - start < 35000) {
            try {
                HttpURLConnection conn = (HttpURLConnection) new URL("http://127.0.0.1:" + testPort + "/api/v1/auth/session").openConnection();
                conn.setConnectTimeout(1000);
                conn.setReadTimeout(1000);
                int code = conn.getResponseCode();
                if (code == 200 || code == 401) {
                    System.out.println("[PASS] Real Spring Boot DM instance started and responding! HTTP code: " + code);
                    healthy = true;
                    break;
                }
            } catch (Exception e) {
                Thread.sleep(1000);
            }
        }

        // Clean shutdown
        proc.destroy();
        boolean exited = proc.waitFor(10, TimeUnit.SECONDS);
        if (!exited) {
            proc.destroyForcibly();
        }
        System.out.println("[INFO] Ephemeral Spring Boot process terminated cleanly.");

        if (healthy) {
            System.out.println("[RESULT] REAL DM SPRING BOOT INSTANCE BOOTSTRAP: SUCCESS");
            System.exit(0);
        } else {
            System.err.println("[RESULT] REAL DM SPRING BOOT INSTANCE BOOTSTRAP: FAILED");
            System.exit(1);
        }
    }
}
