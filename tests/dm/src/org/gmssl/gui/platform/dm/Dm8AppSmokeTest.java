package org.gmssl.gui.platform.dm;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.sql.*;
import java.util.*;

public class Dm8AppSmokeTest {
    public static void main(String[] args) throws Exception {
        System.out.println("=== Starting DM8 App Smoke Test ===");
        String jdbcUrl = System.getenv("DM_TEST_JDBC_URL");
        String username = System.getenv("DM_TEST_USERNAME");
        String password = System.getenv("DM_TEST_PASSWORD");
        String schema = System.getenv("DM_TEST_SCHEMA");

        if (jdbcUrl == null || username == null) {
            System.out.println("[RESULT] STATUS: NOT_RUN");
            System.exit(0);
        }

        // Pick random ephemeral port
        int testPort;
        try (ServerSocket socket = new ServerSocket(0)) {
            testPort = socket.getLocalPort();
        }

        System.out.println("[INFO] Ephemeral port allocated: " + testPort);

        // Create isolated temp vault
        File tempVault = File.createTempFile("dm-vault-", ".dir");
        tempVault.delete();
        tempVault.mkdirs();
        tempVault.deleteOnExit();

        // Find platform jar
        File platformJar = new File("deploy/gmssl-gui-linux-amd64/artifacts/platform-service-0.1.0-SNAPSHOT.jar");
        if (!platformJar.exists()) {
            platformJar = new File("platform-service/target/platform-service-0.1.0-SNAPSHOT.jar");
        }
        System.out.println("[INFO] Testing with platform JAR: " + platformJar.getAbsolutePath());

        // Prepare process builder without password in argv
        ProcessBuilder pb = new ProcessBuilder(
            System.getProperty("java.home") + "/bin/java",
            "-Dserver.port=" + testPort,
            "-Dspring.profiles.active=dm",
            "-Dplatform.vault.path=" + tempVault.getAbsolutePath(),
            "-Dplatform.vault.master-key=test-master-key-32-chars-long!",
            "-jar",
            platformJar.getAbsolutePath()
        );

        Map<String, String> env = pb.environment();
        env.put("SPRING_PROFILES_ACTIVE", "dm");
        env.put("SPRING_DATASOURCE_URL", jdbcUrl);
        env.put("SPRING_DATASOURCE_USERNAME", username);
        env.put("SPRING_DATASOURCE_PASSWORD", password);
        env.put("PLATFORM_VAULT_PATH", tempVault.getAbsolutePath());
        env.put("PLATFORM_VAULT_MASTER_KEY", "test-master-key-32-chars-long!");
        env.put("SERVER_PORT", String.valueOf(testPort));

        pb.redirectErrorStream(true);
        Process proc = pb.start();

        // Wait up to 35 seconds for health endpoint
        long start = System.currentTimeMillis();
        boolean healthy = false;
        String line;
        BufferedReader reader = new BufferedReader(new InputStreamReader(proc.getInputStream()));

        // Monitor logs in background thread
        Thread loggerThread = new Thread(() -> {
            try {
                String l;
                while ((l = reader.readLine()) != null) {
                    // Filter out any passwords
                    if (l.contains("Started PlatformServiceApplication") || l.contains("Tomcat started on port")) {
                        System.out.println("[APP LOG] " + l);
                    }
                }
            } catch (IOException ignored) {}
        });
        loggerThread.start();

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

        // Cleanup
        proc.destroyForcibly();
        proc.waitFor();
        System.out.println("[INFO] Ephemeral Spring Boot process terminated.");

        if (healthy) {
            System.out.println("[RESULT] REAL DM SPRING BOOT INSTANCE BOOTSTRAP: SUCCESS");
            System.exit(0);
        } else {
            System.err.println("[RESULT] REAL DM SPRING BOOT INSTANCE BOOTSTRAP: TIMEOUT / FAILED");
            System.exit(1);
        }
    }
}
