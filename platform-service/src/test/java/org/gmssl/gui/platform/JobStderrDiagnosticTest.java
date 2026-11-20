package org.gmssl.gui.platform;

import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

@SpringBootTest
class JobStderrDiagnosticTest {

  static HttpServer server;
  static Path dir;
  static ObjectMapper mapper = new ObjectMapper();
  static AtomicReference<String> engineStderrToReturn = new AtomicReference<>();
  static AtomicReference<String> engineStatusToReturn = new AtomicReference<>("FAILED");
  static AtomicReference<Integer> engineExitCodeToReturn = new AtomicReference<>(1);

  @DynamicPropertySource
  static void properties(DynamicPropertyRegistry p) throws Exception {
    dir = Files.createTempDirectory("platform-stderr-test-vault");
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.setExecutor(Executors.newCachedThreadPool());
    server.createContext(
        "/internal/v1/",
        ex -> {
          try {
            if (!"test-token".equals(ex.getRequestHeaders().getFirst("X-Engine-Token"))) {
              ex.sendResponseHeaders(401, -1);
              return;
            }
            Object response;
            if (ex.getRequestURI().getPath().endsWith("capabilities")) {
              response = Map.of(
                  "provider", "gmssl",
                  "version", "fixture",
                  "sourceCommit", "fixture",
                  "categories", List.of("pki"),
                  "coverage", Map.of(),
                  "tools", List.of(
                      Map.of(
                          "id", "reqsign",
                          "label", "reqsign",
                          "category", "pki",
                          "command", List.of("reqsign"),
                          "parameters", List.of(),
                          "stateful", false,
                          "sensitiveOutput", false
                      )
                  )
              );
            } else {
              var in = mapper.readTree(ex.getRequestBody());
              var out = mapper.createObjectNode();
              out.put("id", in.path("id").asText());
              out.put("status", engineStatusToReturn.get());
              out.put("exitCode", engineExitCodeToReturn.get());
              out.put("durationMs", 25L);
              out.put("stdoutBase64", "");
              out.put("stderr", engineStderrToReturn.get());
              out.put("truncated", false);
              out.putArray("artifacts");
              out.putArray("updatedInputs");
              response = out;
            }
            byte[] bytes = mapper.writeValueAsBytes(response);
            ex.getResponseHeaders().set("Content-Type", "application/json");
            ex.sendResponseHeaders(200, bytes.length);
            ex.getResponseBody().write(bytes);
          } catch (Exception e) {
            ex.sendResponseHeaders(500, -1);
          } finally {
            ex.close();
          }
        });
    server.start();

    p.add("GMSSL_VAULT_DIR", () -> dir.toString());
    p.add("GMSSL_VAULT_MASTER_KEY", () -> Base64.getEncoder().encodeToString(new byte[32]));
    p.add("GMSSL_ENGINE_URL", () -> "http://127.0.0.1:" + server.getAddress().getPort());
    p.add("GMSSL_ENGINE_TOKEN", () -> "test-token");
    p.add("GMSSL_BOOTSTRAP_USERNAME", () -> "admin");
    p.add("GMSSL_BOOTSTRAP_PASSWORD", () -> "admin123456");
  }

  @AfterAll
  static void tearDown() {
    if (server != null) server.stop(0);
  }

  @Autowired Jobs jobs;
  @Autowired Store store;
  @Autowired Auth auth;

  @Test
  void testFailedJobSavesEngineSanitizedStderrToStderrPreview() throws Exception {
    String pid = store.id();
    store.db.update("insert into projects values(?,?,?,?)", pid, "test-proj", "desc", store.now());
    var users = store.rows("select id from app_users where username='admin'");
    String uid = users.isEmpty() ? store.id() : users.getFirst().get("id").toString();
    if (users.isEmpty()) store.db.update("insert into app_users values(?,?,?,?,?,?)", uid, "admin", auth.encodePassword("admin123456"), "ADMIN", true, store.now());
    store.db.update("insert into memberships values(?,?,?)", pid, uid, "OWNER");

    // Case 1: Engine failed with sanitized diagnostic stderr
    engineStatusToReturn.set("FAILED");
    engineExitCodeToReturn.set(1);
    String sanitizedErr = "error: failed to load CA private key [task]/ca.key";
    engineStderrToReturn.set(sanitizedErr);

    var jobDto = jobs.submitDirect(pid, uid, Map.of("toolId", "reqsign", "parameters", Map.of()), true);
    String jid = jobDto.get("id").toString();

    // Poll until completed
    Map<String, Object> finalJob = null;
    for (int i = 0; i < 50; i++) {
      Thread.sleep(50);
      finalJob = jobs.dto(pid, jid);
      String st = finalJob.get("status").toString();
      if (!Set.of("QUEUED", "RUNNING").contains(st)) break;
    }

    assertNotNull(finalJob);
    assertEquals("FAILED", finalJob.get("status"));
    assertEquals(1, finalJob.get("exitCode"));
    assertEquals("Engine execution did not succeed", finalJob.get("error"));

    // Verify DB column stderr_preview is populated and equals sanitizedErr
    var dbRow = store.one("select stderr_preview from jobs where id=?", jid);
    assertEquals(sanitizedErr, dbRow.get("stderr_preview"), "DB column stderr_preview must store sanitized stderr");
    assertEquals(sanitizedErr, finalJob.get("stderrPreview"), "DTO must expose stderrPreview from DB");
  }
  @Test
  void testSucceededJobLeavesStderrPreviewNull() throws Exception {
    String pid = store.id();
    store.db.update("insert into projects values(?,?,?,?)", pid, "test-proj-succ", "desc", store.now());
    var users = store.rows("select id from app_users where username='admin'");
    String uid = users.getFirst().get("id").toString();
    store.db.update("insert into memberships values(?,?,?)", pid, uid, "OWNER");

    engineStatusToReturn.set("SUCCEEDED");
    engineExitCodeToReturn.set(0);
    String warningErr = "warning: certificate validity exceeds recommended 398 days";
    engineStderrToReturn.set(warningErr);

    var jobDto = jobs.submitDirect(pid, uid, Map.of("toolId", "reqsign", "parameters", Map.of()), true);
    String jid = jobDto.get("id").toString();

    Map<String, Object> finalJob = null;
    for (int i = 0; i < 50; i++) {
      Thread.sleep(50);
      finalJob = jobs.dto(pid, jid);
      String st = finalJob.get("status").toString();
      if (!Set.of("QUEUED", "RUNNING").contains(st)) break;
    }

    assertNotNull(finalJob);
    assertEquals("SUCCEEDED", finalJob.get("status"));
    assertEquals(0, finalJob.get("exitCode"));
    assertNull(finalJob.get("error"));

    var dbRow = store.one("select stderr_preview from jobs where id=?", jid);
    assertNull(dbRow.get("stderr_preview"), "Succeeded job must leave stderr_preview null");
    assertNull(finalJob.get("stderrPreview"), "Succeeded job DTO must leave stderrPreview null");
  }

  @Test
  void testOversizeStderrIsTruncatedAndSetsTruncatedFlag() throws Exception {
    String pid = store.id();
    store.db.update("insert into projects values(?,?,?,?)", pid, "test-proj-trunc", "desc", store.now());
    var users = store.rows("select id from app_users where username='admin'");
    String uid = users.getFirst().get("id").toString();
    store.db.update("insert into memberships values(?,?,?)", pid, uid, "OWNER");

    engineStatusToReturn.set("FAILED");
    engineExitCodeToReturn.set(1);
    String hugeErr = "E".repeat(10000);
    engineStderrToReturn.set(hugeErr);

    var jobDto = jobs.submitDirect(pid, uid, Map.of("toolId", "reqsign", "parameters", Map.of()), true);
    String jid = jobDto.get("id").toString();

    Map<String, Object> finalJob = null;
    for (int i = 0; i < 50; i++) {
      Thread.sleep(50);
      finalJob = jobs.dto(pid, jid);
      String st = finalJob.get("status").toString();
      if (!Set.of("QUEUED", "RUNNING").contains(st)) break;
    }

    assertNotNull(finalJob);
    assertEquals("FAILED", finalJob.get("status"));
    assertTrue((Boolean) finalJob.get("truncated"), "Truncated flag must be true when stderr exceeds limit");
    String stored = (String) finalJob.get("stderrPreview");
    assertNotNull(stored);
    assertEquals(7900, stored.length(), "Stored stderr must be truncated to 7900 chars");
  }

  @Test
  void testBlankOrNullStderrSavesNullInDatabase() throws Exception {
    String pid = store.id();
    store.db.update("insert into projects values(?,?,?,?)", pid, "test-proj-null", "desc", store.now());
    var users = store.rows("select id from app_users where username='admin'");
    String uid = users.getFirst().get("id").toString();
    store.db.update("insert into memberships values(?,?,?)", pid, uid, "OWNER");

    engineStatusToReturn.set("FAILED");
    engineExitCodeToReturn.set(1);
    engineStderrToReturn.set("   ");

    var jobDto = jobs.submitDirect(pid, uid, Map.of("toolId", "reqsign", "parameters", Map.of()), true);
    String jid = jobDto.get("id").toString();

    Map<String, Object> finalJob = null;
    for (int i = 0; i < 50; i++) {
      Thread.sleep(50);
      finalJob = jobs.dto(pid, jid);
      String st = finalJob.get("status").toString();
      if (!Set.of("QUEUED", "RUNNING").contains(st)) break;
    }

    assertNotNull(finalJob);
    assertNull(finalJob.get("stderrPreview"));
    var dbRow = store.one("select stderr_preview from jobs where id=?", jid);
    assertNull(dbRow.get("stderr_preview"));
  }

  @Test
  void testSanitizeStderrReplacesControlCharacters() {
    String dirty = "line1\nline2\twith\u0000null\u001b[31mescape";
    String clean = Jobs.sanitizeStderr(dirty);
    assertNotNull(clean);
    assertTrue(clean.contains("line1\nline2\twith"));
    assertFalse(clean.contains("\u0000"));
    assertFalse(clean.contains("\u001b"));
    assertTrue(clean.contains("?null?"));
  }
}