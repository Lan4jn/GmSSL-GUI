package org.gmssl.gui.platform;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import com.fasterxml.jackson.databind.*;
import com.sun.net.httpserver.HttpServer;
import jakarta.servlet.http.Cookie;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.*;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

@SpringBootTest
@AutoConfigureMockMvc
class PlatformIntegrationTest {
  static HttpServer server;
  static Path dir;
  static AtomicInteger calls = new AtomicInteger(), stateCalls = new AtomicInteger();
  static AtomicBoolean cancel = new AtomicBoolean();
  static ObjectMapper mapper = new ObjectMapper();

  @DynamicPropertySource
  static void properties(DynamicPropertyRegistry p) throws Exception {
    dir = Files.createTempDirectory("platform-test-vault");
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
              response =
                  Map.of(
                      "provider",
                      "gmssl",
                      "version",
                      "fixture",
                      "sourceCommit",
                      "fixture",
                      "categories",
                      List.of("digest", "pqc"),
                      "coverage",
                      Map.of(),
                      "tools",
                      List.of(
                          tool("digest", false),
                          tool("fail", false),
                          tool("slow", false),
                          tool("state", true),
                          tool("statefail", true),
                          tool("lmskeygen", false)));
            } else if (ex.getRequestURI().getPath().endsWith("cancel")) {
              cancel.set(true);
              response = Map.of("status", "CANCELLED");
            } else {
              calls.incrementAndGet();
              JsonNode in = mapper.readTree(ex.getRequestBody());
              String name = in.path("toolId").asText();
              if (name.equals("slow")) {
                for (int i = 0; i < 100 && !cancel.get(); i++) Thread.sleep(20);
              }
              if (name.equals("state")) {
                stateCalls.incrementAndGet();
                Thread.sleep(300);
              }
              String status =
                  (name.equals("fail") || name.equals("statefail"))
                      ? "FAILED"
                      : name.equals("slow") && cancel.get() ? "CANCELLED" : "SUCCEEDED";
              Map<String, Object> out = new HashMap<>();
              out.put("id", in.path("id").asText());
              out.put("status", status);
              out.put("exitCode", status.equals("SUCCEEDED") ? 0 : 1);
              out.put("durationMs", 10);
              out.put(
                  "stdoutBase64", Base64.getEncoder().encodeToString("fixture-result".getBytes()));
              out.put("stderr", "MUST-NOT-LEAK-SECRET");
              out.put("truncated", false);
              out.put(
                  "artifacts",
                  name.equals("lmskeygen")
                      ? List.of(
                          Map.of(
                              "name",
                              in.path("parameters").path("out").asText(),
                              "mediaType",
                              "application/octet-stream",
                              "contentBase64",
                              Base64.getEncoder()
                                  .encodeToString(
                                      ("initial-key-state-" + in.path("id").asText()).getBytes())))
                      : List.of());
              String token = in.path("parameters").path("key").asText().replace("input:", "");
              out.put(
                  "updatedInputs",
                  name.equals("state")
                      ? List.of(
                          Map.of(
                              "token",
                              token,
                              "contentBase64",
                              Base64.getEncoder().encodeToString("advanced-key-state".getBytes())))
                      : List.of());
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
    p.add(
        "spring.datasource.url",
        () -> "jdbc:h2:mem:platform;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DB_CLOSE_DELAY=-1");
    p.add("GMSSL_BOOTSTRAP_USERNAME", () -> "admin");
    p.add("GMSSL_BOOTSTRAP_PASSWORD", () -> "a-long-admin-password");
    p.add("GMSSL_VAULT_MASTER_KEY", () -> Base64.getEncoder().encodeToString(new byte[32]));
    p.add("GMSSL_VAULT_DIR", () -> dir.toString());
    p.add("GMSSL_ENGINE_TOKEN", () -> "test-token");
    p.add("GMSSL_ENGINE_URL", () -> "http://127.0.0.1:" + server.getAddress().getPort());
  }

  static Map<String, Object> tool(String id, boolean state) {
    if (id.equals("lmskeygen"))
      return Map.of(
          "id",
          id,
          "parameters",
          List.of(
              Map.of("name", "out", "type", "OUTPUT_FILE"),
              Map.of("name", "pubout", "type", "OUTPUT_FILE")),
          "sensitiveOutput",
          true,
          "verification",
          Map.of("status", "implemented"));
    return Map.ofEntries(
        Map.entry("id", id),
        Map.entry("category", state ? "pqc" : "digest"),
        Map.entry("stateful", state),
        Map.entry("defaultTimeoutSeconds", 5),
        Map.entry("maxTimeoutSeconds", 30),
        Map.entry("sensitiveOutput", state),
        Map.entry("stdoutFilename", "stdout.txt"),
        Map.entry(
            "parameters",
            List.of(
                Map.of(
                    "name",
                    "key",
                    "type",
                    "INPUT_FILE",
                    "required",
                    state,
                    "allowedKeyKinds",
                    List.of(state ? "STATEFUL_PRIVATE_KEY" : "PRIVATE_KEY")))),
        Map.entry("verification", Map.of("status", "implemented")));
  }

  @Autowired MockMvc mvc;
  @Autowired ObjectMapper json;
  @Autowired Store s;
  @Autowired Materials materials;
  @Autowired Vault vault;
  @Autowired Jobs jobs;
  @Autowired VaultRecovery recovery;

  record Session(Cookie cookie, String csrf) {}

  Session login(String u, String p) throws Exception {
    var result =
        mvc.perform(
                post("/api/v1/auth/login")
                    .contentType("application/json")
                    .content(json.writeValueAsBytes(Map.of("username", u, "password", p))))
            .andExpect(status().isOk())
            .andReturn();
    String cookie = result.getResponse().getHeader("Set-Cookie").split(";", 2)[0].split("=", 2)[1];
    return new Session(
        new Cookie("GMSSL_SESSION", cookie),
        json.readTree(result.getResponse().getContentAsString()).path("csrfToken").asText());
  }

  MockHttpServletRequestBuilder as(MockHttpServletRequestBuilder r, Session u) {
    return r.cookie(u.cookie).header("X-CSRF-Token", u.csrf);
  }

  JsonNode req(MockHttpServletRequestBuilder r, Session u, int code) throws Exception {
    var response = mvc.perform(as(r, u)).andExpect(status().is(code)).andReturn().getResponse();
    return response.getContentAsString().isBlank()
        ? json.nullNode()
        : json.readTree(response.getContentAsString());
  }

  MockHttpServletRequestBuilder body(MockHttpServletRequestBuilder r, Object b) throws Exception {
    return r.contentType("application/json").content(json.writeValueAsBytes(b));
  }

  String project(Session u, String name) throws Exception {
    return req(body(post("/api/v1/projects"), Map.of("name", name)), u, 200).path("id").asText();
  }

  String user(Session a, String name) throws Exception {
    return req(
            body(
                post("/api/v1/users"),
                Map.of("username", name, "password", "long-test-password", "role", "USER")),
            a,
            200)
        .path("id")
        .asText();
  }

  JsonNode waitJob(Session a, String p, String id) throws Exception {
    for (int i = 0; i < 200; i++) {
      JsonNode n = req(get("/api/v1/projects/" + p + "/jobs/" + id), a, 200);
      if (Set.of("SUCCEEDED", "FAILED", "CANCELLED", "TIMED_OUT")
          .contains(n.path("status").asText())) return n;
      Thread.sleep(20);
    }
    throw new AssertionError("Job did not finish");
  }

  String submit(Session a, String p, String tool, Map<String, Object> params) throws Exception {
    return req(
            body(
                post("/api/v1/projects/" + p + "/jobs"),
                Map.of("toolId", tool, "parameters", params)),
            a,
            202)
        .path("id")
        .asText();
  }

  @Test
  void authenticationProjectIsolationRolesAndArtifacts() throws Exception {
    Session admin = login("admin", "a-long-admin-password");
    mvc.perform(get("/api/v1/projects")).andExpect(status().isUnauthorized());
    mvc.perform(
            post("/api/v1/projects")
                .cookie(admin.cookie)
                .contentType("application/json")
                .content("{\"name\":\"bad\"}"))
        .andExpect(status().isForbidden());
    String uid = user(admin, "alice");
    Session alice = login("alice", "long-test-password");
    String pid = project(admin, "private"), other = project(alice, "alice-project");
    req(get("/api/v1/projects/" + pid), alice, 403);
    req(get("/api/v1/users"), alice, 403);
    req(
        body(put("/api/v1/projects/" + pid + "/members/" + uid), Map.of("role", "VIEWER")),
        admin,
        200);
    req(get("/api/v1/projects/" + pid), alice, 200);
    req(
        body(
            post("/api/v1/projects/" + pid + "/jobs"),
            Map.of("toolId", "digest", "parameters", Map.of())),
        alice,
        403);
    MockMultipartFile f =
        new MockMultipartFile(
            "file", "../../secret.bin", "application/octet-stream", "secret-file".getBytes());
    String fid =
        req(multipart("/api/v1/projects/" + pid + "/files").file(f), admin, 200)
            .path("id")
            .asText();
    req(
        body(
            post("/api/v1/projects/" + other + "/jobs"),
            Map.of("toolId", "digest", "parameters", Map.of("key", "file:" + fid))),
        alice,
        404);
    req(get("/api/v1/projects/" + other + "/files/" + fid + "/download"), alice, 404);
    String jid = submit(admin, pid, "digest", Map.of());
    JsonNode done = waitJob(admin, pid, jid);
    assertEquals("SUCCEEDED", done.path("status").asText());
    assertFalse(done.toString().contains("MUST-NOT-LEAK"));
    String aid =
        java.util.stream.StreamSupport.stream(done.path("artifacts").spliterator(), false)
            .filter(n -> n.path("promotable").asBoolean())
            .findFirst()
            .orElseThrow()
            .path("id")
            .asText();
    mvc.perform(
            as(
                get("/api/v1/projects/" + pid + "/jobs/" + jid + "/artifacts/" + aid + "/download"),
                admin))
        .andExpect(status().isOk())
        .andExpect(content().bytes("fixture-result".getBytes()));
    req(
        get("/api/v1/projects/" + other + "/jobs/" + jid + "/artifacts/" + aid + "/download"),
        alice,
        404);
    assertNotEquals(
        admin.cookie.getValue(),
        s.one(
                "select token_hash from sessions where token_hash=?",
                Auth.hash(admin.cookie.getValue()))
            .get("token_hash"));
    req(get("/api/v1/projects/" + pid + "/audit"), alice, 403);
  }

  String authId(Session x) throws Exception {
    return req(get("/api/v1/auth/me"), x, 200).path("user").path("id").asText();
  }

  @Test
  void vaultIntegrityWrongMasterAndAad() throws Exception {
    String pid = project(login("admin", "a-long-admin-password"), "vault");
    String id =
        materials
            .create(
                pid,
                "FILE",
                "file",
                "application/octet-stream",
                "PRIVATE-CONTENT".getBytes(),
                Map.of())
            .get("id")
            .toString();
    byte[] stored = Files.readAllBytes(vault.path(id));
    assertFalse(new String(stored, StandardCharsets.ISO_8859_1).contains("PRIVATE-CONTENT"));
    assertArrayEquals("PRIVATE-CONTENT".getBytes(), vault.read(pid, id));
    assertThrows(ApiError.class, () -> vault.read(UUID.randomUUID().toString(), id));
    byte[] key = new byte[32];
    key[0] = 1;
    Vault wrong = new Vault(dir.toString(), Base64.getEncoder().encodeToString(key));
    assertThrows(ApiError.class, () -> wrong.read(pid, id));
    stored[stored.length - 1] ^= 1;
    Files.write(vault.path(id), stored);
    assertThrows(ApiError.class, () -> vault.read(pid, id));
  }

  @Test
  void failureCancellationStatefulSerializationAndRecovery() throws Exception {
    Session a = login("admin", "a-long-admin-password");
    String p = project(a, "jobs");
    String failed = submit(a, p, "fail", Map.of());
    assertEquals("FAILED", waitJob(a, p, failed).path("status").asText());
    cancel.set(false);
    int before = calls.get();
    String slow = submit(a, p, "slow", Map.of());
    for (int i = 0; i < 100 && calls.get() == before; i++) Thread.sleep(10);
    req(post("/api/v1/projects/" + p + "/jobs/" + slow + "/cancel"), a, 200);
    assertEquals("CANCELLED", waitJob(a, p, slow).path("status").asText());
    String generated = submit(a, p, "lmskeygen", Map.of());
    JsonNode generatedJob = waitJob(a, p, generated);
    assertEquals("SUCCEEDED", generatedJob.path("status").asText());
    JsonNode generatedPrivate =
        java.util.stream.StreamSupport.stream(generatedJob.path("artifacts").spliterator(), false)
            .filter(n -> n.path("promotable").asBoolean())
            .findFirst()
            .orElseThrow();
    String privateAid = generatedPrivate.path("id").asText();
    assertTrue(generatedPrivate.path("statefulPrivate").asBoolean());
    assertFalse(generatedPrivate.path("downloadable").asBoolean());
    String artifactPath =
        "/api/v1/projects/" + p + "/jobs/" + generated + "/artifacts/" + privateAid;
    req(get(artifactPath + "/download"), a, 403);
    JsonNode promoted =
        req(
            body(
                post(artifactPath + "/save-key"),
                Map.of("name", "state", "algorithm", "wrong", "keyKind", "PRIVATE_KEY")),
            a,
            200);
    assertEquals("STATEFUL_PRIVATE_KEY", promoted.path("keyKind").asText());
    assertEquals("LMS", promoted.path("algorithm").asText());
    String key = promoted.path("id").asText();
    req(body(post(artifactPath + "/save-key"), Map.of("name", "copy")), a, 409);
    req(get("/api/v1/projects/" + p + "/keys/" + key + "/download"), a, 403);
    MockMultipartFile external =
        new MockMultipartFile(
            "file", "state.key", "application/octet-stream", "state-data".getBytes());
    req(
        multipart("/api/v1/projects/" + p + "/keys")
            .file(external)
            .param("name", "external")
            .param("algorithm", "LMS")
            .param("keyKind", "STATEFUL_PRIVATE_KEY"),
        a,
        400);
    String disguised =
        materials
            .create(
                p,
                "KEY",
                "disguised",
                "application/octet-stream",
                "initial-key-state".getBytes(),
                Map.of("keyKind", "PRIVATE_KEY", "algorithm", "LMS"))
            .get("id")
            .toString();
    req(
        body(
            post("/api/v1/projects/" + p + "/jobs"),
            Map.of("toolId", "state", "parameters", Map.of("key", "key:" + disguised))),
        a,
        400);
    int start = stateCalls.get();
    String j1 = submit(a, p, "state", Map.of("key", "key:" + key));
    for (int i = 0; i < 100 && stateCalls.get() == start; i++) Thread.sleep(10);
    String j2 = submit(a, p, "state", Map.of("key", "key:" + key));
    assertEquals("FAILED", waitJob(a, p, j2).path("status").asText());
    assertEquals("SUCCEEDED", waitJob(a, p, j1).path("status").asText());
    assertEquals(start + 1, stateCalls.get());
    assertArrayEquals("advanced-key-state".getBytes(), vault.read(p, key));
    assertFalse(Store.bool(materials.raw(p, key), "pending"));
    s.db.update("update materials set pending=true where id=?", key);
    String blocked = submit(a, p, "state", Map.of("key", "key:" + key));
    assertEquals("FAILED", waitJob(a, p, blocked).path("status").asText());
    assertEquals(start + 1, stateCalls.get());
    String restart = s.id();
    s.db.update(
        "insert into jobs(id,project_id,user_id,tool_id,status,created_at,truncated)"
            + " values(?,?,?,?,?,?,?)",
        restart,
        p,
        authId(a),
        "state",
        "RUNNING",
        s.now(),
        false);
    jobs.recover();
    assertEquals("FAILED", jobs.dto(p, restart).get("status"));
    assertTrue(Store.bool(materials.raw(p, key), "pending"));
  }

  @Test
  void queuedCancellationAndRevokedPermissionNeverReachEngine() throws Exception {
    Session a = login("admin", "a-long-admin-password");
    String p = project(a, "queue");
    String uid = user(a, "revoked");
    Session u = login("revoked", "long-test-password");
    req(body(put("/api/v1/projects/" + p + "/members/" + uid), Map.of("role", "EDITOR")), a, 200);
    CountDownLatch blockers = new CountDownLatch(2), release = new CountDownLatch(1);
    for (int i = 0; i < 2; i++)
      jobs.pool.execute(
          () -> {
            blockers.countDown();
            try {
              release.await();
            } catch (InterruptedException e) {
              Thread.currentThread().interrupt();
            }
          });
    assertTrue(blockers.await(5, TimeUnit.SECONDS));
    int before = calls.get();
    String queued = submit(a, p, "digest", Map.of());
    req(post("/api/v1/projects/" + p + "/jobs/" + queued + "/cancel"), a, 200);
    assertEquals("CANCELLED", jobs.dto(p, queued).get("status"));
    String revoked = submit(u, p, "digest", Map.of());
    req(delete("/api/v1/projects/" + p + "/members/" + uid), a, 204);
    release.countDown();
    assertEquals("FAILED", waitJob(a, p, revoked).path("status").asText());
    assertEquals(before, calls.get());
  }

  @Test
  void disabledQueuedUserStatefulFailureAndSensitivePreview() throws Exception {
    Session a = login("admin", "a-long-admin-password");
    String p = project(a, "negative-jobs");
    String uid = user(a, "disabled");
    Session u = login("disabled", "long-test-password");
    req(body(put("/api/v1/projects/" + p + "/members/" + uid), Map.of("role", "EDITOR")), a, 200);
    CountDownLatch blockers = new CountDownLatch(2), release = new CountDownLatch(1);
    for (int i = 0; i < 2; i++)
      jobs.pool.execute(
          () -> {
            blockers.countDown();
            try {
              release.await();
            } catch (InterruptedException e) {
              Thread.currentThread().interrupt();
            }
          });
    assertTrue(blockers.await(5, TimeUnit.SECONDS));
    int before = calls.get();
    String disabled = submit(u, p, "digest", Map.of());
    req(body(patch("/api/v1/users/" + uid), Map.of("enabled", false)), a, 200);
    release.countDown();
    assertEquals("FAILED", waitJob(a, p, disabled).path("status").asText());
    assertEquals(before, calls.get());
    String gen = submit(a, p, "lmskeygen", Map.of());
    JsonNode done = waitJob(a, p, gen);
    assertTrue(done.path("stdoutPreview").isNull() || done.path("stdoutPreview").isMissingNode());
    String aid =
        java.util.stream.StreamSupport.stream(done.path("artifacts").spliterator(), false)
            .filter(n -> n.path("promotable").asBoolean())
            .findFirst()
            .orElseThrow()
            .path("id")
            .asText();
    String path = "/api/v1/projects/" + p + "/jobs/" + gen + "/artifacts/" + aid;
    String key =
        req(body(post(path + "/save-key"), Map.of("name", "failed-state")), a, 200)
            .path("id")
            .asText();
    String failed = submit(a, p, "statefail", Map.of("key", "key:" + key));
    assertEquals("FAILED", waitJob(a, p, failed).path("status").asText());
    assertTrue(Store.bool(materials.raw(p, key), "pending"));
    assertThrows(ApiError.class, () -> materials.delete(p, key));
    String ordinary =
        materials
            .create(
                p,
                "KEY",
                "ordinary",
                "application/octet-stream",
                "private-key-bytes".getBytes(),
                Map.of("algorithm", "SM2", "keyKind", "PRIVATE_KEY"))
            .get("id")
            .toString();
    String sensitive = submit(a, p, "digest", Map.of("key", "key:" + ordinary));
    JsonNode result = waitJob(a, p, sensitive);
    assertTrue(
        result.path("stdoutPreview").isNull() || result.path("stdoutPreview").isMissingNode());
    assertFalse(
        s.rows("select * from jobs where id=?", sensitive)
            .getFirst()
            .toString()
            .contains("private-key-bytes"));
  }

  @Test
  void statefulPromotionTombstoneSurvivesDeletionAndStdoutIsNotKey() throws Exception {
    Session a = login("admin", "a-long-admin-password");
    String p = project(a, "state-tombstone");
    String gen = submit(a, p, "lmskeygen", Map.of());
    JsonNode done = waitJob(a, p, gen);
    String source = null, stdout = null;
    for (JsonNode artifact : done.path("artifacts")) {
      if (artifact.path("promotable").asBoolean()) source = artifact.path("id").asText();
      else stdout = artifact.path("id").asText();
    }
    assertNotNull(source);
    assertNotNull(stdout);
    String path = "/api/v1/projects/" + p + "/jobs/" + gen + "/artifacts/" + source;
    JsonNode key = req(body(post(path + "/save-key"), Map.of("name", "single-authority")), a, 200);
    req(delete("/api/v1/projects/" + p + "/keys/" + key.path("id").asText()), a, 204);
    req(body(post(path + "/save-key"), Map.of("name", "replay")), a, 409);
    req(
        body(
            post("/api/v1/projects/" + p + "/jobs/" + gen + "/artifacts/" + stdout + "/save-key"),
            Map.of("name", "stdout-copy", "algorithm", "LMS", "keyKind", "PRIVATE_KEY")),
        a,
        403);
    JsonNode refreshed = req(get("/api/v1/projects/" + p + "/jobs/" + gen), a, 200);
    for (JsonNode artifact : refreshed.path("artifacts"))
      assertFalse(artifact.path("promotable").asBoolean());
  }

  @Test
  void symmetricReferenceUsesEncodingAndCatalogKindConstraints() throws Exception {
    String p = s.id();
    s.db.update("insert into projects values(?,?,?,?)", p, "encoding", "", s.now());
    String raw =
        materials
            .create(
                p,
                "KEY",
                "raw",
                "application/octet-stream",
                new byte[] {0, 1, 15, (byte) 255},
                Map.of("algorithm", "SM4", "keyKind", "SYMMETRIC_KEY", "encoding", "RAW"))
            .get("id")
            .toString();
    String hex =
        materials
            .create(
                p,
                "KEY",
                "hex",
                "application/octet-stream",
                "001122AABB".getBytes(),
                Map.of("algorithm", "SM4", "keyKind", "SYMMETRIC_KEY", "encoding", "HEX"))
            .get("id")
            .toString();
    Jobs.Work w = new Jobs.Work();
    w.pid = p;
    w.definition = json.readTree("{\"stateful\":false}");
    JsonNode def =
        json.readTree(
            "{\"name\":\"key\",\"type\":\"HEX\",\"allowKeyReference\":true,\"secret\":true}");
    assertEquals("00010fff", jobs.resolve(w, def, "key:" + raw));
    assertEquals("001122AABB", jobs.resolve(w, def, "key:" + hex));
    assertTrue(w.sensitive);
    assertThrows(
        ApiError.class,
        () -> jobs.resolve(w, json.readTree("{\"name\":\"key\",\"type\":\"HEX\"}"), "key:" + raw));
    assertThrows(
        ApiError.class,
        () ->
            jobs.resolve(
                w, json.readTree("{\"name\":\"in\",\"type\":\"INPUT_FILE\"}"), "key:" + raw));
    assertThrows(
        ApiError.class,
        () ->
            materials.create(
                p,
                "KEY",
                "bad-hex",
                "application/octet-stream",
                "0xyz".getBytes(),
                Map.of("algorithm", "SM4", "keyKind", "SYMMETRIC_KEY", "encoding", "HEX")));
  }

  @Test
  void temporaryFileLifecycleAndBindingRestrictions() throws Exception {
    Session a = login("admin", "a-long-admin-password");
    String p = project(a, "temp-files");

    MockMultipartFile tempFile =
        new MockMultipartFile("file", "temp.txt", "text/plain", "temporary-payload".getBytes());
    var uploadRes =
        mvc.perform(
                multipart("/api/v1/projects/" + p + "/files")
                    .file(tempFile)
                    .param("temporary", "true")
                    .cookie(a.cookie)
                    .header("X-CSRF-Token", a.csrf))
            .andExpect(status().isOk())
            .andReturn();
    JsonNode uploadedNode = json.readTree(uploadRes.getResponse().getContentAsString());
    String tempId = uploadedNode.path("id").asText();
    assertTrue(uploadedNode.path("temporary").asBoolean());

    MockMultipartFile keyFile =
        new MockMultipartFile(
            "file", "key.pem", "text/plain", "-----BEGIN PRIVATE KEY-----\nabc\n".getBytes());
    mvc.perform(
            multipart("/api/v1/projects/" + p + "/keys")
                .file(keyFile)
                .param("name", "temp-key")
                .param("keyKind", "PRIVATE_KEY")
                .param("algorithm", "SM2")
                .param("temporary", "true")
                .cookie(a.cookie)
                .header("X-CSRF-Token", a.csrf))
        .andExpect(status().isBadRequest());

    MockMultipartFile slowTemp =
        new MockMultipartFile("file", "slow.txt", "text/plain", "slow-data".getBytes());
    var slowUpload =
        mvc.perform(
                multipart("/api/v1/projects/" + p + "/files")
                    .file(slowTemp)
                    .param("temporary", "true")
                    .cookie(a.cookie)
                    .header("X-CSRF-Token", a.csrf))
            .andExpect(status().isOk())
            .andReturn();
    String slowTempId =
        json.readTree(slowUpload.getResponse().getContentAsString()).path("id").asText();

    String slowJob = submit(a, p, "slow", Map.of("key", "file:" + slowTempId));
    req(
        body(
            post("/api/v1/projects/" + p + "/jobs"),
            Map.of("toolId", "digest", "parameters", Map.of("key", "file:" + slowTempId))),
        a,
        409);
    req(delete("/api/v1/projects/" + p + "/files/" + slowTempId), a, 409);

    req(post("/api/v1/projects/" + p + "/jobs/" + slowJob + "/cancel"), a, 200);
    waitJob(a, p, slowJob);
    assertTrue(s.rows("select id from materials where id=?", slowTempId).isEmpty());
    assertThrows(ApiError.class, () -> vault.read(p, slowTempId));

    MockMultipartFile qTemp =
        new MockMultipartFile("file", "q.txt", "text/plain", "q-data".getBytes());
    var qUpload =
        mvc.perform(
                multipart("/api/v1/projects/" + p + "/files")
                    .file(qTemp)
                    .param("temporary", "true")
                    .cookie(a.cookie)
                    .header("X-CSRF-Token", a.csrf))
            .andExpect(status().isOk())
            .andReturn();
    String qTempId = json.readTree(qUpload.getResponse().getContentAsString()).path("id").asText();
    String qJobId = submit(a, p, "digest", Map.of("key", "file:" + qTempId));
    req(post("/api/v1/projects/" + p + "/jobs/" + qJobId + "/cancel"), a, 200);
    waitJob(a, p, qJobId);
    assertTrue(s.rows("select id from materials where id=?", qTempId).isEmpty());

    String normalJob = submit(a, p, "digest", Map.of("key", "file:" + tempId));
    assertEquals("SUCCEEDED", waitJob(a, p, normalJob).path("status").asText());
    assertTrue(s.rows("select id from materials where id=?", tempId).isEmpty());
    assertThrows(ApiError.class, () -> vault.read(p, tempId));

    String orphanBound =
        materials
            .create(
                p,
                "FILE",
                "orphan.txt",
                "text/plain",
                "orphan".getBytes(),
                Map.of("temporary", "true"))
            .get("id")
            .toString();
    String deadJob = s.id();
    String adminUid = s.one("select id from app_users where username='admin'").get("id").toString();
    s.db.update(
        "insert into jobs(id,project_id,user_id,tool_id,status,created_at,truncated)"
            + " values(?,?,?,?,?,?,?)",
        deadJob,
        p,
        adminUid,
        "digest",
        "RUNNING",
        s.now(),
        false);
    s.db.update("update materials set bound_job_id=? where id=?", deadJob, orphanBound);
    jobs.recover();
    assertTrue(s.rows("select id from materials where id=?", orphanBound).isEmpty());

    String oldUnbound =
        materials
            .create(
                p, "FILE", "old.txt", "text/plain", "old".getBytes(), Map.of("temporary", "true"))
            .get("id")
            .toString();
    s.db.update(
        "update materials set created_at=? where id=?",
        java.time.Instant.now().minus(java.time.Duration.ofHours(2)).toString(),
        oldUnbound);
    recovery.periodicCleanup();
    assertTrue(s.rows("select id from materials where id=?", oldUnbound).isEmpty());

    // 验证：409 pending/RUNNING FILE_BOUND后vault仍然存在且可读，跨项目/不存在id不会触及磁盘
    String boundKeep =
        materials
            .create(
                p,
                "FILE",
                "bound-keep.txt",
                "text/plain",
                "keep-vault-data".getBytes(),
                Map.of("temporary", "true"))
            .get("id")
            .toString();
    String activeJobId = s.id();
    s.db.update(
        "insert into jobs(id,project_id,user_id,tool_id,status,created_at,truncated)"
            + " values(?,?,?,?,?,?,?)",
        activeJobId,
        p,
        adminUid,
        "digest",
        "RUNNING",
        s.now(),
        false);
    s.db.update("update materials set bound_job_id=? where id=?", activeJobId, boundKeep);
    assertThrows(ApiError.class, () -> materials.delete(p, boundKeep));
    assertArrayEquals("keep-vault-data".getBytes(), vault.read(p, boundKeep));

    assertThrows(ApiError.class, () -> materials.delete(p, "00000000-0000-0000-0000-000000000000"));
    assertThrows(ApiError.class, () -> materials.delete("other-project", boundKeep));
    assertArrayEquals("keep-vault-data".getBytes(), vault.read(p, boundKeep));

    s.db.update("update jobs set status='FAILED',finished_at=? where id=?", s.now(), activeJobId);
    recovery.periodicCleanup();
    assertTrue(s.rows("select id from materials where id=?", boundKeep).isEmpty());
    assertThrows(ApiError.class, () -> vault.read(p, boundKeep));
  }

  @AfterAll
  static void stop() {
    server.stop(0);
  }
}
