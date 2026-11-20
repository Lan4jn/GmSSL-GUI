package org.gmssl.gui.platform;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import com.fasterxml.jackson.databind.*;
import com.sun.net.httpserver.HttpServer;
import jakarta.servlet.http.Cookie;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

@SpringBootTest
@AutoConfigureMockMvc
class KeyGenerationIntegrationTest {
  static HttpServer server;
  static Path dir;
  static ObjectMapper mapper = new ObjectMapper();
  static AtomicReference<JsonNode> lastEngineExecutionRequest = new AtomicReference<>();
  static AtomicReference<JsonNode> lastEngineKeyGenRequest = new AtomicReference<>();

  @DynamicPropertySource
  static void properties(DynamicPropertyRegistry p) throws Exception {
    dir = Files.createTempDirectory("platform-test-keygen-vault");
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
            String path = ex.getRequestURI().getPath();
            Object response;
            if (path.endsWith("/capabilities")) {
              response =
                  Map.of(
                      "provider", "gmssl",
                      "version", "fixture",
                      "tools",
                      List.of(
                          Map.of(
                              "id", "sm2sign-tool",
                              "category", "signature",
                              "parameters",
                              List.of(
                                  Map.of(
                                      "name", "key",
                                      "type", "INPUT_FILE",
                                      "required", true,
                                      "allowedKeyKinds", List.of("PRIVATE_KEY")),
                                  Map.of(
                                      "name", "pass",
                                      "type", "SECRET",
                                      "secret", true,
                                      "required", false,
                                      "credentialKeyParameter", "key")))));
            } else if (path.endsWith("/key-generation-capabilities")) {
              response =
                  Map.of(
                      "providers",
                      List.of(
                          Map.of(
                              "id", "gmssl",
                              "available", true,
                              "version", "GmSSL 3.1.2",
                              "algorithms", List.of("SM4", "SM2")),
                          Map.of(
                              "id", "openssl",
                              "available", true,
                              "version", "OpenSSL 3.6.4",
                              "algorithms", List.of("SM4", "AES"))),
                      "algorithms",
                      List.of(
                          Map.of(
                              "id", "SM4",
                              "kind", "SYMMETRIC_KEY",
                              "bits", List.of(128),
                              "providers", List.of("gmssl", "openssl")),
                          Map.of(
                              "id", "SM2",
                              "kind", "PRIVATE_KEY",
                              "curves", List.of("sm2p256v1"),
                              "providers", List.of("gmssl"))));
            } else if (path.endsWith("key-generations")) {
              JsonNode in = mapper.readTree(ex.getRequestBody());
              lastEngineKeyGenRequest.set(in);
              String algo = in.path("algorithm").asText();
              String prov = in.path("provider").asText();
              if ("CORRUPT_HEX".equalsIgnoreCase(algo)) {
                response =
                    Map.of(
                        "provider", prov,
                        "algorithm", algo,
                        "keyKind", "SYMMETRIC_KEY",
                        "encoding", "HEX",
                        "valueBase64",
                        Base64.getEncoder().encodeToString("not-a-valid-hex-value!@#".getBytes(StandardCharsets.US_ASCII)),
                        "warnings", List.of());
              } else if ("LENGTH_MISMATCH".equalsIgnoreCase(algo)) {
                response =
                    Map.of(
                        "provider", prov,
                        "algorithm", algo,
                        "keyKind", "SYMMETRIC_KEY",
                        "encoding", "HEX",
                        "valueBase64",
                        Base64.getEncoder().encodeToString("0123456789abcdef".getBytes(StandardCharsets.US_ASCII)),
                        "warnings", List.of());
              } else if ("SLOW_KEYGEN".equalsIgnoreCase(algo)) {
                try { Thread.sleep(300); } catch (InterruptedException ignored) {}
                response =
                    Map.of(
                        "provider", prov,
                        "algorithm", "SM4",
                        "keyKind", "SYMMETRIC_KEY",
                        "encoding", "HEX",
                        "valueBase64",
                        Base64.getEncoder().encodeToString("0123456789abcdeffedcba9876543210".getBytes(StandardCharsets.US_ASCII)),
                        "warnings", List.of());
              } else if ("SM4".equalsIgnoreCase(algo)) {
                response =
                    Map.of(
                        "provider", prov,
                        "algorithm", algo,
                        "keyKind", "SYMMETRIC_KEY",
                        "encoding", "HEX",
                        "valueBase64",
                        Base64.getEncoder()
                            .encodeToString("0123456789abcdeffedcba9876543210".getBytes(StandardCharsets.US_ASCII)),
                        "warnings", List.of());
              } else {
                response =
                    Map.of(
                        "provider", prov,
                        "algorithm", algo,
                        "keyKind", "PRIVATE_KEY",
                        "encoding", "PEM",
                        "privateKeyBase64",
                        Base64.getEncoder()
                            .encodeToString("-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIB...fake...\n-----END ENCRYPTED PRIVATE KEY-----\n".getBytes(StandardCharsets.UTF_8)),
                        "publicKeyBase64",
                        Base64.getEncoder()
                            .encodeToString("-----BEGIN PUBLIC KEY-----\nMFkw...fake...\n-----END PUBLIC KEY-----\n".getBytes(StandardCharsets.UTF_8)),
                        "warnings", List.of());
              }
            } else {
              JsonNode in = mapper.readTree(ex.getRequestBody());
              lastEngineExecutionRequest.set(in);
              Map<String, Object> out = new HashMap<>();
              out.put("id", in.path("id").asText());
              out.put("status", "SUCCEEDED");
              out.put("exitCode", 0);
              out.put("durationMs", 10);
              out.put("stdoutBase64", Base64.getEncoder().encodeToString("ok".getBytes()));
              out.put("stderr", "");
              out.put("truncated", false);
              out.put("artifacts", List.of());
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
        () -> "jdbc:h2:mem:keygen_test;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DB_CLOSE_DELAY=-1");
    p.add("GMSSL_BOOTSTRAP_USERNAME", () -> "admin");
    p.add("GMSSL_BOOTSTRAP_PASSWORD", () -> "a-long-admin-password");
    p.add("GMSSL_VAULT_MASTER_KEY", () -> Base64.getEncoder().encodeToString(new byte[32]));
    p.add("GMSSL_VAULT_DIR", () -> dir.toString());
    p.add("GMSSL_ENGINE_TOKEN", () -> "test-token");
    p.add("GMSSL_ENGINE_URL", () -> "http://127.0.0.1:" + server.getAddress().getPort());
  }

  @Autowired MockMvc mvc;
  @Autowired ObjectMapper json;
  @Autowired Store s;
  @Autowired Materials materials;
  @org.springframework.test.context.bean.override.mockito.MockitoSpyBean Vault vault;
  @Autowired Jobs jobs;
  @org.springframework.test.context.bean.override.mockito.MockitoSpyBean CredentialService credentialService;
  @Autowired KeyGenerationService keyGenerationService;
  @Autowired Auth auth;

  @BeforeEach
  void setUp() {
    auth.attempts.clear();
  }

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

  @Test
  void testKeyGenerationCapabilities() throws Exception {
    Session admin = login("admin", "a-long-admin-password");
    // Unauthenticated -> 401
    mvc.perform(get("/api/v1/key-generation-capabilities")).andExpect(status().isUnauthorized());

    // Authenticated
    JsonNode res = req(get("/api/v1/key-generation-capabilities"), admin, 200);
    assertTrue(res.has("providers"));
    assertTrue(res.has("algorithms"));
    assertEquals("gmssl", res.path("providers").get(0).path("id").asText());
  }

  @Test
  void testSymmetricKeyGenerationManagedAndTemporary() throws Exception {
    Session admin = login("admin", "a-long-admin-password");
    String pid = project(admin, "sym-project");

    // 1. MANAGED storage
    JsonNode managedRes =
        req(
            body(
                post("/api/v1/projects/" + pid + "/keys/generate"),
                Map.of(
                    "provider", "gmssl",
                    "algorithm", "SM4",
                    "storage", "MANAGED")),
            admin,
            200);
    assertEquals("gmssl", managedRes.path("provider").asText());
    assertEquals("SM4", managedRes.path("algorithm").asText());
    assertEquals("MANAGED", managedRes.path("storage").asText());
    assertTrue(managedRes.has("reference"));
    assertTrue(managedRes.path("reference").asText().startsWith("key:"));
    assertFalse(managedRes.has("valueHex")); // raw secret not leaked!
    String keyId = managedRes.path("key").path("id").asText();
    assertEquals("gmssl", managedRes.path("key").path("generationProvider").asText());
    assertFalse(managedRes.path("key").path("hasManagedPassphrase").asBoolean());

    // Verify stored in vault as HEX
    byte[] vaultData = vault.read(pid, keyId);
    String hexInVault = new String(vaultData, StandardCharsets.US_ASCII).trim();
    assertEquals("0123456789abcdeffedcba9876543210", hexInVault);

    // 2. TEMPORARY storage
    JsonNode tempRes =
        req(
            body(
                post("/api/v1/projects/" + pid + "/keys/generate"),
                Map.of(
                    "provider", "openssl",
                    "algorithm", "SM4",
                    "storage", "TEMPORARY")),
            admin,
            200);
    assertEquals("openssl", tempRes.path("provider").asText());
    assertEquals("TEMPORARY", tempRes.path("storage").asText());
    assertTrue(tempRes.has("valueHex"));
    assertEquals("0123456789abcdeffedcba9876543210", tempRes.path("valueHex").asText());
    assertFalse(tempRes.has("key"));
  }

  @Test
  void testAsymmetricKeyGenerationAndPassphraseLifecycle() throws Exception {
    Session admin = login("admin", "a-long-admin-password");
    String pid = project(admin, "asym-project");

    // 1. Generate SM2 keypair with MANAGED storage and auto-generated passphrase
    JsonNode genRes =
        req(
            body(
                post("/api/v1/projects/" + pid + "/keys/generate"),
                Map.of(
                    "provider", "gmssl",
                    "algorithm", "SM2",
                    "storage", "MANAGED")),
            admin,
            200);

    String privKeyId = genRes.path("key").path("id").asText();
    String pubKeyId = genRes.path("publicKey").path("id").asText();
    assertTrue(genRes.path("key").path("hasManagedPassphrase").asBoolean());
    assertEquals("gmssl", genRes.path("key").path("generationProvider").asText());
    assertFalse(genRes.has("password")); // Password not leaked in response
    assertFalse(genRes.has("passphrase"));

    // Verify engine received generated password
    JsonNode engineCall = lastEngineKeyGenRequest.get();
    assertNotNull(engineCall);
    assertTrue(engineCall.has("password"));
    String sentPassword = engineCall.path("password").asText();
    assertFalse(sentPassword.isBlank());

    // Verify key_credentials table in DB contains encrypted ciphertext, not plaintext
    var rows = s.rows("select encrypted_passphrase from key_credentials where material_id=?", privKeyId);
    assertEquals(1, rows.size());
    byte[] encrypted = (byte[]) rows.getFirst().get("encrypted_passphrase");
    assertNotNull(encrypted);
    String encStr = new String(encrypted, StandardCharsets.ISO_8859_1);
    assertFalse(encStr.contains(sentPassword), "Ciphertext must not contain plaintext password");

    // 2. Reveal passphrase (EDITOR/admin)
    var revealMvcRes =
        mvc.perform(as(post("/api/v1/projects/" + pid + "/keys/" + privKeyId + "/reveal-passphrase"), admin))
            .andExpect(status().isOk())
            .andExpect(header().string("Cache-Control", "no-store"))
            .andReturn()
            .getResponse();
    JsonNode revealRes = json.readTree(revealMvcRes.getContentAsString());
    assertEquals(privKeyId, revealRes.path("id").asText());
    assertEquals(sentPassword, revealRes.path("passphrase").asText());

    // Verify audit event logged for reveal
    var auditRows = s.rows("select action, outcome from audit_events where resource_id=?", privKeyId);
    assertTrue(auditRows.stream().anyMatch(r -> "REVEAL_KEY_PASSPHRASE".equals(r.get("action"))));

    // 3. Update passphrase
    JsonNode updateRes =
        req(
            body(
                post("/api/v1/projects/" + pid + "/keys/" + privKeyId + "/passphrase"),
                Map.of("password", "updated-new-pass-123")),
            admin,
            200);
    assertEquals("updated-new-pass-123", credentialService.getPassphrase(pid, privKeyId));
    assertTrue(updateRes.path("note").asText().contains("does not re-encrypt"));

    var updateAuditRows = s.rows("select action, outcome from audit_events where resource_id=?", privKeyId);
    assertTrue(updateAuditRows.stream().anyMatch(r -> "UPDATE_KEY_CREDENTIAL".equals(r.get("action"))));

    // 4. Delete material and verify cascade deletion of credentials
    req(delete("/api/v1/projects/" + pid + "/keys/" + privKeyId), admin, 204);
    assertFalse(credentialService.hasPassphrase(privKeyId));
    assertEquals(0, s.rows("select * from key_credentials where material_id=?", privKeyId).size());
  }

  @Test
  void testTemporaryAsymmetricFileAndPassphrase() throws Exception {
    Session admin = login("admin", "a-long-admin-password");
    String pid = project(admin, "temp-asym-project");

    JsonNode tempRes =
        req(
            body(
                post("/api/v1/projects/" + pid + "/keys/generate"),
                Map.of(
                    "provider", "gmssl",
                    "algorithm", "SM2",
                    "storage", "TEMPORARY")),
            admin,
            200);
    assertTrue(tempRes.has("temporaryFile"));
    String fileId = tempRes.path("temporaryFile").path("id").asText();
    assertTrue(tempRes.path("temporaryFile").path("temporary").asBoolean());
    assertTrue(tempRes.path("temporaryFile").path("hasManagedPassphrase").asBoolean());

    // Verify temporary public key file is also returned for asymmetric key in TEMPORARY mode
    assertTrue(tempRes.has("temporaryPublicKeyFile"));
    String pubFileId = tempRes.path("temporaryPublicKeyFile").path("id").asText();
    assertTrue(tempRes.path("temporaryPublicKeyFile").path("temporary").asBoolean());
    assertTrue(tempRes.path("temporaryPublicKeyFile").path("name").asText().contains("-pub.pem"));

    assertTrue(credentialService.hasPassphrase(fileId));
    JsonNode reveal =
        req(post("/api/v1/projects/" + pid + "/files/" + fileId + "/reveal-passphrase"), admin, 200);
    assertFalse(reveal.path("passphrase").asText().isBlank());
  }

  @Test
  void testSecurityStatefulRejectionAndCrossProjectIsolation() throws Exception {
    Session admin = login("admin", "a-long-admin-password");
    String aliceUid = user(admin, "alice_sec");
    Session alice = login("alice_sec", "long-test-password");

    String adminPid = project(admin, "admin-p");
    String alicePid = project(alice, "alice-p");

    // 1. Stateful key rejection
    req(
        body(
            post("/api/v1/projects/" + adminPid + "/keys/generate"),
            Map.of("algorithm", "LMS", "storage", "MANAGED")),
        admin,
        400);

    req(
        body(
            post("/api/v1/projects/" + adminPid + "/keys/generate"),
            Map.of("algorithm", "XMSS", "storage", "MANAGED")),
        admin,
        400);

    // 2. Generate SM2 key in admin project
    JsonNode gen =
        req(
            body(
                post("/api/v1/projects/" + adminPid + "/keys/generate"),
                Map.of("algorithm", "SM2", "storage", "MANAGED")),
            admin,
            200);
    String keyId = gen.path("key").path("id").asText();

    // Alice attempts to reveal admin's key passphrase -> forbidden/cross-project denied
    req(post("/api/v1/projects/" + adminPid + "/keys/" + keyId + "/reveal-passphrase"), alice, 403);
    req(post("/api/v1/projects/" + alicePid + "/keys/" + keyId + "/reveal-passphrase"), alice, 404);

    // VIEWER role check: Add bob as VIEWER to adminPid
    String bobUid = user(admin, "bob_viewer");
    Session bob = login("bob_viewer", "long-test-password");
    s.db.update("insert into memberships values(?,?,?)", adminPid, bobUid, "VIEWER");

    // Bob cannot generate key (requires EDITOR)
    req(
        body(
            post("/api/v1/projects/" + adminPid + "/keys/generate"),
            Map.of("algorithm", "SM4", "storage", "MANAGED")),
        bob,
        403);

    // Bob cannot reveal passphrase (requires EDITOR)
    req(post("/api/v1/projects/" + adminPid + "/keys/" + keyId + "/reveal-passphrase"), bob, 403);
  }

  @Test
  void testJobAutoInjectPassphraseFromCredential() throws Exception {
    Session admin = login("admin", "a-long-admin-password");
    String pid = project(admin, "job-inject-project");

    // 1. Generate managed SM2 key
    JsonNode gen =
        req(
            body(
                post("/api/v1/projects/" + pid + "/keys/generate"),
                Map.of("algorithm", "SM2", "storage", "MANAGED")),
            admin,
            200);
    String keyId = gen.path("key").path("id").asText();
    String expectedPass = credentialService.getPassphrase(pid, keyId);
    assertNotNull(expectedPass);

    // 2. Submit job referencing key with NO pass supplied
    JsonNode submitRes =
        req(
            body(
                post("/api/v1/projects/" + pid + "/jobs"),
                Map.of(
                    "toolId", "sm2sign-tool",
                    "parameters", Map.of("key", "key:" + keyId))),
            admin,
            202);
    String jobId = submitRes.path("id").asText();
    waitJob(admin, pid, jobId);

    // Verify engine was sent the injected pass parameter!
    JsonNode execReq = lastEngineExecutionRequest.get();
    assertNotNull(execReq);
    assertEquals(expectedPass, execReq.path("parameters").path("pass").asText());

    // 3. Submit job with explicit pass override
    JsonNode submitRes2 =
        req(
            body(
                post("/api/v1/projects/" + pid + "/jobs"),
                Map.of(
                    "toolId", "sm2sign-tool",
                    "parameters",
                    Map.of("key", "key:" + keyId, "pass", "explicit-user-pass"))),
            admin,
            202);
    String jobId2 = submitRes2.path("id").asText();
    waitJob(admin, pid, jobId2);

    JsonNode execReq2 = lastEngineExecutionRequest.get();
    assertNotNull(execReq2);
    assertEquals("explicit-user-pass", execReq2.path("parameters").path("pass").asText());
  }

  @Test
  void testAlgorithmDistinctionStatefulVsUnsupportedPqc() throws Exception {
    Session admin = login("admin", "a-long-admin-password");
    String pid = project(admin, "algo-dist-project");

    // Stateful algorithms must return stateful job message
    JsonNode lmsRes =
        req(
            body(
                post("/api/v1/projects/" + pid + "/keys/generate"),
                Map.of("algorithm", "LMS", "storage", "MANAGED")),
            admin,
            400);
    assertTrue(lmsRes.path("message").asText().contains("Stateful private keys"));

    JsonNode xmssRes =
        req(
            body(
                post("/api/v1/projects/" + pid + "/keys/generate"),
                Map.of("algorithm", "XMSS", "storage", "MANAGED")),
            admin,
            400);
    assertTrue(xmssRes.path("message").asText().contains("Stateful private keys"));

    // Stateless PQC / SM9 not supported by quick generation must return unsupported message
    JsonNode sphincsRes =
        req(
            body(
                post("/api/v1/projects/" + pid + "/keys/generate"),
                Map.of("algorithm", "SPHINCS", "storage", "MANAGED")),
            admin,
            400);
    assertTrue(sphincsRes.path("message").asText().contains("not supported by quick generation"));

    JsonNode sm9Res =
        req(
            body(
                post("/api/v1/projects/" + pid + "/keys/generate"),
                Map.of("algorithm", "SM9", "storage", "MANAGED")),
            admin,
            400);
    assertTrue(sm9Res.path("message").asText().contains("not supported by quick generation"));

    // Kyber generation without password is supported on gmssl provider
    JsonNode kyberRes =
        req(
            body(
                post("/api/v1/projects/" + pid + "/keys/generate"),
                Map.of("algorithm", "Kyber", "storage", "MANAGED")),
            admin,
            200);
    assertEquals("Kyber", kyberRes.path("key").path("algorithm").asText());
    assertNotNull(kyberRes.path("publicKey").path("id"));
    assertFalse(credentialService.hasPassphrase(kyberRes.path("key").path("id").asText()));

    // Kyber on openssl provider must be rejected
    JsonNode kyberOpensslRes =
        req(
            body(
                post("/api/v1/projects/" + pid + "/keys/generate"),
                Map.of("algorithm", "Kyber", "provider", "openssl", "storage", "MANAGED")),
            admin,
            400);
    assertTrue(kyberOpensslRes.path("message").asText().contains("OpenSSL does not support algorithm: Kyber"));
  }

  @Test
  void testSymmetricHexStrictValidation() throws Exception {
    Session admin = login("admin", "a-long-admin-password");
    String pid = project(admin, "hex-strict-project");

    // Corrupt hex content from engine must fail closed with ENGINE_ERROR
    JsonNode corruptRes =
        req(
            body(
                post("/api/v1/projects/" + pid + "/keys/generate"),
                Map.of("algorithm", "CORRUPT_HEX", "storage", "MANAGED")),
            admin,
            500);
    assertEquals("ENGINE_ERROR", corruptRes.path("code").asText());

    // Length mismatch (requested 256 bits but engine returned 128 bits) must fail closed
    JsonNode mismatchRes =
        req(
            body(
                post("/api/v1/projects/" + pid + "/keys/generate"),
                Map.of("algorithm", "LENGTH_MISMATCH", "bits", 256, "storage", "MANAGED")),
            admin,
            500);
    assertEquals("ENGINE_ERROR", mismatchRes.path("code").asText());
  }

  @Test
  void testFaultInjectionAsymmetricRollback() throws Exception {
    Session admin = login("admin", "a-long-admin-password");
    String pid = project(admin, "fault-injection-project");

    int beforeMaterials = s.rows("select * from materials where project_id=?", pid).size();
    int beforeCredentials = s.rows("select * from key_credentials").size();

    // Passing a 198-char name causes private key creation to succeed (198 <= 200 chars),
    // but subsequent public key creation (name + "-pub" = 202 chars > 200) fails in Materials.createControlled.
    String longName = "k".repeat(198);
    req(
        body(
            post("/api/v1/projects/" + pid + "/keys/generate"),
            Map.of("name", longName, "algorithm", "SM2", "storage", "MANAGED")),
        admin,
        500);

    // Verify rollback: zero orphan materials and zero orphan credentials created!
    int afterMaterials = s.rows("select * from materials where project_id=?", pid).size();
    int afterCredentials = s.rows("select * from key_credentials").size();
    assertEquals(beforeMaterials, afterMaterials, "Orphan materials must not remain after fault");
    assertEquals(beforeCredentials, afterCredentials, "Orphan credentials must not remain after fault");
  }

  @Test
  @org.junit.jupiter.api.extension.ExtendWith(org.springframework.boot.test.system.OutputCaptureExtension.class)
  void credentialWriteFailureRollsBackDatabase(org.springframework.boot.test.system.CapturedOutput output) throws Exception {
    verifyPersistenceFault(false, false, output);
  }

  @Test
  @org.junit.jupiter.api.extension.ExtendWith(org.springframework.boot.test.system.OutputCaptureExtension.class)
  void cleanupFailureStillRollsBackDatabaseWithoutSecretLogs(org.springframework.boot.test.system.CapturedOutput output) throws Exception {
    verifyPersistenceFault(true, false, output);
  }

  @Test
  @org.junit.jupiter.api.extension.ExtendWith(org.springframework.boot.test.system.OutputCaptureExtension.class)
  void publicWriteFailureWithCleanupFaultLeavesNoPartialDatabase(org.springframework.boot.test.system.CapturedOutput output) throws Exception {
    verifyPersistenceFault(true, true, output);
  }

  void verifyPersistenceFault(boolean cleanupFails, boolean publicFails,
      org.springframework.boot.test.system.CapturedOutput output) throws Exception {
    Session admin = login("admin", "a-long-admin-password");
    String pid = project(admin, "atomic-fault-" + UUID.randomUUID());
    String secret = "fixture-secret-not-for-logs";
    var activeTransaction = new java.util.concurrent.atomic.AtomicBoolean();
    var deletedIds = new ArrayList<String>();
    int credentialsBefore = s.rows("select * from key_credentials").size();
    org.mockito.Mockito.doAnswer(invocation -> {
      activeTransaction.set(org.springframework.transaction.support.TransactionSynchronizationManager.isActualTransactionActive());
      invocation.callRealMethod();
      try (var connection = java.util.Objects.requireNonNull(s.db.getDataSource()).getConnection();
          var query = connection.prepareStatement("select count(*) from materials where project_id=?")) {
        query.setString(1, pid);
        try (var rows = query.executeQuery()) {
          assertTrue(rows.next());
          assertEquals(0, rows.getInt(1), "Other connections must not see an uncommitted private key");
        }
      }
      if (!publicFails) throw new IllegalStateException(secret);
      return null;
    }).when(credentialService).savePassphrase(org.mockito.ArgumentMatchers.eq(pid), org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.anyString());
    org.mockito.Mockito.doAnswer(invocation -> {
      deletedIds.add(invocation.getArgument(0));
      if (cleanupFails) throw new IllegalStateException(secret);
      return invocation.callRealMethod();
    }).when(vault).delete(org.mockito.ArgumentMatchers.anyString());
    try {
      for (String storage : List.of("MANAGED", "TEMPORARY")) {
        var failure = assertThrows(ApiError.class, () -> keyGenerationService.generate(pid, "fault-user",
            Map.of("algorithm", "SM2", "storage", storage,
                "name", publicFails ? "k".repeat(storage.equals("MANAGED") ? 198 : 195) : "fault-key")));
        assertEquals("KEY_PERSISTENCE_ERROR", failure.code);
        assertEquals("Generated key persistence failed", failure.getMessage());
        assertTrue(activeTransaction.get(), "Private key and credential must share the outer DB transaction");
        assertTrue(s.rows("select id from materials where project_id=?", pid).isEmpty());
        assertEquals(credentialsBefore, s.rows("select * from key_credentials").size());
      }
      assertFalse(deletedIds.isEmpty(), "Vault cleanup must be attempted");
      assertFalse(output.getAll().contains(secret));
      if (cleanupFails) assertTrue(output.getAll().contains("KEYGEN_VAULT_CLEANUP_FAILED"));
    } finally {
      org.mockito.Mockito.reset(vault, credentialService);
      for (String id : deletedIds) vault.delete(id);
    }
  }

  @Test
  void testCredentialValidationAndSecurityLimits() throws Exception {
    Session admin = login("admin", "a-long-admin-password");
    String pid = project(admin, "cred-val-project");

    JsonNode gen =
        req(
            body(
                post("/api/v1/projects/" + pid + "/keys/generate"),
                Map.of("algorithm", "SM2", "storage", "MANAGED")),
            admin,
            200);
    String keyId = gen.path("key").path("id").asText();

    // 1. Empty password
    req(
        body(
            post("/api/v1/projects/" + pid + "/keys/" + keyId + "/passphrase"),
            Map.of("password", "")),
        admin,
        400);

    // 2. Password > 512 characters
    req(
        body(
            post("/api/v1/projects/" + pid + "/keys/" + keyId + "/passphrase"),
            Map.of("password", "a".repeat(513))),
        admin,
        400);

    // 3. Password containing NUL byte
    req(
        body(
            post("/api/v1/projects/" + pid + "/keys/" + keyId + "/passphrase"),
            Map.of("password", "pass\0word")),
        admin,
        400);
  }

  @Test
  void testKeyGenerationConcurrencyLimit() throws Exception {
    Session admin = login("admin", "a-long-admin-password");
    String pid = project(admin, "concurrent-keygen-project");

    var executor = Executors.newFixedThreadPool(4);
    var futures = new ArrayList<java.util.concurrent.Future<Integer>>();
    for (int i = 0; i < 4; i++) {
      futures.add(
          executor.submit(
              () -> {
                try {
                  var res =
                      mvc.perform(
                              as(
                                  body(
                                      post("/api/v1/projects/" + pid + "/keys/generate"),
                                      Map.of("algorithm", "SLOW_KEYGEN", "storage", "MANAGED")),
                                  admin))
                          .andReturn()
                          .getResponse();
                  return res.getStatus();
                } catch (Exception e) {
                  return 500;
                }
              }));
    }

    List<Integer> statuses = new ArrayList<>();
    for (var f : futures) {
      statuses.add(f.get());
    }
    executor.shutdown();

    // At least one request must have been rejected with 429 CONCURRENCY_LIMIT
    assertTrue(
        statuses.contains(429),
        "Expected at least one 429 CONCURRENCY_LIMIT among statuses: " + statuses);
  }
}
