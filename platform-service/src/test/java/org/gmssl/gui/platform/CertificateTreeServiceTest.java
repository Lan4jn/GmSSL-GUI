package org.gmssl.gui.platform;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import com.fasterxml.jackson.databind.*;
import com.sun.net.httpserver.HttpServer;
import jakarta.servlet.http.Cookie;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

@SpringBootTest
@AutoConfigureMockMvc
class CertificateTreeServiceTest {
  @Autowired CredentialService credentials;
  @Autowired Store store;
  @Autowired CertificateTreeService certTreeService;
  @Autowired MockMvc mvc;
  @Autowired ObjectMapper json;

  static HttpServer server;
  static Path dir;
  static Path runner;
  static JsonNode catalogJson;
  static ObjectMapper mapper = new ObjectMapper();

  static Path findRunner() {
    Path r = Path.of("../native/.build/bin/gmssl-runner");
    if (Files.exists(r)) return r.toAbsolutePath().normalize();
    r = Path.of("native/.build/bin/gmssl-runner");
    if (Files.exists(r)) return r.toAbsolutePath().normalize();
    return null;
  }

  static byte[] frame(List<String> arguments) throws IOException {
    ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    DataOutputStream out = new DataOutputStream(buffer);
    out.write("GMRUN001".getBytes(StandardCharsets.US_ASCII));
    out.writeInt(arguments.size());
    List<byte[]> encoded = new ArrayList<>();
    int total = 0;
    for (String value : arguments) {
      byte[] b = value.getBytes(StandardCharsets.UTF_8);
      total = Math.addExact(total, b.length);
      encoded.add(b);
    }
    out.writeInt(total);
    for (byte[] b : encoded) {
      out.writeInt(b.length);
      out.write(b);
    }
    return buffer.toByteArray();
  }

  @DynamicPropertySource
  static void properties(DynamicPropertyRegistry p) throws Exception {
    dir = Files.createTempDirectory("platform-cert-tree-vault");
    runner = findRunner();

    Path catPath = Path.of("../native/catalog.json");
    if (!Files.exists(catPath)) catPath = Path.of("native/catalog.json");
    catalogJson = mapper.readTree(catPath.toFile());

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
              response = catalogJson;
            } else if (path.endsWith("/key-generation-capabilities")) {
              response =
                  Map.of(
                      "providers",
                      List.of(
                          Map.of(
                              "id", "gmssl",
                              "available", true,
                              "version", "GmSSL 3.1.2",
                              "algorithms", List.of("SM4", "SM2"))),
                      "algorithms",
                      List.of(
                          Map.of(
                              "id", "SM2",
                              "kind", "PRIVATE_KEY",
                              "curves", List.of("sm2p256v1"),
                              "providers", List.of("gmssl"))));
            } else if (path.endsWith("key-generations")) {
              JsonNode in = mapper.readTree(ex.getRequestBody());
              String algo = in.path("algorithm").asText();
              String prov = in.path("provider").asText();
              String pass = in.path("password").asText("123456");

              Path tmp = Files.createTempDirectory("key-gen-tree-test");
              byte[] privBytes;
              byte[] pubBytes;

              Path kFile = tmp.resolve("key.pem");
              Path pubFile = tmp.resolve("pub.pem");

              Process proc =
                  new ProcessBuilder(runner.toString())
                      .directory(tmp.toFile())
                      .start();
              try (var os = proc.getOutputStream()) {
                os.write(frame(List.of("sm2keygen", "-pass", pass, "-out", "key.pem", "-pubout", "pub.pem")));
              }
              proc.waitFor(15, TimeUnit.SECONDS);

              privBytes = Files.readAllBytes(kFile);
              pubBytes = Files.readAllBytes(pubFile);

              response =
                  Map.of(
                      "provider", prov,
                      "algorithm", algo,
                      "keyKind", "PRIVATE_KEY",
                      "encoding", "PEM",
                      "valueBase64", Base64.getEncoder().encodeToString(privBytes),
                      "privateKeyBase64", Base64.getEncoder().encodeToString(privBytes),
                      "publicKeyBase64", Base64.getEncoder().encodeToString(pubBytes),
                      "warnings", List.of());
            } else if (path.endsWith("executions")) {
              JsonNode in = mapper.readTree(ex.getRequestBody());
              String toolId = in.path("toolId").asText();
              JsonNode params = in.path("parameters");
              JsonNode inputs = in.path("inputs");

              Path workDir = Files.createTempDirectory("engine-exec-tree-test");
              Map<String, String> tokenPaths = new HashMap<>();
              if (inputs != null && inputs.isObject()) {
                var it = inputs.fields();
                while (it.hasNext()) {
                  var entry = it.next();
                  String token = entry.getKey();
                  byte[] bytes = Base64.getDecoder().decode(entry.getValue().path("contentBase64").asText());
                  Path pFile = workDir.resolve("in_" + token + ".pem");
                  Files.write(pFile, bytes);
                  tokenPaths.put(token, pFile.toAbsolutePath().toString());
                }
              }

              JsonNode toolNode = null;
              for (JsonNode t : catalogJson.path("tools")) {
                if (t.path("id").asText().equals(toolId)) {
                  toolNode = t;
                  break;
                }
              }

              Map<String, String> paramFlags = new HashMap<>();
              if (toolNode != null) {
                for (JsonNode pDef : toolNode.path("parameters")) {
                  paramFlags.put(pDef.path("name").asText(), pDef.path("flag").asText());
                }
              }

              List<String> args = new ArrayList<>();
              args.add(toolId);
              System.err.println("MOCK_ENGINE_TOOL: " + toolId + " params: " + params + " inputs: " + (inputs != null ? inputs : "null"));

              if (params != null && params.isObject()) {
                var pIt = params.fields();
                while (pIt.hasNext()) {
                  var en = pIt.next();
                  String name = en.getKey();
                  JsonNode val = en.getValue();
                  String flag = paramFlags.get(name);
                  if (flag == null) flag = "-" + name;

                  if (val.isBoolean()) {
                    if (val.asBoolean()) {
                      args.add(flag);
                    }
                  } else if (val.isArray()) {
                    for (JsonNode item : val) {
                      args.add(flag);
                      String strVal = item.asText();
                      if (strVal.startsWith("input:")) {
                        String tok = strVal.substring("input:".length());
                        strVal = tokenPaths.getOrDefault(tok, strVal);
                      }
                      args.add(strVal);
                    }
                  } else {
                    args.add(flag);
                    String strVal = val.asText();
                    if (strVal.startsWith("input:")) {
                      String tok = strVal.substring("input:".length());
                      strVal = tokenPaths.getOrDefault(tok, strVal);
                    }
                    args.add(strVal);
                  }
                }
              }

              ProcessBuilder pb = new ProcessBuilder(runner.toString());
              pb.directory(workDir.toFile());
              Process proc = pb.start();
              try (var os = proc.getOutputStream()) {
                os.write(frame(args));
              }
              proc.waitFor(15, TimeUnit.SECONDS);
              int exitCode = proc.exitValue();
              byte[] stderrBytes = proc.getErrorStream().readAllBytes();
              byte[] stdoutBytes = proc.getInputStream().readAllBytes();
              if (exitCode != 0) {
                System.err.println("MOCK_ENGINE_FAIL: " + toolId + " exit=" + exitCode + " err=" + new String(stderrBytes, StandardCharsets.UTF_8) + " out=" + new String(stdoutBytes, StandardCharsets.UTF_8));
              }

              List<Map<String, Object>> artifacts = new ArrayList<>();
              String outParam = params.has("out") ? params.path("out").asText() : null;
              if (outParam != null) {
                Path outFile = workDir.resolve(outParam);
                if (Files.exists(outFile)) {
                  byte[] outBytes = Files.readAllBytes(outFile);
                  artifacts.add(
                      Map.of(
                          "name", outParam,
                          "mediaType", outParam.endsWith(".csr") ? "application/pkcs10" : "application/x-x509-ca-cert",
                          "contentBase64", Base64.getEncoder().encodeToString(outBytes)));
                }
              }

              try (var stream = Files.walk(workDir)) {
                for (Path pFile : stream.sorted(Comparator.reverseOrder()).toList()) {
                  Files.deleteIfExists(pFile);
                }
              }

              response =
                  Map.of(
                      "id", in.path("id").asText(),
                      "status", exitCode == 0 ? "SUCCEEDED" : "FAILED",
                      "exitCode", exitCode,
                      "durationMs", 20,
                      "stdoutBase64", "",
                      "stderr", "",
                      "artifacts", artifacts,
                      "truncated", false);
            } else {
              response = Map.of("error", "not found");
            }
            byte[] body = mapper.writeValueAsBytes(response);
            ex.getResponseHeaders().set("Content-Type", "application/json");
            ex.sendResponseHeaders(200, body.length);
            ex.getResponseBody().write(body);
          } catch (Exception e) {
            e.printStackTrace();
          } finally {
            ex.close();
          }
        });
    server.start();

    p.add(
        "spring.datasource.url",
        () -> "jdbc:h2:mem:cert_tree_test;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DB_CLOSE_DELAY=-1");
    p.add("GMSSL_BOOTSTRAP_USERNAME", () -> "admin");
    p.add("GMSSL_BOOTSTRAP_PASSWORD", () -> "a-long-admin-password");
    p.add("GMSSL_VAULT_MASTER_KEY", () -> Base64.getEncoder().encodeToString(new byte[32]));
    p.add("GMSSL_VAULT_DIR", () -> dir.toString());
    p.add("GMSSL_ENGINE_TOKEN", () -> "test-token");
    p.add("GMSSL_ENGINE_URL", () -> "http://127.0.0.1:" + server.getAddress().getPort());
    p.add("GMSSL_SESSION_COOKIE_SECURE", () -> "false");
  }

  @AfterAll
  static void tearDown() {
    if (server != null) server.stop(0);
  }

  record Session(Cookie cookie, String csrf) {}
  static final Map<String, Session> sessions = new HashMap<>();

  Session login(String u, String p) throws Exception {
    if (sessions.containsKey(u)) return sessions.get(u);
    var result =
        mvc.perform(
                post("/api/v1/auth/login")
                    .contentType("application/json")
                    .content(json.writeValueAsBytes(Map.of("username", u, "password", p))))
            .andExpect(status().isOk())
            .andReturn();
    String cookie = result.getResponse().getHeader("Set-Cookie").split(";", 2)[0].split("=", 2)[1];
    Session session = new Session(
        new Cookie("GMSSL_SESSION", cookie),
        json.readTree(result.getResponse().getContentAsString()).path("csrfToken").asText());
    sessions.put(u, session);
    return session;
  }

  MockHttpServletRequestBuilder as(MockHttpServletRequestBuilder r, Session u) {
    return r.cookie(u.cookie).header("X-CSRF-Token", u.csrf);
  }

  JsonNode req(MockHttpServletRequestBuilder r, Session u, int code) throws Exception {
    var response = mvc.perform(as(r, u)).andReturn().getResponse();
    if (response.getStatus() != code) {
      System.err.println("REQ_FAIL: expected=" + code + " actual=" + response.getStatus() + " body=" + response.getContentAsString());
    }
    assertEquals(code, response.getStatus(), response.getContentAsString());
    return response.getContentAsString().isBlank()
        ? json.createObjectNode()
        : json.readTree(response.getContentAsString());
  }

  String createProject(Session u, String name) throws Exception {
    var res =
        req(
            post("/api/v1/projects")
                .contentType("application/json")
                .content(json.writeValueAsBytes(Map.of("name", name))),
            u,
            200);
    return res.path("id").asText();
  }

  @Test
  void testRootCaClassifiedAndSelectable() throws Exception {
    var admin = login("admin", "a-long-admin-password");
    String pid = createProject(admin, "root-ca-tree-project");

    Map<String, Object> req = new LinkedHashMap<>();
    req.put("profile", "ROOT_CA");
    req.put("name", "CorpRootCA");
    req.put("subject", Map.of("CN", "Corp Root CA", "C", "CN", "O", "Corp"));
    req.put("days", 3650);

    req(post("/api/v1/projects/" + pid + "/certificate-workflows")
        .contentType("application/json")
        .content(json.writeValueAsBytes(req)), admin, 200);

    var certs = req(get("/api/v1/projects/" + pid + "/certificates"), admin, 200);
    assertEquals(1, certs.path("nodes").size(), certs.toString());

    var node = certs.path("nodes").get(0);
    assertEquals("ROOT_CA", node.path("category").asText());
    assertEquals("Corp Root CA", node.path("subjectCN").asText());
    assertEquals("Corp Root CA", node.path("issuerCN").asText());
    assertTrue(node.path("isCa").asBoolean());
    assertTrue(node.path("selectableAsIssuer").asBoolean());
    assertEquals("VALID", node.path("validityStatus").asText());
    assertEquals("UNCHECKED", node.path("revocationStatus").asText());
    assertTrue(node.path("downloadRef").asText().startsWith("file:"));
    assertEquals(0, node.path("parentRefs").size());
  }

  @Test
  void testSelfSignedEndEntityIsNotRootCa() throws Exception {
    var admin = login("admin", "a-long-admin-password");
    String pid = createProject(admin, "self-signed-tree-project");

    Map<String, Object> req = new LinkedHashMap<>();
    req.put("profile", "SELF_SIGNED");
    req.put("name", "LocalDevCert");
    req.put("subject", Map.of("CN", "localhost", "C", "CN"));
    req.put("sanDns", List.of("localhost"));
    req.put("days", 365);
    req.put("purpose", "SERVER");

    req(post("/api/v1/projects/" + pid + "/certificate-workflows")
        .contentType("application/json")
        .content(json.writeValueAsBytes(req)), admin, 200);

    var certs = req(get("/api/v1/projects/" + pid + "/certificates"), admin, 200);
    assertEquals(1, certs.path("nodes").size());

    var node = certs.path("nodes").get(0);
    assertEquals("SELF_SIGNED_END_ENTITY", node.path("category").asText());
    assertFalse(node.path("isCa").asBoolean());
    assertFalse(node.path("selectableAsIssuer").asBoolean());
  }

  @Test
  void testHierarchyRootAndLeafCert() throws Exception {
    var admin = login("admin", "a-long-admin-password");
    String pid = createProject(admin, "hierarchy-tree-project");

    // 1. Root CA
    var root = req(post("/api/v1/projects/" + pid + "/certificate-workflows")
        .contentType("application/json")
        .content(json.writeValueAsBytes(Map.of("profile", "ROOT_CA", "name", "MyCA", "subject", Map.of("CN", "My Root CA")))), admin, 200);
    String rootKeyRef = "key:" + root.path("keys").get(0).path("id").asText();
    String rootCertRef = "file:" + root.path("files").get(0).path("id").asText();

    // 2. Leaf Cert
    req(post("/api/v1/projects/" + pid + "/certificate-workflows")
        .contentType("application/json")
        .content(json.writeValueAsBytes(Map.of(
            "profile", "QUICK_ISSUE",
            "name", "AppServer",
            "issuerCertRef", rootCertRef,
            "issuerKeyRef", rootKeyRef,
            "subject", Map.of("CN", "app.example.com"),
            "days", 365
        ))), admin, 200);

    var certs = req(get("/api/v1/projects/" + pid + "/certificates"), admin, 200);
    // Nodes should have 2 unique certificates (Root CA and AppServer)
    assertEquals(2, certs.path("nodes").size(), certs.toString());

    JsonNode rootNode = null;
    JsonNode leafNode = null;
    for (var n : certs.path("nodes")) {
      if ("ROOT_CA".equals(n.path("category").asText())) rootNode = n;
      if ("ISSUED_CERT".equals(n.path("category").asText())) leafNode = n;
    }

    assertNotNull(rootNode);
    assertNotNull(leafNode);
    assertEquals(1, leafNode.path("parentRefs").size());
    assertEquals(rootNode.path("id").asText(), leafNode.path("parentRefs").get(0).asText());

    // Bundles should contain the _chain.pem file
    assertTrue(certs.path("bundles").size() >= 1);
  }

  @Test
  void testOrphanCertificateWhenIssuerNotPresent() throws Exception {
    var admin = login("admin", "a-long-admin-password");
    String pidA = createProject(admin, "proj-a");
    String pidB = createProject(admin, "proj-b");

    // Create root + leaf in Proj A
    var root = req(post("/api/v1/projects/" + pidA + "/certificate-workflows")
        .contentType("application/json")
        .content(json.writeValueAsBytes(Map.of("profile", "ROOT_CA", "name", "ProjARoot", "subject", Map.of("CN", "ProjA CA")))), admin, 200);
    var leaf = req(post("/api/v1/projects/" + pidA + "/certificate-workflows")
        .contentType("application/json")
        .content(json.writeValueAsBytes(Map.of(
            "profile", "CA_SIGN",
            "name", "LeafInA",
            "issuerCertRef", "file:" + root.path("files").get(0).path("id").asText(),
            "issuerKeyRef", "key:" + root.path("keys").get(0).path("id").asText(),
            "subject", Map.of("CN", "leaf.proj-a.com"),
            "days", 365
        ))), admin, 200);

    String leafFileId = null;
    for (var f : leaf.path("files")) {
      if (f.path("name").asText().endsWith("_cert.pem")) {
        leafFileId = f.path("id").asText();
        break;
      }
    }
    assertNotNull(leafFileId, "Certificate file must be found in workflow output files");
    var fileResp = mvc.perform(as(get("/api/v1/projects/" + pidA + "/files/" + leafFileId + "/download"), admin))
        .andExpect(status().isOk())
        .andReturn().getResponse();
    byte[] fileContent = fileResp.getContentAsByteArray();

    // Upload leaf only into Proj B
    MockMultipartFile mp = new MockMultipartFile("file", "leaf_only.pem", "application/x-x509-ca-cert", fileContent);
    mvc.perform(as(multipart("/api/v1/projects/" + pidB + "/files").file(mp).param("name", "leaf_only.pem"), admin))
        .andExpect(status().isOk());

    var certsB = req(get("/api/v1/projects/" + pidB + "/certificates"), admin, 200);
    assertEquals(1, certsB.path("nodes").size(), certsB.toString());
    var node = certsB.path("nodes").get(0);
    assertEquals("ORPHAN", node.path("category").asText());
    assertFalse(node.path("selectableAsIssuer").asBoolean());
    assertEquals(0, node.path("parentRefs").size());
  }

  @Test
  void testCsrExtractedAsCsrNode() throws Exception {
    var admin = login("admin", "a-long-admin-password");
    String pid = createProject(admin, "csr-tree-project");

    Map<String, Object> csrReq = new LinkedHashMap<>();
    csrReq.put("profile", "CSR");
    csrReq.put("name", "ExtService");
    csrReq.put("subject", Map.of("CN", "service.internal", "C", "CN", "O", "Finance"));
    req(post("/api/v1/projects/" + pid + "/certificate-workflows")
        .contentType("application/json")
        .content(json.writeValueAsBytes(csrReq)), admin, 200);

    var certs = req(get("/api/v1/projects/" + pid + "/certificates"), admin, 200);
    assertEquals(0, certs.path("nodes").size());
    assertEquals(1, certs.path("csrs").size());
    assertEquals("ExtService.csr", certs.path("csrs").get(0).path("name").asText());
    assertEquals("service.internal", certs.path("csrs").get(0).path("subjectCN").asText());
  }

  @Test
  void testInvalidFileToleratedAsUnsupportedWithout500() throws Exception {
    var admin = login("admin", "a-long-admin-password");
    String pid = createProject(admin, "corrupt-tree-project");

    MockMultipartFile mp = new MockMultipartFile("file", "corrupt.pem", "application/x-x509-ca-cert", "corrupted-content".getBytes(StandardCharsets.UTF_8));
    mvc.perform(as(multipart("/api/v1/projects/" + pid + "/files").file(mp).param("name", "corrupt.pem"), admin))
        .andExpect(status().isOk());

    var certs = req(get("/api/v1/projects/" + pid + "/certificates"), admin, 200);
    assertEquals(1, certs.path("nodes").size());
    var node = certs.path("nodes").get(0);
    assertEquals("UNSUPPORTED", node.path("category").asText());
    assertEquals("UNKNOWN", node.path("validityStatus").asText());
    assertNotNull(node.path("error").asText());
  }

  @Test
  void testRepeatedReadsProduceZeroJobs() throws Exception {
    var admin = login("admin", "a-long-admin-password");
    String pid = createProject(admin, "cache-tree-project");

    // Initial query
    var c1 = req(get("/api/v1/projects/" + pid + "/certificates"), admin, 200);

    int jobsBefore = store.rows("select count(*) as c from jobs where project_id=?", pid).get(0).get("c") instanceof Number n ? n.intValue() : 0;

    // 20 repeated queries
    for (int i = 0; i < 100; i++) {
      var c2 = req(get("/api/v1/projects/" + pid + "/certificates"), admin, 200);
      assertEquals(c1.path("nodes").size(), c2.path("nodes").size());
    }

    int jobsAfter = store.rows("select count(*) as c from jobs where project_id=?", pid).get(0).get("c") instanceof Number n ? n.intValue() : 0;
    assertEquals(jobsBefore, jobsAfter, "Repeated reads must produce zero jobs");
  }

  @Test
  void testUnauthenticatedBlocked() throws Exception {
    mvc.perform(get("/api/v1/projects/non-existent-pid/certificates"))
        .andExpect(status().isUnauthorized());
  }

  @Test
  void testIntermediateCaThreeTierHierarchy() throws Exception {
    var admin = login("admin", "a-long-admin-password");
    String pid = createProject(admin, "intermediate-tree-project");

    // 1. Root CA
    var root = req(post("/api/v1/projects/" + pid + "/certificate-workflows")
        .contentType("application/json")
        .content(json.writeValueAsBytes(Map.of("profile", "ROOT_CA", "name", "MyRoot", "subject", Map.of("CN", "Root Authority"), "days", 3650))), admin, 200);
    String rootKeyRef = "key:" + root.path("keys").get(0).path("id").asText();
    String rootCertRef = "file:" + root.path("files").get(0).path("id").asText();

    // 2. Intermediate CA
    var inter = req(post("/api/v1/projects/" + pid + "/certificate-workflows")
        .contentType("application/json")
        .content(json.writeValueAsBytes(Map.of(
            "profile", "INTERMEDIATE_CA",
            "name", "MyInter",
            "issuerCertRef", rootCertRef,
            "issuerKeyRef", rootKeyRef,
            "subject", Map.of("CN", "Inter Authority"),
            "days", 1800
        ))), admin, 200);
    String interKeyRef = "key:" + inter.path("keys").get(0).path("id").asText();
    String interCertRef = null;
    for (var f : inter.path("files")) {
      if (f.path("name").asText().endsWith("_intermediate_ca.pem")) {
        interCertRef = "file:" + f.path("id").asText();
        break;
      }
    }
    assertNotNull(interCertRef, "Intermediate CA cert file must be present");

    // 3. Leaf Cert signed by Intermediate CA
    req(post("/api/v1/projects/" + pid + "/certificate-workflows")
        .contentType("application/json")
        .content(json.writeValueAsBytes(Map.of(
            "profile", "CA_SIGN",
            "name", "EndService",
            "issuerCertRef", interCertRef,
            "issuerKeyRef", interKeyRef,
            "subject", Map.of("CN", "service.internal"),
            "days", 365
        ))), admin, 200);

    var certs = req(get("/api/v1/projects/" + pid + "/certificates"), admin, 200);
    assertEquals(3, certs.path("nodes").size(), certs.toString());

    JsonNode rootNode = null, interNode = null, leafNode = null;
    for (var n : certs.path("nodes")) {
      if ("ROOT_CA".equals(n.path("category").asText())) rootNode = n;
      if ("INTERMEDIATE_CA".equals(n.path("category").asText())) interNode = n;
      if ("ISSUED_CERT".equals(n.path("category").asText())) leafNode = n;
    }

    assertNotNull(rootNode);
    assertNotNull(interNode);
    assertNotNull(leafNode);

    assertEquals(0, rootNode.path("parentRefs").size());
    assertEquals(1, interNode.path("parentRefs").size());
    assertEquals(rootNode.path("id").asText(), interNode.path("parentRefs").get(0).asText());

    assertEquals(1, leafNode.path("parentRefs").size());
    assertEquals(interNode.path("id").asText(), leafNode.path("parentRefs").get(0).asText());

    assertTrue(interNode.path("isCa").asBoolean());
    assertTrue(interNode.path("selectableAsIssuer").asBoolean());
  }

  @Test
  void testViewerCanReadCertificatesAndOtherProject403() throws Exception {
    var admin = login("admin", "a-long-admin-password");
    String pid = createProject(admin, "viewer-perm-project");

    // Create user viewer
    var uRes = req(post("/api/v1/users")
        .contentType("application/json")
        .content(json.writeValueAsBytes(Map.of("username", "tree-viewer", "password", "a-long-viewer-password", "role", "USER"))), admin, 200);
    String uid = uRes.path("id").asText();

    // Grant VIEWER (role 1) on pid
    req(put("/api/v1/projects/" + pid + "/members/" + uid)
        .contentType("application/json")
        .content(json.writeValueAsBytes(Map.of("role", "VIEWER"))), admin, 200);

    var viewer = login("tree-viewer", "a-long-viewer-password");
    var res = req(get("/api/v1/projects/" + pid + "/certificates"), viewer, 200);
    assertNotNull(res.path("nodes"));

    // Other project should be 403
    String otherPid = createProject(admin, "other-closed-project");
    mvc.perform(as(get("/api/v1/projects/" + otherPid + "/certificates"), viewer))
        .andExpect(status().isForbidden());
  }

  @Test
  void testCacheInvalidationOnAddAndDelete() throws Exception {
    var admin = login("admin", "a-long-admin-password");
    String pid = createProject(admin, "cache-invalidation-project");

    var c0 = req(get("/api/v1/projects/" + pid + "/certificates"), admin, 200);
    assertEquals(0, c0.path("nodes").size());

    // Upload an invalid cert file
    MockMultipartFile mp = new MockMultipartFile("file", "inv.pem", "application/x-x509-ca-cert", "bad-data".getBytes(StandardCharsets.UTF_8));
    var uploadRes = req(multipart("/api/v1/projects/" + pid + "/files").file(mp).param("name", "inv.pem"), admin, 200);
    String fileId = uploadRes.path("id").asText();

    // Cache must have refreshed immediately
    var c1 = req(get("/api/v1/projects/" + pid + "/certificates"), admin, 200);
    assertEquals(1, c1.path("nodes").size());

    // Delete file
    mvc.perform(as(delete("/api/v1/projects/" + pid + "/files/" + fileId), admin))
        .andExpect(status().isNoContent());

    // Cache must reflect deletion
    var c2 = req(get("/api/v1/projects/" + pid + "/certificates"), admin, 200);
    assertEquals(0, c2.path("nodes").size());
  }
  @Test
  void testSameKeyCertAndCsrLinkedBidirectionally() throws Exception {
    var admin = login("admin", "a-long-admin-password");
    String pid = createProject(admin, "linked-csr-cert-project");

    // 1. Root CA
    var root = req(post("/api/v1/projects/" + pid + "/certificate-workflows")
        .contentType("application/json")
        .content(json.writeValueAsBytes(Map.of("profile", "ROOT_CA", "name", "SignCA", "subject", Map.of("CN", "Sign CA"), "days", 3650))), admin, 200);
    String rootKeyRef = "key:" + root.path("keys").get(0).path("id").asText();
    String rootCertRef = "file:" + root.path("files").get(0).path("id").asText();

    // 2. CSR
    var csrRes = req(post("/api/v1/projects/" + pid + "/certificate-workflows")
        .contentType("application/json")
        .content(json.writeValueAsBytes(Map.of(
            "profile", "CSR",
            "name", "MyService",
            "subject", Map.of("CN", "myservice.local", "C", "CN")
        ))), admin, 200);
    String csrFileRef = "file:" + csrRes.path("files").get(0).path("id").asText();

    // 3. Sign cert using that CSR
    var signRes = req(post("/api/v1/projects/" + pid + "/certificate-workflows")
        .contentType("application/json")
        .content(json.writeValueAsBytes(Map.of(
            "profile", "CA_SIGN",
            "name", "MyServiceCert",
            "csrRef", csrFileRef,
            "issuerCertRef", rootCertRef,
            "issuerKeyRef", rootKeyRef,
            "days", 365
        ))), admin, 200);

    var certs = req(get("/api/v1/projects/" + pid + "/certificates"), admin, 200);
    assertEquals(1, certs.path("csrs").size());
    assertEquals(2, certs.path("nodes").size());

    var csrNode = certs.path("csrs").get(0);
    assertEquals(csrFileRef, csrNode.path("id").asText());
    assertEquals("KEY_AND_SUBJECT_MATCH", csrNode.path("matchKind").asText());
    assertFalse(csrNode.path("ambiguous").asBoolean());
    assertEquals(1, csrNode.path("matchedCertIds").size());

    JsonNode issuedCertNode = null;
    for (var n : certs.path("nodes")) {
      if ("ISSUED_CERT".equals(n.path("category").asText())) {
        issuedCertNode = n;
        break;
      }
    }
    assertNotNull(issuedCertNode);
    assertEquals(issuedCertNode.path("id").asText(), csrNode.path("matchedCertIds").get(0).asText());

    assertEquals(1, issuedCertNode.path("matchedCsrRefs").size());
    assertEquals(csrFileRef, issuedCertNode.path("matchedCsrRefs").get(0).asText());
    assertEquals("KEY_AND_SUBJECT_MATCH", issuedCertNode.path("csrMatchEvidence").asText());
  }

  @Test
  void testDifferentKeySameCnDoesNotMatch() throws Exception {
    var admin = login("admin", "a-long-admin-password");
    String pid = createProject(admin, "different-key-same-cn-project");

    // CSR with CN="same.cn.local"
    req(post("/api/v1/projects/" + pid + "/certificate-workflows")
        .contentType("application/json")
        .content(json.writeValueAsBytes(Map.of(
            "profile", "CSR",
            "name", "SameCnCsr",
            "subject", Map.of("CN", "same.cn.local")
        ))), admin, 200);

    // Self-signed cert with CN="same.cn.local" but freshly generated independent key
    req(post("/api/v1/projects/" + pid + "/certificate-workflows")
        .contentType("application/json")
        .content(json.writeValueAsBytes(Map.of(
            "profile", "SELF_SIGNED",
            "name", "SameCnCert",
            "subject", Map.of("CN", "same.cn.local"),
            "days", 365
        ))), admin, 200);

    var certs = req(get("/api/v1/projects/" + pid + "/certificates"), admin, 200);
    assertEquals(1, certs.path("csrs").size());
    assertEquals(1, certs.path("nodes").size());

    var csrNode = certs.path("csrs").get(0);
    assertEquals("UNMATCHED", csrNode.path("matchKind").asText());
    assertEquals(0, csrNode.path("matchedCertIds").size());
    assertFalse(csrNode.path("ambiguous").asBoolean());

    var certNode = certs.path("nodes").get(0);
    assertEquals(0, certNode.path("matchedCsrRefs").size());
    assertTrue(certNode.path("csrMatchEvidence").isNull() || certNode.path("csrMatchEvidence").isMissingNode());
  }

  @Test
  void testInvalidCsrDoesNotMatch() throws Exception {
    var admin = login("admin", "a-long-admin-password");
    String pid = createProject(admin, "invalid-csr-project");

    MockMultipartFile mp = new MockMultipartFile("file", "corrupt.csr", "application/pkcs10", "bad-csr-content".getBytes(StandardCharsets.UTF_8));
    mvc.perform(as(multipart("/api/v1/projects/" + pid + "/files").file(mp).param("name", "corrupt.csr"), admin))
        .andExpect(status().isOk());

    var certs = req(get("/api/v1/projects/" + pid + "/certificates"), admin, 200);
    assertEquals(1, certs.path("csrs").size());
    var csrNode = certs.path("csrs").get(0);
    assertEquals("INVALID_CSR", csrNode.path("matchKind").asText());
    assertEquals(0, csrNode.path("matchedCertIds").size());
    assertFalse(csrNode.path("ambiguous").asBoolean());
    assertNotNull(csrNode.path("error").asText());
  }
  @Test
  void testSameKeyDifferentSubjectMatch() throws Exception {
    var admin = login("admin", "a-long-admin-password");
    String pid = createProject(admin, "diff-subject-project");

    // 1. Root CA
    var root = req(post("/api/v1/projects/" + pid + "/certificate-workflows")
        .contentType("application/json")
        .content(json.writeValueAsBytes(Map.of("profile", "ROOT_CA", "name", "DiffSubCA", "subject", Map.of("CN", "DiffSub CA"), "days", 3650))), admin, 200);
    String rootKeyRef = "key:" + root.path("keys").get(0).path("id").asText();
    String rootCertRef = "file:" + root.path("files").get(0).path("id").asText();

    // 2. Generate a key to share
    var genRes = req(post("/api/v1/projects/" + pid + "/certificate-workflows")
        .contentType("application/json")
        .content(json.writeValueAsBytes(Map.of(
            "profile", "CSR",
            "name", "CsrOriginal",
            "subject", Map.of("CN", "original.local", "O", "OrgA")
        ))), admin, 200);
    String sharedKeyRef = "key:" + genRes.path("keys").get(0).path("id").asText();
    String csr1Ref = "file:" + genRes.path("files").get(0).path("id").asText();

    // 3. Generate a second CSR with the same key but different subject
    var csr2Res = req(post("/api/v1/projects/" + pid + "/certificate-workflows")
        .contentType("application/json")
        .content(json.writeValueAsBytes(Map.of(
            "profile", "CSR",
            "name", "CsrChangedSubject",
            "keyRef", sharedKeyRef,
            "subject", Map.of("CN", "changed.local", "O", "OrgB")
        ))), admin, 200);
    String csr2Ref = "file:" + csr2Res.path("files").get(0).path("id").asText();

    // 4. Sign certificate using CsrOriginal (subject CN=original.local)
    req(post("/api/v1/projects/" + pid + "/certificate-workflows")
        .contentType("application/json")
        .content(json.writeValueAsBytes(Map.of(
            "profile", "CA_SIGN",
            "name", "OriginalCert",
            "csrRef", csr1Ref,
            "issuerCertRef", rootCertRef,
            "issuerKeyRef", rootKeyRef,
            "days", 365
        ))), admin, 200);

    var certs = req(get("/api/v1/projects/" + pid + "/certificates"), admin, 200);
    assertEquals(2, certs.path("csrs").size());

    JsonNode csrOrig = null, csrChanged = null;
    for (var c : certs.path("csrs")) {
      if (csr1Ref.equals(c.path("id").asText())) csrOrig = c;
      if (csr2Ref.equals(c.path("id").asText())) csrChanged = c;
    }
    assertNotNull(csrOrig);
    assertNotNull(csrChanged);

    // Both CSRs share the same key, so both should have ambiguous = true
    assertTrue(csrOrig.path("ambiguous").asBoolean());
    assertTrue(csrChanged.path("ambiguous").asBoolean());

    // CsrOrig matches subject of the certificate
    assertEquals("KEY_AND_SUBJECT_MATCH", csrOrig.path("matchKind").asText());
    // CsrChanged has different subject than the certificate
    assertEquals("KEY_MATCH_DIFFERENT_SUBJECT", csrChanged.path("matchKind").asText());

    // On the certificate node side: has 2 candidate CSRs -> AMBIGUOUS_MATCH
    JsonNode certNode = null;
    for (var n : certs.path("nodes")) {
      if ("ISSUED_CERT".equals(n.path("category").asText())) {
        certNode = n;
        break;
      }
    }
    assertNotNull(certNode);
    assertEquals(2, certNode.path("matchedCsrRefs").size());
    assertEquals("AMBIGUOUS_MATCH", certNode.path("csrMatchEvidence").asText());
  }

  @Test
  void testBundleCertMatchesCsr() throws Exception {
    var admin = login("admin", "a-long-admin-password");
    String pid = createProject(admin, "bundle-csr-link-project");

    // 1. Root CA
    var root = req(post("/api/v1/projects/" + pid + "/certificate-workflows")
        .contentType("application/json")
        .content(json.writeValueAsBytes(Map.of("profile", "ROOT_CA", "name", "BndlCA", "subject", Map.of("CN", "Bndl Root CA"), "days", 3650))), admin, 200);
    String rootKeyRef = "key:" + root.path("keys").get(0).path("id").asText();
    String rootCertRef = "file:" + root.path("files").get(0).path("id").asText();

    // 2. Quick issue leaf cert (creates key, csr, cert, and chain bundle)
    req(post("/api/v1/projects/" + pid + "/certificate-workflows")
        .contentType("application/json")
        .content(json.writeValueAsBytes(Map.of(
            "profile", "QUICK_ISSUE",
            "name", "QuickLeaf",
            "issuerCertRef", rootCertRef,
            "issuerKeyRef", rootKeyRef,
            "subject", Map.of("CN", "quick.bundle.local"),
            "days", 365
        ))), admin, 200);

    var certs = req(get("/api/v1/projects/" + pid + "/certificates"), admin, 200);
    assertEquals(1, certs.path("csrs").size());
    var csrNode = certs.path("csrs").get(0);

    // Should match the issued certificate
    assertEquals(1, csrNode.path("matchedCertIds").size());
    assertEquals("KEY_AND_SUBJECT_MATCH", csrNode.path("matchKind").asText());

    // Bundles should contain chain file
    assertTrue(certs.path("bundles").size() >= 1);
  }
}
