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
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

@SpringBootTest
@AutoConfigureMockMvc
class CertificateWorkflowTest {
  @Autowired CredentialService credentials;
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
    dir = Files.createTempDirectory("platform-cert-workflow-vault");
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

              Path tmp = Files.createTempDirectory("key-gen-test");
              byte[] privBytes;
              byte[] pubBytes;
              try {
                ProcessBuilder pb = new ProcessBuilder(runner.toString());
                pb.directory(tmp.toFile());
                Process proc = pb.start();
                try (var os = proc.getOutputStream()) {
                  os.write(frame(List.of("sm2keygen", "-pass", pass, "-out", "k.pem", "-pubout", "p.pem")));
                }
                proc.waitFor(10, TimeUnit.SECONDS);
                privBytes = Files.readAllBytes(tmp.resolve("k.pem"));
                pubBytes = Files.readAllBytes(tmp.resolve("p.pem"));
              } finally {
                Files.deleteIfExists(tmp.resolve("k.pem"));
                Files.deleteIfExists(tmp.resolve("p.pem"));
                Files.deleteIfExists(tmp);
              }

              response =
                  Map.of(
                      "provider", prov,
                      "algorithm", algo,
                      "keyKind", "PRIVATE_KEY",
                      "encoding", "PEM",
                      "privateKeyBase64", Base64.getEncoder().encodeToString(privBytes),
                      "publicKeyBase64", Base64.getEncoder().encodeToString(pubBytes),
                      "warnings", List.of());
            } else if (path.endsWith("executions")) {
              JsonNode in = mapper.readTree(ex.getRequestBody());
              String toolId = in.path("toolId").asText();
              JsonNode params = in.path("parameters");
              JsonNode inputs = in.path("inputs");

              Path workDir = Files.createTempDirectory("engine-exec-test");
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

              // Find tool definition in catalog
              JsonNode toolNode = null;
              for (JsonNode t : catalogJson.path("tools")) {
                if (t.path("id").asText().equals(toolId)) {
                  toolNode = t;
                  break;
                }
              }

              Map<String, String> paramFlags = new HashMap<>();
              Map<String, String> paramTypes = new HashMap<>();
              if (toolNode != null) {
                for (JsonNode pDef : toolNode.path("parameters")) {
                  paramFlags.put(pDef.path("name").asText(), pDef.path("flag").asText());
                  paramTypes.put(pDef.path("name").asText(), pDef.path("type").asText());
                }
              }

              List<String> args = new ArrayList<>();
              args.add(toolId);

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
              byte[] stdout = proc.getInputStream().readAllBytes();
              byte[] stderr = proc.getErrorStream().readAllBytes();

              List<Map<String, Object>> artifacts = new ArrayList<>();
              String outParam = params.has("out") ? params.path("out").asText() : (params.has("sig") && toolId.equals("sm2sign") ? params.path("sig").asText() : null);
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

              // Cleanup workDir
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
                      "stdoutBase64", Base64.getEncoder().encodeToString(stdout),
                      "stderr", new String(stderr, StandardCharsets.UTF_8),
                      "truncated", false,
                      "artifacts", artifacts,
                      "updatedInputs", List.of());
            } else {
              response = Map.of("status", "OK");
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
        () -> "jdbc:h2:mem:cert_workflow_test;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DB_CLOSE_DELAY=-1");
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
  @Autowired Vault vault;
  @Autowired Jobs jobs;
  @Autowired CredentialService credentialService;
  @Autowired CertificateWorkflowService workflowService;

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
    var response = mvc.perform(as(r, u)).andExpect(status().is(code)).andReturn().getResponse();
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
  void testRootCaProfileWorkflow() throws Exception {
    var admin = login("admin", "a-long-admin-password");
    String pid = createProject(admin, "root-ca-project");

    Map<String, Object> req = new LinkedHashMap<>();
    req.put("profile", "ROOT_CA");
    req.put("name", "CorpRootCA");
    req.put("subject", Map.of("CN", "Corp Root CA", "C", "CN", "O", "Corp", "OU", "Security"));
    req.put("days", 3650);

    var res =
        req(
            post("/api/v1/projects/" + pid + "/certificate-workflows")
                .contentType("application/json")
                .content(json.writeValueAsBytes(req)),
            admin,
            200);

    assertEquals("SUCCEEDED", res.path("status").asText(), res.toString());
    assertNotNull(res.path("workflowId").asText());
    assertEquals(3, res.path("stages").size());
    assertEquals("generate_key", res.path("stages").get(0).path("name").asText());
    assertEquals("generate_root_ca", res.path("stages").get(1).path("name").asText());
    assertEquals("parse_certificate", res.path("stages").get(2).path("name").asText());

    assertEquals(1, res.path("keys").size());
    assertEquals(1, res.path("files").size());
    String certFileId = res.path("files").get(0).path("id").asText();
    assertNotNull(certFileId);

    // Verify cert file exists in project materials
    var rawFile = materials.raw(pid, certFileId, "FILE");
    assertEquals("CorpRootCA_root_ca.pem", rawFile.get("name"));
    assertEquals("application/x-x509-ca-cert", rawFile.get("media_type"));
  }

  @Test
  void testSelfSignedProfileWorkflow() throws Exception {
    var admin = login("admin", "a-long-admin-password");
    String pid = createProject(admin, "self-signed-project");

    Map<String, Object> req = new LinkedHashMap<>();
    req.put("profile", "SELF_SIGNED");
    req.put("name", "LocalDevCert");
    req.put("subject", Map.of("CN", "localhost", "C", "CN"));
    req.put("sanDns", List.of("localhost", "app.local"));
    req.put("days", 365);
    req.put("purpose", "SERVER");

    var res =
        req(
            post("/api/v1/projects/" + pid + "/certificate-workflows")
                .contentType("application/json")
                .content(json.writeValueAsBytes(req)),
            admin,
            200);

    assertEquals("SUCCEEDED", res.path("status").asText(), res.toString());
    assertEquals(3, res.path("stages").size());
    assertEquals("generate_key", res.path("stages").get(0).path("name").asText());
    assertEquals("generate_certificate", res.path("stages").get(1).path("name").asText());
    assertEquals("parse_certificate", res.path("stages").get(2).path("name").asText());

    assertEquals(1, res.path("keys").size());
    assertEquals(1, res.path("files").size());
    String certFileId = res.path("files").get(0).path("id").asText();
    var rawFile = materials.raw(pid, certFileId, "FILE");
    assertEquals("LocalDevCert_cert.pem", rawFile.get("name"));
  }

  @Test
  void testCsrProfileWorkflow() throws Exception {
    var admin = login("admin", "a-long-admin-password");
    String pid = createProject(admin, "csr-project");

    Map<String, Object> req = new LinkedHashMap<>();
    req.put("profile", "CSR");
    req.put("name", "PaymentService");
    req.put("subject", Map.of("CN", "payment.example.com", "C", "CN", "O", "Bank"));

    var res =
        req(
            post("/api/v1/projects/" + pid + "/certificate-workflows")
                .contentType("application/json")
                .content(json.writeValueAsBytes(req)),
            admin,
            200);

    assertEquals("SUCCEEDED", res.path("status").asText(), res.toString());
    assertEquals(3, res.path("stages").size());
    assertEquals("generate_key", res.path("stages").get(0).path("name").asText());
    assertEquals("generate_csr", res.path("stages").get(1).path("name").asText());
    assertEquals("parse_csr", res.path("stages").get(2).path("name").asText());

    assertEquals(1, res.path("files").size());
    String csrFileId = res.path("files").get(0).path("id").asText();
    var rawFile = materials.raw(pid, csrFileId, "FILE");
    assertEquals("application/pkcs10", rawFile.get("media_type"));
  }

  @Test
  void testCaSignAndIntermediateWorkflow() throws Exception {
    var admin = login("admin", "a-long-admin-password");
    String pid = createProject(admin, "ca-chain-project");

    // 1. First create a Root CA
    Map<String, Object> rootReq = new LinkedHashMap<>();
    rootReq.put("profile", "ROOT_CA");
    rootReq.put("name", "RootCA");
    rootReq.put("subject", Map.of("CN", "Root CA", "C", "CN"));
    rootReq.put("days", 3650);

    var rootRes =
        req(
            post("/api/v1/projects/" + pid + "/certificate-workflows")
                .contentType("application/json")
                .content(json.writeValueAsBytes(rootReq)),
            admin,
            200);
    assertEquals("SUCCEEDED", rootRes.path("status").asText());
    String rootKeyRef = "key:" + rootRes.path("keys").get(0).path("id").asText();
    String rootCertRef = "file:" + rootRes.path("files").get(0).path("id").asText();

    // 2. Intermediate CA signed by Root CA
    Map<String, Object> interReq = new LinkedHashMap<>();
    interReq.put("profile", "INTERMEDIATE_CA");
    interReq.put("name", "SubCA");
    interReq.put("subject", Map.of("CN", "Sub CA", "C", "CN"));
    interReq.put("issuerCertRef", rootCertRef);
    interReq.put("issuerKeyRef", rootKeyRef);
    interReq.put("days", 1825);
    interReq.put("advanced", Map.of("pathLenConstraint", 0));

    var interRes =
        req(
            post("/api/v1/projects/" + pid + "/certificate-workflows")
                .contentType("application/json")
                .content(json.writeValueAsBytes(interReq)),
            admin,
            200);
    assertEquals("SUCCEEDED", interRes.path("status").asText(), interRes.toString());
    String subKeyRef = "key:" + interRes.path("keys").get(0).path("id").asText();
    String subCertRef = "file:" + interRes.path("files").get(1).path("id").asText(); // [csr, cert]

    // 3. CA_SIGN end-entity certificate signed by Sub CA
    Map<String, Object> signReq = new LinkedHashMap<>();
    signReq.put("profile", "CA_SIGN");
    signReq.put("name", "WebEndpoint");
    signReq.put("subject", Map.of("CN", "web.sub.local", "C", "CN"));
    signReq.put("issuerCertRef", subCertRef);
    signReq.put("issuerKeyRef", subKeyRef);
    signReq.put("days", 365);
    signReq.put("purpose", "SERVER");
    signReq.put("sanDns", List.of("web.sub.local"));

    var signRes =
        req(
            post("/api/v1/projects/" + pid + "/certificate-workflows")
                .contentType("application/json")
                .content(json.writeValueAsBytes(signReq)),
            admin,
            200);
    assertEquals("SUCCEEDED", signRes.path("status").asText(), signRes.toString());
    // Verify verify_certificate stage succeeded!
    assertTrue(signRes.path("stages").toString().contains("verify_certificate"));
  }

  @Test
  void testCaSignWithExistingCsrWithoutSubject() throws Exception {
    var admin = login("admin", "a-long-admin-password");
    String pid = createProject(admin, "ca-sign-csr-project");

    // 1. Generate Root CA
    Map<String, Object> rootReq = new LinkedHashMap<>();
    rootReq.put("profile", "ROOT_CA");
    rootReq.put("name", "RootCA");
    rootReq.put("subject", Map.of("CN", "Sign Root CA", "C", "CN"));
    var rootRes =
        req(
            post("/api/v1/projects/" + pid + "/certificate-workflows")
                .contentType("application/json")
                .content(json.writeValueAsBytes(rootReq)),
            admin,
            200);
    String rootKeyRef = "key:" + rootRes.path("keys").get(0).path("id").asText();
    String rootCertRef = "file:" + rootRes.path("files").get(0).path("id").asText();

    // 2. Generate a CSR independently
    Map<String, Object> csrReq = new LinkedHashMap<>();
    csrReq.put("profile", "CSR");
    csrReq.put("name", "ExtService");
    csrReq.put("subject", Map.of("CN", "service.internal", "C", "CN", "O", "Finance"));
    var csrRes =
        req(
            post("/api/v1/projects/" + pid + "/certificate-workflows")
                .contentType("application/json")
                .content(json.writeValueAsBytes(csrReq)),
            admin,
            200);
    String csrRef = "file:" + csrRes.path("files").get(0).path("id").asText();

    // 3. CA_SIGN using existing csrRef with NO subject specified
    Map<String, Object> signReq = new LinkedHashMap<>();
    signReq.put("profile", "CA_SIGN");
    signReq.put("name", "SignedServiceCert");
    signReq.put("csrRef", csrRef);
    signReq.put("issuerCertRef", rootCertRef);
    signReq.put("issuerKeyRef", rootKeyRef);
    signReq.put("days", 365);
    signReq.put("purpose", "SERVER");

    var signRes =
        req(
            post("/api/v1/projects/" + pid + "/certificate-workflows")
                .contentType("application/json")
                .content(json.writeValueAsBytes(signReq)),
            admin,
            200);

    assertEquals("SUCCEEDED", signRes.path("status").asText(), signRes.toString());
    assertEquals(3, signRes.path("stages").size());
    assertEquals("sign_certificate", signRes.path("stages").get(0).path("name").asText());
    assertEquals("parse_certificate", signRes.path("stages").get(1).path("name").asText());
    assertEquals("verify_certificate", signRes.path("stages").get(2).path("name").asText());
  }

  @Test
  void testTlcpProfileWorkflow() throws Exception {
    var admin = login("admin", "a-long-admin-password");
    String pid = createProject(admin, "tlcp-project");

    Map<String, Object> req = new LinkedHashMap<>();
    req.put("profile", "TLCP");
    req.put("name", "TlcpGateway");
    req.put("subject", Map.of("CN", "localhost", "C", "CN", "O", "Security"));
    req.put("sanDns", List.of("localhost"));
    req.put("days", 365);

    var res =
        req(
            post("/api/v1/projects/" + pid + "/certificate-workflows")
                .contentType("application/json")
                .content(json.writeValueAsBytes(req)),
            admin,
            200);

    assertEquals("SUCCEEDED", res.path("status").asText(), res.toString());
    // TLCP produces 3 keys: CA key, Sign key, Enc key
    assertEquals(3, res.path("keys").size());
    // TLCP produces files: CA cert, sign CSR, enc CSR, sign cert, enc cert, tlcp bundle
    assertTrue(res.path("files").size() >= 4);

    // Verify bundle file
    boolean foundBundle = false;
    for (JsonNode f : res.path("files")) {
      if ("TlcpGateway_tlcp_certs.pem".equals(f.path("name").asText())) {
        foundBundle = true;
        break;
      }
    }
    assertTrue(foundBundle, "TLCP bundle file must be present");
    assertTrue(res.path("files").toString().contains("TlcpGateway_tlcp_keys.pem"));
    String signId = res.path("keys").get(1).path("id").asText();
    String encId = res.path("keys").get(2).path("id").asText();
    assertNotEquals(signId, encId);
    assertEquals(credentials.getPassphrase(pid, signId), credentials.getPassphrase(pid, encId));
    // Verify verify_tlcp stage succeeded!
    assertTrue(res.path("stages").toString().contains("verify_tlcp"));
    Map<String, String> fileIds = new HashMap<>();
    for (var file : res.path("files")) fileIds.put(file.path("name").asText(), file.path("id").asText());
    String pairId = fileIds.get("TlcpGateway_tlcp_keys.pem");
    String pass = credentials.getPassphrase(pid, pairId);
    assertEquals(credentials.getPassphrase(pid, signId), pass);
    Path work = Files.createTempDirectory("workflow-real-tlcp");
    Process serverProcess = null, clientProcess = null;
    try {
      Files.write(work.resolve("certs.pem"), vault.read(pid, fileIds.get("TlcpGateway_tlcp_certs.pem")));
      Files.write(work.resolve("keys.pem"), vault.read(pid, pairId));
      Files.write(work.resolve("ca.pem"), vault.read(pid, fileIds.get("TlcpGateway_tlcp_ca_cert.pem")));
      int port;
      try (var socket = new java.net.ServerSocket(0)) { port = socket.getLocalPort(); }
      serverProcess = new ProcessBuilder(runner.toString()).directory(work.toFile())
          .redirectOutput(work.resolve("server.log").toFile()).redirectErrorStream(true).start();
      try (var output = serverProcess.getOutputStream()) {
        output.write(frame(List.of("tlcp_server", "-port", Integer.toString(port), "-cert", "certs.pem",
            "-key", "keys.pem", "-pass", pass, "-cipher_suite", "TLS_ECC_SM4_GCM_SM3", "-www")));
      }
      // A bounded readiness probe may cause one harmless failed accept before the actual client.
      long readyUntil = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
      boolean listening = false;
      while (System.nanoTime() < readyUntil && serverProcess.isAlive()) {
        try (var socket = new java.net.Socket("127.0.0.1", port)) { listening = true; break; }
        catch (IOException e) { Thread.sleep(30); }
      }
      assertTrue(listening, "TLCP server did not start: " + Files.readString(work.resolve("server.log")));
      clientProcess = new ProcessBuilder(runner.toString()).directory(work.toFile())
          .redirectOutput(work.resolve("client.log").toFile()).redirectErrorStream(true).start();
      try (var output = clientProcess.getOutputStream()) {
        output.write(frame(List.of("tlcp_client", "-host", "127.0.0.1", "-port", Integer.toString(port),
            "-cacert", "ca.pem", "-cipher_suite", "TLS_ECC_SM4_GCM_SM3", "-server_name", "localhost", "-get", "/")));
      }
      assertTrue(clientProcess.waitFor(12, TimeUnit.SECONDS), "TLCP client exceeded handshake budget");
      String transcript = Files.readString(work.resolve("client.log"));
      assertEquals(0, clientProcess.exitValue(), transcript);
      assertTrue(transcript.contains("200 OK"), "TLCP encrypted application exchange missing: " + transcript);
    } finally {
      for (Process process : new Process[]{clientProcess, serverProcess}) if (process != null && process.isAlive()) {
        process.destroy();
        if (!process.waitFor(2, TimeUnit.SECONDS)) { process.destroyForcibly(); process.waitFor(2, TimeUnit.SECONDS); }
      }
      try (var paths = Files.list(work)) { for (Path path : paths.toList()) Files.deleteIfExists(path); }
      Files.deleteIfExists(work);
    }
  }

  @Test
  void testSecurityAndValidationChecks() throws Exception {
    var admin = login("admin", "a-long-admin-password");
    String pid = createProject(admin, "validation-project");

    // 1. Missing CSRF Token -> 403
    mvc.perform(
            post("/api/v1/projects/" + pid + "/certificate-workflows")
                .cookie(admin.cookie)
                .contentType("application/json")
                .content(json.writeValueAsBytes(Map.of("profile", "ROOT_CA", "name", "Test", "subject", Map.of("CN", "Test")))))
        .andExpect(status().isForbidden());

    // 2. Missing profile -> 400
    req(
        post("/api/v1/projects/" + pid + "/certificate-workflows")
            .contentType("application/json")
            .content(json.writeValueAsBytes(Map.of("name", "Test", "subject", Map.of("CN", "Test")))),
        admin,
        400);

    // 3. Unknown profile -> 400
    req(
        post("/api/v1/projects/" + pid + "/certificate-workflows")
            .contentType("application/json")
            .content(json.writeValueAsBytes(Map.of("profile", "INVALID_PROFILE", "name", "Test", "subject", Map.of("CN", "Test")))),
        admin,
        400);

    // 4. Missing CN -> 400
    req(
        post("/api/v1/projects/" + pid + "/certificate-workflows")
            .contentType("application/json")
            .content(json.writeValueAsBytes(Map.of("profile", "ROOT_CA", "name", "Test", "subject", Map.of("O", "Test")))),
        admin,
        400);

    // 5. Invalid SAN DNS -> 400
    req(
        post("/api/v1/projects/" + pid + "/certificate-workflows")
            .contentType("application/json")
            .content(json.writeValueAsBytes(Map.of(
                "profile", "SELF_SIGNED",
                "name", "Test",
                "subject", Map.of("CN", "Test"),
                "sanDns", List.of("invalid..domain")))),
        admin,
        400);

    // 6. Invalid days -> 400
    req(
        post("/api/v1/projects/" + pid + "/certificate-workflows")
            .contentType("application/json")
            .content(json.writeValueAsBytes(Map.of(
                "profile", "SELF_SIGNED",
                "name", "Test",
                "subject", Map.of("CN", "Test"),
                "days", 0))),
        admin,
        400);

    // 7. Missing issuer for CA_SIGN -> 400
    req(
        post("/api/v1/projects/" + pid + "/certificate-workflows")
            .contentType("application/json")
            .content(json.writeValueAsBytes(Map.of(
                "profile", "CA_SIGN",
                "name", "Test",
                "subject", Map.of("CN", "Test")))),
        admin,
        400);
  }
  @Test
  void rejectsMalformedIpDnsAndSm2IdBoundaries() throws Exception {
    var admin = login("admin", "a-long-admin-password");
    String pid = createProject(admin, "strict-boundaries");
    for (var bad : List.of(Map.of("sanIps", List.of(":::")), Map.of("sanIps", List.of("1:2")),
        Map.of("sanDns", List.of("-bad.example")), Map.of("sanDns", List.of("bad-.example")),
        Map.of("advanced", Map.of("sm2Id", "a".repeat(129))), Map.of("advanced", Map.of("sm2Id", "中文")))) {
      Map<String,Object> body = new LinkedHashMap<>(Map.of("profile", "SELF_SIGNED", "name", "Invalid",
          "subject", Map.of("CN", "localhost")));
      body.putAll(bad);
      req(post("/api/v1/projects/" + pid + "/certificate-workflows").contentType("application/json")
          .content(json.writeValueAsBytes(body)), admin, 400);
    }
    assertTrue(CertificateWorkflowService.validIpv6("2001:db8::1"));
  }

  @Test
  void signingPurposeUsesActualSignatureVerification() throws Exception {
    var admin = login("admin", "a-long-admin-password");
    String pid = createProject(admin, "signing-purpose");
    var root = req(post("/api/v1/projects/" + pid + "/certificate-workflows").contentType("application/json")
        .content(json.writeValueAsBytes(Map.of("profile", "ROOT_CA", "name", "SigningCA", "subject", Map.of("CN", "Signing CA")))), admin, 200);
    var leaf = req(post("/api/v1/projects/" + pid + "/certificate-workflows").contentType("application/json")
        .content(json.writeValueAsBytes(Map.of("profile", "CA_SIGN", "name", "CodeSigner", "subject", Map.of("CN", "Signer"),
            "issuerKeyRef", "key:" + root.path("keys").get(0).path("id").asText(),
            "issuerCertRef", "file:" + root.path("files").get(0).path("id").asText(), "purpose", "SIGNING"))), admin, 200);
    assertEquals("SUCCEEDED", leaf.path("status").asText(), leaf.toString());
    for (var stage : leaf.path("stages")) assertNotEquals("verify_certificate", stage.path("name").asText());
  }

  @Test
  void overallDeadlineCancelsOwnedJobAndPreservesPartialKeys() throws Exception {
    Jobs fakeJobs = org.mockito.Mockito.mock(Jobs.class);
    Store fakeStore = org.mockito.Mockito.mock(Store.class);
    Auth fakeAuth = org.mockito.Mockito.mock(Auth.class);
    Materials fakeMaterials = org.mockito.Mockito.mock(Materials.class);
    KeyGenerationService generator = org.mockito.Mockito.mock(KeyGenerationService.class);
    CredentialService creds = org.mockito.Mockito.mock(CredentialService.class);
    var http = new org.springframework.mock.web.MockHttpServletRequest();
    org.mockito.Mockito.when(fakeStore.id()).thenReturn("workflow-budget");
    org.mockito.Mockito.when(fakeAuth.uid(http)).thenReturn("user");
    String keyId = UUID.randomUUID().toString();
    org.mockito.Mockito.when(generator.generateWithTimeout(org.mockito.Mockito.anyString(), org.mockito.Mockito.anyString(),
        org.mockito.Mockito.anyMap(), org.mockito.Mockito.anyInt())).thenReturn(Map.of("reference", "key:" + keyId,
            "key", Map.of("id", keyId)));
    org.mockito.Mockito.when(creds.getPassphrase("project", keyId)).thenReturn("not-in-response");
    org.mockito.Mockito.when(fakeJobs.submit(org.mockito.Mockito.eq("project"), org.mockito.Mockito.anyMap(), org.mockito.Mockito.eq(http)))
        .thenReturn(Map.of("id", "owned-job"));
    org.mockito.Mockito.when(fakeJobs.dto("project", "owned-job")).thenReturn(Map.of("status", "RUNNING"));
    var service = new CertificateWorkflowService(fakeJobs, fakeMaterials, fakeStore, vault, generator, creds, fakeAuth);
    org.springframework.test.util.ReflectionTestUtils.setField(service, "workflowTimeoutMillis", 1100L);
    var input = json.readValue("{\"profile\":\"ROOT_CA\",\"name\":\"Budget\",\"subject\":{\"CN\":\"Budget\"}}",
        CertificateWorkflowService.CertificateWorkflowRequest.class);
    var result = service.execute("project", input, http);
    assertEquals("FAILED", result.status());
    assertEquals(keyId, result.keys().getFirst().get("id"));
    assertFalse(result.toString().contains("not-in-response"));
    org.mockito.Mockito.verify(fakeJobs).cancel("project", "owned-job", http);
    org.mockito.Mockito.verify(fakeMaterials, org.mockito.Mockito.never()).delete(org.mockito.Mockito.anyString(), org.mockito.Mockito.anyString());
    var captor = org.mockito.ArgumentCaptor.forClass(Map.class);
    org.mockito.Mockito.verify(fakeJobs).submit(org.mockito.Mockito.eq("project"), captor.capture(), org.mockito.Mockito.eq(http));
    assertTrue(((Number)captor.getValue().get("timeoutSeconds")).intValue() <= 1);
  }

  private JsonNode workflow(Session session, String pid, Map<String,Object> body, int status) throws Exception {
    return req(post("/api/v1/projects/" + pid + "/certificate-workflows").contentType("application/json")
        .content(json.writeValueAsBytes(body)), session, status);
  }

  private String opensslInspect(String command, byte[] pem) throws Exception {
    Process process = new ProcessBuilder("openssl", command, "-text", "-noout").redirectErrorStream(true).start();
    try (var stdin = process.getOutputStream()) { stdin.write(pem); }
    assertTrue(process.waitFor(5, TimeUnit.SECONDS));
    String text = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
    assertEquals(0, process.exitValue(), text);
    return text;
  }

  @Test
  void csrAndIssuedCertificateContainRealDnsAndIpExtensions() throws Exception {
    var admin = login("admin", "a-long-admin-password");
    String pid = createProject(admin, "san-der");
    var root = workflow(admin, pid, Map.of("profile", "ROOT_CA", "name", "SanCA", "subject", Map.of("CN", "SAN CA")), 200);
    assertEquals("SUCCEEDED", root.path("status").asText(), root.toString());
    String issuer = "file:" + root.path("files").get(0).path("id").asText();
    String key = "key:" + root.path("keys").get(0).path("id").asText();
    var csr = workflow(admin, pid, Map.of("profile", "CSR", "name", "SanRequest", "subject", Map.of("CN", "san.example"),
        "sanDns", List.of("san.example"), "sanIps", List.of("192.168.1.50", "2001:db8::1")), 200);
    assertEquals("SUCCEEDED", csr.path("status").asText(), csr.toString());
    String csrId = csr.path("files").get(0).path("id").asText();
    String requested = opensslInspect("req", vault.read(pid, csrId));
    assertTrue(requested.contains("DNS:san.example"), requested);
    assertTrue(requested.contains("IP Address:192.168.1.50"), requested);
    var signed = workflow(admin, pid, Map.of("profile", "CA_SIGN", "name", "SanIssued", "csrRef", "file:" + csrId,
        "issuerCertRef", issuer, "issuerKeyRef", key), 200);
    assertEquals("SUCCEEDED", signed.path("status").asText(), signed.toString());
    String issued = opensslInspect("x509", vault.read(pid, signed.path("files").get(0).path("id").asText()));
    assertTrue(issued.contains("DNS:san.example"), issued);
    assertTrue(issued.contains("IP Address:192.168.1.50"), issued);
    assertTrue(issued.toLowerCase().contains("2001:db8:0:0:0:0:0:1"), issued);
    var override = workflow(admin, pid, Map.of("profile", "CA_SIGN", "name", "SanOverride", "csrRef", "file:" + csrId,
        "issuerCertRef", issuer, "issuerKeyRef", key, "sanDns", List.of("override.example"), "sanIps", List.of("127.0.0.1")), 200);
    assertEquals("SUCCEEDED", override.path("status").asText(), override.toString());
    String changed = opensslInspect("x509", vault.read(pid, override.path("files").get(0).path("id").asText()));
    assertTrue(changed.contains("DNS:override.example"));
    assertTrue(changed.contains("IP Address:127.0.0.1"));
  }

  @Test
  void issuerConstraintsAndExpirationAreEnforced() throws Exception {
    var admin = login("admin", "a-long-admin-password");
    String pid = createProject(admin, "issuer-negative");
    var issuer = workflow(admin, pid, Map.of("profile", "ROOT_CA", "name", "ShortCA", "subject", Map.of("CN", "Short CA"),
        "days", 2), 200);
    String certRef = "file:" + issuer.path("files").get(0).path("id").asText();
    String keyRef = "key:" + issuer.path("keys").get(0).path("id").asText();
    workflow(admin, pid, Map.of("profile", "CA_SIGN", "name", "TooLong", "subject", Map.of("CN", "Too Long"),
        "issuerCertRef", certRef, "issuerKeyRef", keyRef, "days", 3), 400);
    var leaf = workflow(admin, pid, Map.of("profile", "SELF_SIGNED", "name", "NotCA", "subject", Map.of("CN", "Not CA")), 200);
    workflow(admin, pid, Map.of("profile", "CA_SIGN", "name", "InvalidIssuer", "subject", Map.of("CN", "Invalid"),
        "issuerCertRef", "file:" + leaf.path("files").get(0).path("id").asText(),
        "issuerKeyRef", "key:" + leaf.path("keys").get(0).path("id").asText()), 400);
  }

  @Test
  void testQuickIssueProfileGeneratesKeyCsrSignAndChain() throws Exception {
    var admin = login("admin", "a-long-admin-password");
    String pid = createProject(admin, "quick-issue-project");

    // 1. Create a Root CA first
    Map<String, Object> rootReq = new LinkedHashMap<>();
    rootReq.put("profile", "ROOT_CA");
    rootReq.put("name", "CorpRootCA");
    rootReq.put("subject", Map.of("CN", "Corp Root CA", "C", "CN"));
    rootReq.put("days", 3650);

    var rootRes =
        req(
            post("/api/v1/projects/" + pid + "/certificate-workflows")
                .contentType("application/json")
                .content(json.writeValueAsBytes(rootReq)),
            admin,
            200);
    assertEquals("SUCCEEDED", rootRes.path("status").asText());
    String caCertRef = "file:" + rootRes.path("files").get(0).path("id").asText();
    String caKeyRef = "key:" + rootRes.path("keys").get(0).path("id").asText();

    // 2. Issue end-entity certificate via QUICK_ISSUE without providing csrRef or keyRef
    Map<String, Object> quickReq = new LinkedHashMap<>();
    quickReq.put("profile", "QUICK_ISSUE");
    quickReq.put("name", "WebServerCert");
    quickReq.put("subject", Map.of("CN", "www.example.com", "C", "CN"));
    quickReq.put("sanDns", List.of("www.example.com", "example.com"));
    quickReq.put("days", 365);
    quickReq.put("purpose", "SERVER");
    quickReq.put("issuerCertRef", caCertRef);
    quickReq.put("issuerKeyRef", caKeyRef);

    var quickRes =
        req(
            post("/api/v1/projects/" + pid + "/certificate-workflows")
                .contentType("application/json")
                .content(json.writeValueAsBytes(quickReq)),
            admin,
            200);

    assertEquals("SUCCEEDED", quickRes.path("status").asText(), quickRes.toString());
    // Stages: generate_key -> generate_csr -> sign_certificate -> parse_certificate -> build_chain
    assertTrue(quickRes.path("stages").size() >= 4);

    // Keys contains the new generated private key (sensitive managed key)
    assertEquals(1, quickRes.path("keys").size());
    String newKeyId = quickRes.path("keys").get(0).path("id").asText();
    assertTrue(credentials.hasPassphrase(newKeyId));

    // Files contains end-entity certificate and certificate chain
    assertTrue(quickRes.path("files").size() >= 2);
    boolean hasCert = false, hasChain = false;
    for (JsonNode f : quickRes.path("files")) {
      String fname = f.path("name").asText();
      if (fname.equals("WebServerCert_cert.pem")) hasCert = true;
      if (fname.equals("WebServerCert_chain.pem")) hasChain = true;
    }
    assertTrue(hasCert, "Output files must contain WebServerCert_cert.pem");
    assertTrue(hasChain, "Output files must contain WebServerCert_chain.pem");
  }

  @Test
  void testCsrMaterialValidationRejectsCertificatePassedAsCsr() throws Exception {
    var admin = login("admin", "a-long-admin-password");
    String pid = createProject(admin, "csr-val-project");

    // Create a certificate
    Map<String, Object> rootReq = new LinkedHashMap<>();
    rootReq.put("profile", "ROOT_CA");
    rootReq.put("name", "SomeCert");
    rootReq.put("subject", Map.of("CN", "Some Cert", "C", "CN"));
    var certRes =
        req(
            post("/api/v1/projects/" + pid + "/certificate-workflows")
                .contentType("application/json")
                .content(json.writeValueAsBytes(rootReq)),
            admin,
            200);
    String fakeCsrFileRef = "file:" + certRes.path("files").get(0).path("id").asText();
    String keyRef = "key:" + certRes.path("keys").get(0).path("id").asText();

    // Use certificate file as csrRef in CA_SIGN -> Must fail prevalidation with clear message
    Map<String, Object> signReq = new LinkedHashMap<>();
    signReq.put("profile", "CA_SIGN");
    signReq.put("name", "MisconfiguredSign");
    signReq.put("issuerCertRef", fakeCsrFileRef);
    signReq.put("issuerKeyRef", keyRef);
    signReq.put("csrRef", fakeCsrFileRef);

    var res =
        req(
            post("/api/v1/projects/" + pid + "/certificate-workflows")
                .contentType("application/json")
                .content(json.writeValueAsBytes(signReq)),
            admin,
            400);

    assertTrue(res.path("message").asText().contains("CSR") || res.path("message").asText().contains("CERTIFICATE REQUEST"),
        "Must reject non-CSR file passed as csrRef: " + res.path("message").asText());
  }

  @Test
  void testIssuerValidityPrecheckRejectsDaysExceedingCaExpiration() throws Exception {
    var admin = login("admin", "a-long-admin-password");
    String pid = createProject(admin, "ca-exp-project");

    // 1. Create a CA with only 10 days validity
    Map<String, Object> caReq = new LinkedHashMap<>();
    caReq.put("profile", "ROOT_CA");
    caReq.put("name", "ShortLivedCA");
    caReq.put("subject", Map.of("CN", "Short Lived CA", "C", "CN"));
    caReq.put("days", 10);

    var caRes =
        req(
            post("/api/v1/projects/" + pid + "/certificate-workflows")
                .contentType("application/json")
                .content(json.writeValueAsBytes(caReq)),
            admin,
            200);
    String caCertRef = "file:" + caRes.path("files").get(0).path("id").asText();
    String caKeyRef = "key:" + caRes.path("keys").get(0).path("id").asText();

    // 2. Request 365 days certificate from this 10-day CA -> Must fail precheck
    Map<String, Object> req = new LinkedHashMap<>();
    req.put("profile", "QUICK_ISSUE");
    req.put("name", "ShouldFailExpiry");
    req.put("subject", Map.of("CN", "test.com"));
    req.put("issuerCertRef", caCertRef);
    req.put("issuerKeyRef", caKeyRef);
    req.put("days", 365);

    var res =
        req(
            post("/api/v1/projects/" + pid + "/certificate-workflows")
                .contentType("application/json")
                .content(json.writeValueAsBytes(req)),
            admin,
            400);

    assertTrue(res.path("message").asText().contains("exceeds issuer expiration") || res.path("message").asText().contains("有效期"),
        "Must reject requested days exceeding issuer expiration: " + res.path("message").asText());
  }
}
