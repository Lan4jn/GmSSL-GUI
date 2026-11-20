package org.gmssl.gui.platform;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;

import com.fasterxml.jackson.databind.*;
import jakarta.servlet.http.Cookie;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.*;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.jcajce.*;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.*;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

@SpringBootTest
@AutoConfigureMockMvc
class StandardClientCertificateTest {
  static final String PID = UUID.randomUUID().toString(), OTHER = UUID.randomUUID().toString();
  static final String PATH = "/projects/" + PID + "/standard-client-certificates";
  static final String SERVICE = "/integration/v1" + PATH, ADMIN = "/api/v1" + PATH;
  static final String TOKEN =
      Base64.getUrlEncoder().withoutPadding().encodeToString(new SecureRandom().generateSeed(32));
  static X509Certificate ca;
  static KeyPair device;
  @Autowired MockMvc mvc;
  @Autowired Store store;
  @Autowired ObjectMapper json;

  static KeyPair key(int bits) throws Exception {
    var g = KeyPairGenerator.getInstance("RSA");
    g.initialize(bits);
    return g.generateKeyPair();
  }

  static String csr(KeyPair key, PrivateKey signer) throws Exception {
    var b = new JcaPKCS10CertificationRequestBuilder(new X500Name("CN=device"), key.getPublic());
    var ext = new ExtensionsGenerator();
    ext.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
    ext.addExtension(
        Extension.subjectAlternativeName,
        false,
        new GeneralNames(new GeneralName(GeneralName.dNSName, "example.test")));
    b.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, ext.generate());
    return "-----BEGIN CERTIFICATE REQUEST-----\n"
        + Base64.getMimeEncoder()
            .encodeToString(
                b.build(new JcaContentSignerBuilder("SHA256withRSA").build(signer)).getEncoded())
        + "\n-----END CERTIFICATE REQUEST-----\n";
  }

  @DynamicPropertySource
  static void props(DynamicPropertyRegistry p) throws Exception {
    Path dir = Files.createTempDirectory("standard-ca-test");
    device = key(3072);
    var pair = key(3072);
    var name = new X500Name("CN=Test Issuer");
    var b =
        new JcaX509v3CertificateBuilder(
            name,
            BigInteger.ONE,
            new Date(System.currentTimeMillis() - 10000),
            new Date(System.currentTimeMillis() + 86400000),
            name,
            pair.getPublic());
    b.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
    b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign));
    ca =
        new JcaX509CertificateConverter()
            .getCertificate(
                b.build(new JcaContentSignerBuilder("SHA256withRSA").build(pair.getPrivate())));
    var ks = KeyStore.getInstance("PKCS12");
    char[] pass = "fixture".toCharArray();
    ks.load(null, pass);
    ks.setKeyEntry("issuer", pair.getPrivate(), pass, new X509Certificate[] {ca});
    try (var os = Files.newOutputStream(dir.resolve("ca.p12"))) {
      ks.store(os, pass);
    }
    p.add(
        "spring.datasource.url",
        () -> "jdbc:h2:mem:standard;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE");
    p.add("GMSSL_VAULT_DIR", () -> dir.resolve("vault").toString());
    p.add("GMSSL_VAULT_MASTER_KEY", () -> Base64.getEncoder().encodeToString(new byte[32]));
    p.add("GMSSL_ENGINE_TOKEN", () -> "unused");
    p.add("GMSSL_BOOTSTRAP_USERNAME", () -> "admin");
    p.add("GMSSL_BOOTSTRAP_PASSWORD", () -> "admin-pass");
    p.add("GMSSL_STANDARD_CA_PKCS12", () -> dir.resolve("ca.p12").toString());
    p.add("GMSSL_STANDARD_CA_ALIAS", () -> "issuer");
    p.add("GMSSL_STANDARD_CA_PASSWORD", () -> "fixture");
    p.add("GMSSL_STANDARD_INTEGRATION_ENABLED", () -> true);
    p.add("GMSSL_STANDARD_INTEGRATION_PROJECT_ID", () -> PID);
    p.add("GMSSL_STANDARD_INTEGRATION_TOKEN", () -> TOKEN);
  }

  @BeforeEach
  void projects() {
    for (var id : List.of(PID, OTHER))
      if (store.rows("select id from projects where id=?", id).isEmpty())
        store.db.update("insert into projects values(?,?,?,?)", id, "test", "", store.now());
  }

  MockHttpServletRequestBuilder service(MockHttpServletRequestBuilder b) {
    return b.secure(true)
        .requestAttr("jakarta.servlet.request.ssl_session_id", "test-native-session")
        .header("Authorization", "Bearer " + TOKEN);
  }

  JsonNode call(MockHttpServletRequestBuilder b, int status) throws Exception {
    var r = mvc.perform(b).andReturn().getResponse();
    assertEquals(status, r.getStatus(), r.getContentAsString());
    return json.readTree(r.getContentAsByteArray());
  }

  MockHttpServletRequestBuilder issue(String id, String pem, String label) throws Exception {
    return service(post(SERVICE))
        .contentType("application/json")
        .content(
            json.writeValueAsBytes(Map.of("requestId", id, "csrPem", pem, "deviceLabel", label)));
  }

  @Test
  void enforcesSeparateAccessBoundaries() throws Exception {
    call(
        get(SERVICE)
            .header("Authorization", "Bearer " + TOKEN)
            .header("X-Forwarded-Proto", "https"),
        403);
    call(
        get(SERVICE).secure(true).requestAttr("jakarta.servlet.request.ssl_session_id", "test"),
        401);
    call(service(get(SERVICE.replace(PID, OTHER))), 403);
    call(service(get(ADMIN)), 401);
    var login =
        mvc.perform(
                post("/api/v1/auth/login")
                    .contentType("application/json")
                    .content("{\"username\":\"admin\",\"password\":\"admin-pass\"}"))
            .andReturn()
            .getResponse();
    var cookie = login.getCookie("GMSSL_SESSION");
    call(get(ADMIN).cookie(cookie), 200);
    call(post(ADMIN).cookie(cookie).contentType("application/json").content("{}"), 403);
    call(
        get(SERVICE)
            .secure(true)
            .requestAttr("jakarta.servlet.request.ssl_session_id", "test")
            .cookie(cookie),
        401);
  }

  @Test
  void rejectsInvalidSignatureSizeAndCallerCaSettings() throws Exception {
    var weak = key(2048);
    call(issue("wrong-sig", csr(device, weak.getPrivate()), "test"), 400);
    call(issue("wrong-key", csr(weak, weak.getPrivate()), "test"), 400);
    call(
        issue("ca-knob", csr(device, device.getPrivate()), "test")
            .content(
                json.writeValueAsBytes(
                    Map.of(
                        "caAlias",
                        "other",
                        "requestId",
                        "ca-knob",
                        "deviceLabel",
                        "test",
                        "csrPem",
                        csr(device, device.getPrivate())))),
        400);
  }

  @Test
  void rejectsInvalidCaAndMissingConfiguration(@org.junit.jupiter.api.io.TempDir Path dir)
      throws Exception {
    var pair = key(3072);
    var name = new X500Name("CN=Broken CA");
    for (String defect : List.of("not-ca", "no-keycertsign", "expired", "mismatched-private")) {
      long now = System.currentTimeMillis();
      var b =
          new JcaX509v3CertificateBuilder(
              name,
              BigInteger.TWO,
              new Date(now - 86400000L),
              new Date(now + (defect.equals("expired") ? -10000 : 86400000L)),
              name,
              pair.getPublic());
      b.addExtension(
          Extension.basicConstraints, true, new BasicConstraints(!defect.equals("not-ca")));
      b.addExtension(
          Extension.keyUsage,
          true,
          new KeyUsage(
              defect.equals("no-keycertsign") ? KeyUsage.digitalSignature : KeyUsage.keyCertSign));
      var cert =
          new JcaX509CertificateConverter()
              .getCertificate(
                  b.build(new JcaContentSignerBuilder("SHA256withRSA").build(pair.getPrivate())));
      var ks = KeyStore.getInstance("PKCS12");
      var pass = "fixture".toCharArray();
      ks.load(null, pass);
      ks.setKeyEntry(
          "bad",
          defect.equals("mismatched-private") ? device.getPrivate() : pair.getPrivate(),
          pass,
          new X509Certificate[] {cert});
      var path = dir.resolve(defect + ".p12");
      try (var out = Files.newOutputStream(path)) {
        ks.store(out, pass);
      }
      assertThrows(
          IllegalStateException.class,
          () -> new StandardClientIssuer(path.toString(), "fixture", "bad"),
          defect);
    }
    var inactive = new StandardClientIssuer("", "", "");
    var valid = inactive.verify(csr(device, device.getPrivate()));
    assertEquals(503, assertThrows(ApiError.class, () -> inactive.sign(valid, "label")).status);
  }

  @Test
  void serviceDisabledByDefaultAndWeakConfigRejected() {
    var disabled =
        new IntegrationStandardClientController(null, json, store, false, "", "", "", "", "", "");
    assertEquals(
        404,
        assertThrows(
                ApiError.class,
                () ->
                    disabled.actor(new org.springframework.mock.web.MockHttpServletRequest(), PID))
            .status);
    assertThrows(
        IllegalStateException.class,
        () ->
            new IntegrationStandardClientController(
                null, json, store, true, PID, "A".repeat(43), "", "", "", ""));
    assertThrows(
        IllegalStateException.class,
        () ->
            new IntegrationStandardClientController(
                null, json, store, true, PID, TOKEN, TOKEN, "", "", ""));
  }

  @Test
  void evenProjectOwnerNeedsAdministratorSession() throws Exception {
    String uid = store.id(), token = UUID.randomUUID().toString();
    store.db.update(
        "insert into app_users values(?,?,?,?,?,?)",
        uid,
        "ordinary",
        "unused",
        "USER",
        true,
        store.now());
    store.db.update("insert into memberships values(?,?,?)", PID, uid, "OWNER");
    store.db.update(
        "insert into sessions values(?,?,?,?)",
        Auth.hash(token),
        uid,
        "csrf",
        System.currentTimeMillis() + 60000L);
    var cookie = new Cookie("GMSSL_SESSION", token);
    call(get(ADMIN).cookie(cookie), 403);
    call(
        post(ADMIN)
            .cookie(cookie)
            .header("X-CSRF-Token", "csrf")
            .contentType("application/json")
            .content("{}"),
        403);
  }

  @Test
  void auditFailureRollsBackIssuance() throws Exception {
    // Inject a failure in the existing H2 audit sink. No orphaned ledger record may be visible.
    String rid = UUID.randomUUID().toString();
    store.db.execute(
        "alter table audit_events add constraint fixture_block_issue check (action <>"
            + " 'STANDARD_CERT_ISSUE') nocheck");
    try {
      call(issue(rid, csr(device, device.getPrivate()), "audit"), 500);
      assertEquals(
          0,
          store.db.queryForObject(
              "select count(*) from standard_client_certs where project_id=? and request_id=?",
              Integer.class,
              PID,
              rid));
    } finally {
      store.db.execute("alter table audit_events drop constraint fixture_block_issue");
    }
  }

  @Test
  void listAcceptsEmptyFilterAndValidatesPageBounds() throws Exception {
    assertTrue(
        call(
                service(
                    get(SERVICE).param("fingerprint", "").param("page", "0").param("size", "50")),
                200)
            .get("items")
            .isArray());
    call(service(get(SERVICE).param("size", "101")), 400);
    call(service(get(SERVICE).param("page", "-1")), 400);
    call(service(get(SERVICE).param("fingerprint", "partial")), 400);
    call(service(get(SERVICE).param("caAlias", "other")), 400);
  }

  @Test
  void neverTreatProxyAssertedSecureSchemeAsNativeTls() throws Exception {
    // Simulates a container with forwarded-headers enabled, not a native TLS connector.
    call(
        get(SERVICE)
            .secure(true)
            .header("X-Forwarded-Proto", "https")
            .header("Authorization", "Bearer " + TOKEN),
        403);
  }

  @Test
  void concurrentReplayIssuesOnlyOneCertificateAndAudits() throws Exception {
    String pem = csr(device, device.getPrivate()), id = UUID.randomUUID().toString();
    var gate = new CountDownLatch(1);
    JsonNode record;
    try (var pool = Executors.newFixedThreadPool(4)) {
      List<Future<JsonNode>> results = new ArrayList<>();
      for (int i = 0; i < 4; i++)
        results.add(
            pool.submit(
                () -> {
                  gate.await();
                  return call(issue(id, pem, "device"), 200);
                }));
      gate.countDown();
      record = results.getFirst().get(30, TimeUnit.SECONDS);
      for (var result : results) assertEquals(record, result.get());
    }
    assertEquals(PID, record.get("projectId").asText());
    assertEquals(id, record.get("requestId").asText());
    assertEquals("VALID", record.get("status").asText());
    var cf = CertificateFactory.getInstance("X.509");
    var cert =
        (X509Certificate)
            cf.generateCertificate(
                new ByteArrayInputStream(
                    record.get("certificatePem").asText().getBytes(StandardCharsets.US_ASCII)));
    cert.verify(ca.getPublicKey());
    assertEquals(device.getPublic(), cert.getPublicKey());
    assertEquals(-1, cert.getBasicConstraints());
    assertNull(cert.getSubjectAlternativeNames());
    assertEquals(List.of("1.3.6.1.5.5.7.3.2"), cert.getExtendedKeyUsage());
    assertTrue(cert.getKeyUsage()[0]);
    for (int i = 1; i < cert.getKeyUsage().length; i++) assertFalse(cert.getKeyUsage()[i]);
    assertEquals("SHA256withRSA", cert.getSigAlgName());
    assertTrue(!cert.getNotAfter().after(ca.getNotAfter()));
    assertEquals(cert.getNotAfter().getTime(), record.get("expiresAt").asLong());
    var fp =
        HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(cert.getEncoded()));
    assertEquals(fp, record.get("fingerprint").asText());
    assertEquals(cert.getSerialNumber().toString(16), record.get("serial").asText());
    assertEquals(
        ca,
        cf.generateCertificate(
            new ByteArrayInputStream(
                record.get("chainPem").asText().getBytes(StandardCharsets.US_ASCII))));
    var page = call(service(get(SERVICE).param("fingerprint", fp)), 200);
    assertEquals(1, page.get("total").asInt());
    assertEquals(record, page.get("items").get(0));
    call(service(get(SERVICE).param("fingerprint", fp.toUpperCase(Locale.ROOT))), 400);
    var detail = SERVICE + "/" + record.get("id").asText();
    assertEquals(record, call(service(get(detail)), 200));
    call(issue(id, pem, "changed"), 409);
    var different = key(3072);
    call(issue(id, csr(different, different.getPrivate()), "device"), 409);
    var login =
        mvc.perform(
                post("/api/v1/auth/login")
                    .contentType("application/json")
                    .content("{\"username\":\"admin\",\"password\":\"admin-pass\"}"))
            .andReturn()
            .getResponse();
    Cookie cookie = login.getCookie("GMSSL_SESSION");
    String adminDetail = detail.replace("/integration/v1", "/api/v1");
    assertEquals(record, call(get(adminDetail).cookie(cookie), 200));
    call(get(adminDetail.replace(PID, OTHER)).cookie(cookie), 404);
    store.db.update(
        "update standard_client_certs set expires_at=? where id=?",
        1000L,
        record.get("id").asText());
    assertEquals("EXPIRED", call(service(get(detail)), 200).get("status").asText());
    assertEquals("REVOKED", call(service(post(detail + "/revoke")), 200).get("status").asText());
    assertEquals("REVOKED", call(issue(id, pem, "device"), 200).get("status").asText());
    assertEquals(
        1,
        store.db.queryForObject(
            "select count(*) from audit_events where resource_id=? and action=? and outcome=?",
            Integer.class,
            record.get("id").asText(),
            "STANDARD_CERT_ISSUE",
            "SUCCESS"));
    assertEquals(
        2,
        store.db.queryForObject(
            "select count(*) from audit_events where resource_id=? and outcome=?",
            Integer.class,
            record.get("id").asText(),
            "CONFLICT"));
  }
}
