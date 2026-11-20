package org.gmssl.gui.platform;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.sql.*;
import java.time.Duration;
import java.util.*;
import javax.sql.DataSource;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.web.servlet.context.ServletWebServerApplicationContext;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;

/** Test-only same-package entry point; all business Beans come from the frozen production JAR. */
public class Dm8ProductionVerification {
  @Configuration(proxyBeanMethods = false)
  @EnableAutoConfiguration
  @Import({Store.class, Vault.class, Materials.class, CredentialService.class, Auth.class,
      AccountController.class, ErrorAdvice.class})
  static class Application {
    @Bean DataSource dataSource() {
      DriverManagerDataSource ds = new DriverManagerDataSource();
      ds.setDriverClassName("dm.jdbc.driver.DmDriver");
      ds.setUrl(env("DM_TEST_JDBC_URL"));
      ds.setUsername(env("DM_TEST_USERNAME"));
      ds.setPassword(env("DM_TEST_PASSWORD"));
      return ds;
    }
  }

  static String stage = "safety";
  static int checks;
  static void require(boolean condition, String label) {
    if (!condition) throw new AssertionError(label);
    checks++;
    System.out.println("DMPROD PASS " + label);
  }
  static String env(String name) { return Objects.requireNonNull(System.getenv(name)); }
  static String random() {
    byte[] bytes = new byte[24]; new SecureRandom().nextBytes(bytes);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }
  static void safety() throws Exception {
    String schema = env("DM_TEST_SCHEMA"), user = env("DM_TEST_USERNAME");
    if (!schema.matches("GMSSL_TEST(?:_[A-Z0-9_]+)?") || !user.toUpperCase(Locale.ROOT).matches("GMSSL_TEST(?:_[A-Z0-9_]+)?")
        || !env("DM_TEST_JDBC_URL").startsWith("jdbc:dm://")) throw new IllegalArgumentException("test-target-only");
    Class.forName("dm.jdbc.driver.DmDriver");
    DriverManager.setLoginTimeout(10);
    try (Connection c = DriverManager.getConnection(env("DM_TEST_JDBC_URL"), user, env("DM_TEST_PASSWORD"))) {
      if (!schema.equals(c.getSchema()) || !user.equalsIgnoreCase(c.getMetaData().getUserName()))
        throw new IllegalStateException("schema-mismatch");
    }
    require(true, "DEDICATED_SCHEMA_AND_USER_MATCH");
  }

  record Session(String cookie, String csrf) {}
  static final ObjectMapper JSON = new ObjectMapper();
  static final HttpClient HTTP = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5))
      .followRedirects(HttpClient.Redirect.NEVER).build();
  static String base;
  static HttpResponse<String> request(String method, String path, Object body, Session session, int expected, String label) throws Exception {
    HttpRequest.Builder r = HttpRequest.newBuilder(URI.create(base + path)).timeout(Duration.ofSeconds(8));
    if (session != null) r.header("Cookie", session.cookie()).header("X-CSRF-Token", session.csrf());
    if (body != null) r.header("Content-Type", "application/json");
    r.method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofByteArray(JSON.writeValueAsBytes(body)));
    HttpResponse<String> response = HTTP.send(r.build(), HttpResponse.BodyHandlers.ofString());
    String safePath = path.replaceAll("/[a-f0-9-]{36}$", "/{pid}");
    System.out.println("DMPROD HTTP " + label + " " + method + " path=" + safePath + " status=" + response.statusCode());
    require(response.statusCode() == expected, label);
    return response;
  }
  static Session login(String username, String password, String label) throws Exception {
    var response = request("POST", "/api/v1/auth/login", Map.of("username", username, "password", password), null, 200, label);
    return new Session(response.headers().firstValue("Set-Cookie").orElseThrow().split(";", 2)[0],
        JSON.readTree(response.body()).path("csrfToken").asText());
  }
  static int independentCount(DataSource ds, String table, String column, String id) throws SQLException {
    if (!Set.of("materials", "key_credentials", "app_users", "projects", "audit_events", "memberships", "sessions").contains(table) || !Set.of("id", "material_id", "actor", "project_id", "user_id").contains(column))
      throw new IllegalArgumentException("count-target");
    // Direct getConnection is deliberately separate from Spring's transaction-bound JdbcTemplate.
    try (Connection c = ds.getConnection(); PreparedStatement p = c.prepareStatement("select count(*) from " + table + " where " + column + "=?")) {
      p.setString(1, id);
      try (ResultSet r = p.executeQuery()) { r.next(); return r.getInt(1); }
    }
  }
  static class ControlledAbort extends RuntimeException {}

  public static void main(String[] args) {
    try { execute(); }
    catch (Throwable failure) {
      // Never expose exception messages, SQL, connection details, usernames, or credentials.
      System.out.println("DMPROD FAIL stage=" + stage + " type=" + failure.getClass().getSimpleName());
      System.exit(1);
    }
  }

  static void ledger(List<String> users, List<String> projects, List<String> materials) {
    try {
      java.nio.file.Path path = java.nio.file.Path.of(env("DM_PRODUCTION_LEDGER"));
      if (!java.nio.file.Files.exists(path)) java.nio.file.Files.createFile(path,
          java.nio.file.attribute.PosixFilePermissions.asFileAttribute(java.nio.file.attribute.PosixFilePermissions.fromString("rw-------")));
      java.nio.file.Files.writeString(path, JSON.writeValueAsString(Map.of("users", users, "projects", projects, "materials", materials)));
    } catch (Exception e) { throw new IllegalStateException("fixture-ledger-write"); }
  }
  static void recoverFirstRun(Store s, TransactionTemplate tx) {
    stage = "first-run-recovery";
    var admins = s.rows("select id,username,created_at from app_users where username like ?", "dmprobe-admin-%");
    require(admins.size() == 1, "RECOVERY_EXACTLY_ONE_FIXTURE_ADMIN");
    var admin = admins.getFirst();
    if (!admin.get("username").toString().matches("dmprobe-admin-[a-f0-9]{20}") ||
        java.time.Instant.parse(admin.get("created_at").toString()).isBefore(java.time.Instant.now().minusSeconds(1800)))
      throw new IllegalStateException("recovery-boundary");
    String aid = admin.get("id").toString();
    var createdUsers = s.rows("select resource_id from audit_events where actor=? and action=? and resource_type=?", aid, "CREATE_USER", "USER");
    var owned = s.rows("select p.id,p.name from projects p join memberships m on p.id=m.project_id where m.user_id=? and m.role=?", aid, "OWNER");
    require(createdUsers.size() == 1 && owned.size() == 1, "RECOVERY_EXACT_FIXTURE_AUDIT_AND_PROJECT");
    String uid = createdUsers.getFirst().get("resource_id").toString(), pid = owned.getFirst().get("id").toString();
    if (!s.one("select username from app_users where id=?", uid).get("username").toString().matches("dmprobe-[a-f0-9-]{36}") ||
        !owned.getFirst().get("name").toString().matches("dm-production-[a-f0-9-]{36}") ||
        !s.rows("select id from materials where project_id=?", pid).isEmpty() ||
        !s.rows("select id from jobs where project_id=?", pid).isEmpty()) throw new IllegalStateException("recovery-boundary");
    tx.executeWithoutResult(status -> {
      for (String id : List.of(aid, uid)) {
        s.db.update("delete from sessions where user_id=?", id);
        s.db.update("delete from audit_events where actor=?", id);
      }
      s.db.update("delete from audit_events where project_id=?", pid);
      s.db.update("delete from memberships where project_id=?", pid);
      s.db.update("delete from projects where id=?", pid);
      for (String id : List.of(uid, aid)) s.db.update("delete from app_users where id=?", id);
    });
    require(s.rows("select id from projects where id=?", pid).isEmpty() && s.rows("select id from app_users where id=? or id=?", aid, uid).isEmpty(), "FIRST_RUN_FIXTURES_RECOVERED");
  }

  static void execute() throws Exception {
    safety();
    stage = "spring-context";
    SpringApplication app = new SpringApplication(Application.class);
    app.setRegisterShutdownHook(false);
    app.setDefaultProperties(Map.of("server.address", "127.0.0.1", "server.port", "0",
        "spring.flyway.enabled", "false", "spring.sql.init.mode", "never", "spring.main.banner-mode", "off",
        "logging.level.root", "OFF", "logging.level.org.apache.catalina", "OFF"));
    try (ConfigurableApplicationContext context = app.run()) {
      require(context.getBeansOfType(Jobs.class).isEmpty(), "NO_JOB_OR_CLEANUP_WORKERS");
      Store store = context.getBean(Store.class);
      Auth auth = context.getBean(Auth.class);
      Materials materials = context.getBean(Materials.class);
      CredentialService credentials = context.getBean(CredentialService.class);
      Vault vault = context.getBean(Vault.class);
      DataSource ds = context.getBean(DataSource.class);
      PlatformTransactionManager manager = context.getBean(PlatformTransactionManager.class);
      TransactionTemplate transaction = context.getBean(TransactionTemplate.class);
      JdbcTemplate jdbc = store.db;
      require(CredentialService.class.getProtectionDomain().getCodeSource().getLocation().toString().endsWith("BOOT-INF/classes/"), "BEANS_LOADED_FROM_FROZEN_JAR_CLASSES");
      if ("true".equals(System.getenv("DM_PRODUCTION_RECOVER"))) {
        recoverFirstRun(store, transaction);
        System.out.println("DMPROD RESULT PASS checks=" + checks);
        return;
      }
      require(transaction.getTransactionManager() == manager, "REAL_SPRING_TRANSACTION_MANAGER");
      require(jdbc.getDataSource() == ds, "PRODUCTION_STORE_SAME_DATASOURCE");
      base = "http://127.0.0.1:" + ((ServletWebServerApplicationContext)context).getWebServer().getPort();
      String username = env("GMSSL_BOOTSTRAP_USERNAME"), password = env("GMSSL_BOOTSTRAP_PASSWORD");
      List<String> users = new ArrayList<>(), projects = new ArrayList<>(), materialIds = new ArrayList<>();
      Throwable primaryFailure = null;
      String failureStage = null;
      try {
        stage = "http-rbac";
        var existing = store.rows("select id from app_users where username=?", username);
        String adminId = existing.isEmpty() ? auth.createUser(username, password, "ADMIN").get("id").toString() : existing.getFirst().get("id").toString();
        users.add(adminId); ledger(users, projects, materialIds);
        Session admin = login(username, password, "ADMIN_LOGIN");
        var project = request("POST", "/api/v1/projects", Map.of("name", "dm-production-" + UUID.randomUUID()), admin, 200, "PROJECT_CREATE");
        String pid = JSON.readTree(project.body()).path("id").asText(); projects.add(pid); ledger(users, projects, materialIds);
        String outsiderName = "dmprobe-" + UUID.randomUUID(), outsiderPassword = random();
        var outsider = request("POST", "/api/v1/users", Map.of("username", outsiderName, "password", outsiderPassword, "role", "USER"), admin, 200, "NONMEMBER_CREATE");
        String outsiderId = JSON.readTree(outsider.body()).path("id").asText(); users.add(outsiderId); ledger(users, projects, materialIds);
        Session nonmember = login(outsiderName, outsiderPassword, "NONMEMBER_LOGIN");
        require(store.rows("select user_id from memberships where project_id=? and user_id=?", pid, outsiderId).isEmpty(), "NONMEMBER_HAS_NO_MEMBERSHIP");
        var forbidden = request("GET", "/api/v1/projects/" + pid, null, nonmember, 403, "NONMEMBER_PROJECT_READ");
        require("FORBIDDEN".equals(JSON.readTree(forbidden.body()).path("code").asText()), "NONMEMBER_FORBIDDEN_BODY");

        stage = "production-credential-roundtrip";
        byte[] payload = new byte[32]; new SecureRandom().nextBytes(payload);
        Map<String,String> attributes = Map.of("keyKind", "SYMMETRIC_KEY", "algorithm", "SM4", "encoding", "RAW");
        var material = materials.create(pid, "KEY", "dm-production-key", "application/octet-stream", payload, attributes);
        String materialId = material.get("id").toString(); materialIds.add(materialId); ledger(users, projects, materialIds);
        String secret = random().repeat(16);
        credentials.savePassphrase(pid, materialId, secret);
        require(secret.equals(credentials.getPassphrase(pid, materialId)), "PRODUCTION_CREDENTIAL_ENCRYPT_DECRYPT_ROUNDTRIP");
        byte[] encrypted = (byte[]) store.one("select encrypted_passphrase from key_credentials where material_id=?", materialId).get("encrypted_passphrase");
        require(encrypted.length == secret.getBytes(StandardCharsets.UTF_8).length + 28
            && !Arrays.equals(encrypted, secret.getBytes(StandardCharsets.UTF_8)), "PERSISTED_GCM_ENVELOPE_NOT_PLAINTEXT");
        require(encrypted.length == 540, "PRODUCTION_512_BYTE_SECRET_540_BYTE_CIPHERTEXT");
        require(Boolean.TRUE.equals(materials.dto(materials.raw(pid, materialId)).get("hasManagedPassphrase")), "PRODUCTION_MATERIAL_METADATA");
        require(Arrays.equals(payload, vault.read(pid, materialId)), "PRODUCTION_VAULT_MATERIAL_READ");

        for (boolean rollbackOnly : List.of(true, false)) {
          stage = rollbackOnly ? "spring-rollback-only" : "spring-exception-rollback";
          String[] rolledId = new String[1];
          try {
            transaction.executeWithoutResult(status -> {
              if (!TransactionSynchronizationManager.isActualTransactionActive()) throw new AssertionError("transaction-inactive");
              var created = materials.create(pid, "KEY", "dm-rollback-key", "application/octet-stream", payload, attributes);
              rolledId[0] = created.get("id").toString(); materialIds.add(rolledId[0]); ledger(users, projects, materialIds);
              credentials.savePassphrase(pid, rolledId[0], secret);
              if (jdbc.queryForObject("select count(*) from materials where id=?", Integer.class, rolledId[0]) != 1
                  || jdbc.queryForObject("select count(*) from key_credentials where material_id=?", Integer.class, rolledId[0]) != 1)
                throw new AssertionError("both-writes-not-visible");
              if (rollbackOnly) status.setRollbackOnly(); else throw new ControlledAbort();
            });
            if (!rollbackOnly) throw new AssertionError("exception-not-propagated");
          } catch (ControlledAbort expected) { if (rollbackOnly) throw expected; }
          require(rolledId[0] != null, "BOTH_PRODUCTION_WRITES_EXECUTED_" + (rollbackOnly ? "ROLLBACK_ONLY" : "EXCEPTION"));
          int materialCount = independentCount(ds, "materials", "id", rolledId[0]);
          int credentialCount = independentCount(ds, "key_credentials", "material_id", rolledId[0]);
          require(materialCount == 0 && credentialCount == 0, "INDEPENDENT_CONNECTION_BOTH_TABLES_ZERO_" + (rollbackOnly ? "ROLLBACK_ONLY" : "EXCEPTION"));
        }
      } catch (Exception | Error failure) {
        primaryFailure = failure;
        failureStage = stage;
        throw failure;
      } finally {
        stage = "cleanup";
        try {
        // All predicates use only IDs recorded by this invocation; no schema-wide cleanup.
        for (String id : materialIds) {
          for (String pid : projects) if (!store.rows("select id from materials where id=? and project_id=?", id, pid).isEmpty()) materials.delete(pid, id);
          vault.delete(id); // Outer rollback does not enlist filesystem writes; isolated fixture owns these files.
        }
        for (String uid : users) {
          jdbc.update("delete from sessions where user_id=?", uid);
          jdbc.update("delete from audit_events where actor=?", uid);
        }
        for (String pid : projects) {
          jdbc.update("delete from audit_events where project_id=?", pid);
          jdbc.update("delete from memberships where project_id=?", pid);
          jdbc.update("delete from projects where id=?", pid);
        }
        for (String uid : users) jdbc.update("delete from app_users where id=?", uid);
        for (String id : materialIds) require(independentCount(ds, "materials", "id", id) == 0
            && independentCount(ds, "key_credentials", "material_id", id) == 0, "OWN_MATERIALS_AND_CREDENTIALS_CLEANED");
        for (String uid : users) require(independentCount(ds, "app_users", "id", uid) == 0
            && independentCount(ds, "sessions", "user_id", uid) == 0
            && independentCount(ds, "audit_events", "actor", uid) == 0, "INDEPENDENT_OWN_USERS_SESSIONS_AUDIT_ZERO");
        for (String pid : projects) require(independentCount(ds, "projects", "id", pid) == 0
            && independentCount(ds, "memberships", "project_id", pid) == 0
            && independentCount(ds, "audit_events", "project_id", pid) == 0, "INDEPENDENT_OWN_PROJECT_MEMBERSHIPS_AUDIT_ZERO");
        } catch (Exception | Error cleanupFailure) {
          if (primaryFailure == null) throw cleanupFailure;
          primaryFailure.addSuppressed(cleanupFailure);
          System.out.println("DMPROD FAIL stage=cleanup type=" + cleanupFailure.getClass().getSimpleName());
        } finally { if (primaryFailure != null) stage = failureStage; }
      }
    }
    System.out.println("DMPROD RESULT PASS checks=" + checks);
  }
}
