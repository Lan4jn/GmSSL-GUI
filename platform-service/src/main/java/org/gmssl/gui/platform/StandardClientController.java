package org.gmssl.gui.platform;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.*;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

/**
 * Both route families have identical wire contracts; each separately authorizes before body I/O.
 */
abstract class StandardClientController {
  private final StandardClientLedger ledger;
  private final ObjectReader reader;

  StandardClientController(StandardClientLedger ledger, ObjectMapper json) {
    this.ledger = ledger;
    reader =
        json.reader()
            .with(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
            .with(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
  }

  abstract String actor(HttpServletRequest req, String pid);

  @GetMapping
  StandardClientLedger.Page list(HttpServletRequest req, @PathVariable String pid) {
    String actor = actor(req, pid);
    parameters(req, Set.of("fingerprint", "page", "size"));
    return ledger.list(
        pid,
        actor,
        req.getParameter("fingerprint"),
        number(req, "page", 0),
        number(req, "size", 50));
  }

  @PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE)
  StandardClientLedger.Entry issue(HttpServletRequest req, @PathVariable String pid) {
    String actor = actor(req, pid);
    parameters(req, Set.of());
    var body = body(req, false);
    for (var key : List.of("requestId", "csrPem", "deviceLabel"))
      if (!body.path(key).isTextual()) throw ApiError.bad("Missing or invalid field: " + key);
    if (body.size() != 3) throw ApiError.bad("Unexpected issuance field");
    return ledger.issue(
        pid,
        actor,
        body.get("requestId").textValue(),
        body.get("csrPem").textValue(),
        body.get("deviceLabel").textValue());
  }

  @GetMapping("/{id}")
  StandardClientLedger.Entry get(
      HttpServletRequest req, @PathVariable String pid, @PathVariable String id) {
    String actor = actor(req, pid);
    parameters(req, Set.of());
    return ledger.get(pid, actor, id);
  }

  @PostMapping("/{id}/revoke")
  StandardClientLedger.Entry revoke(
      HttpServletRequest req, @PathVariable String pid, @PathVariable String id) {
    String actor = actor(req, pid);
    parameters(req, Set.of());
    body(req, true);
    return ledger.revoke(pid, actor, id);
  }

  private JsonNode body(HttpServletRequest req, boolean empty) {
    try {
      int limit = empty ? 1024 : 32768;
      var bytes = req.getInputStream().readNBytes(limit + 1);
      if (bytes.length > limit) throw new ApiError(413, "TOO_LARGE", "Request body too large");
      if (empty && bytes.length == 0) return null;
      JsonNode value = reader.readTree(bytes);
      if (value == null || !value.isObject() || (empty && !value.isEmpty()))
        throw ApiError.bad("Invalid JSON object");
      return value;
    } catch (IOException e) {
      throw ApiError.bad("Invalid JSON object");
    }
  }

  private static int number(HttpServletRequest req, String key, int fallback) {
    String v = req.getParameter(key);
    try {
      return v == null ? fallback : Integer.parseInt(v);
    } catch (NumberFormatException e) {
      throw ApiError.bad("Invalid pagination");
    }
  }

  private static void parameters(HttpServletRequest req, Set<String> allowed) {
    req.getParameterMap()
        .forEach(
            (key, values) -> {
              if (!allowed.contains(key) || values.length != 1)
                throw ApiError.bad("Unexpected or duplicate parameter");
            });
  }
}

@RestController
@RequestMapping("/api/v1/projects/{pid}/standard-client-certificates")
class AdminStandardClientController extends StandardClientController {
  private final Auth auth;

  AdminStandardClientController(StandardClientLedger ledger, ObjectMapper json, Auth auth) {
    super(ledger, json);
    this.auth = auth;
  }

  @Override
  String actor(HttpServletRequest req, String pid) {
    auth.adminRequired(req);
    auth.project(req, pid, 3);
    return auth.uid(req);
  }
}

@RestController
@RequestMapping("/integration/v1/projects/{pid}/standard-client-certificates")
class IntegrationStandardClientController extends StandardClientController {
  private final Store s;
  private final boolean enabled;
  private final String project;
  private final byte[] authorization;

  IntegrationStandardClientController(
      StandardClientLedger ledger,
      ObjectMapper json,
      Store s,
      @Value("${GMSSL_STANDARD_INTEGRATION_ENABLED:false}") boolean enabled,
      @Value("${GMSSL_STANDARD_INTEGRATION_PROJECT_ID:}") String project,
      @Value("${GMSSL_STANDARD_INTEGRATION_TOKEN:}") String token,
      @Value("${GMSSL_ENGINE_TOKEN:}") String engineToken,
      @Value("${GMSSL_STANDARD_CA_PASSWORD:}") String caPassword,
      @Value("${GMSSL_BOOTSTRAP_PASSWORD:}") String bootstrapPassword,
      @Value("${GMSSL_VAULT_MASTER_KEY:}") String vaultKey) {
    super(ledger, json);
    this.s = s;
    this.enabled = enabled;
    this.project = project;
    if (enabled
        && (!project.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
            || !strongToken(token)
            || List.of(engineToken, caPassword, bootstrapPassword, vaultKey).contains(token)))
      throw new IllegalStateException("Invalid dedicated integration project or credential");
    authorization = ("Bearer " + token).getBytes(StandardCharsets.US_ASCII);
  }

  private static boolean strongToken(String token) {
    if (!token.matches("[A-Za-z0-9_-]{43}") || token.chars().distinct().count() < 12) return false;
    byte[] bytes = Base64.getUrlDecoder().decode(token);
    return bytes.length == 32
        && Base64.getUrlEncoder().withoutPadding().encodeToString(bytes).equals(token);
  }

  @Override
  String actor(HttpServletRequest req, String pid) {
    if (!enabled) throw ApiError.missing();
    // A forwarded scheme alone is not evidence of a TLS session on this connector.
    if (!req.isSecure() || req.getAttribute("jakarta.servlet.request.ssl_session_id") == null)
      throw ApiError.denied();
    var headers = req.getHeaders("Authorization");
    if (!headers.hasMoreElements()
        || !MessageDigest.isEqual(
            authorization, headers.nextElement().getBytes(StandardCharsets.US_ASCII))
        || headers.hasMoreElements())
      throw new ApiError(401, "UNAUTHENTICATED", "Service credential required");
    if (!project.equals(pid)) throw ApiError.denied();
    s.one("select id from projects where id=?", pid);
    return "standard-client-service";
  }
}
