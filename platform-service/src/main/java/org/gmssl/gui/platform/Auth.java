package org.gmssl.gui.platform;

import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import java.util.concurrent.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.config.annotation.*;

@Component
class Auth implements HandlerInterceptor, WebMvcConfigurer {
  final Store s;
  final BCryptPasswordEncoder bcrypt = new BCryptPasswordEncoder(12);
  final Pbkdf2PasswordEncoder pbkdf2 = createPbkdf2();
  final SecureRandom rng = new SecureRandom();

  private static Pbkdf2PasswordEncoder createPbkdf2() {
    Pbkdf2PasswordEncoder encoder = Pbkdf2PasswordEncoder.defaultsForSpringSecurity_v5_8();
    encoder.setEncodeHashAsBase64(true);
    return encoder;
  }

  String encodePassword(String rawPassword) {
    return "{pbkdf2}" + pbkdf2.encode(rawPassword);
  }

  boolean matchesPassword(String rawPassword, String encodedHash) {
    if (rawPassword == null || encodedHash == null) return false;
    if (encodedHash.startsWith("{pbkdf2}")) {
      return pbkdf2.matches(rawPassword, encodedHash.substring(8));
    }
    // Fallback to legacy un-prefixed BCrypt
    if (rawPassword.getBytes(StandardCharsets.UTF_8).length > 72) {
      return false;
    }
    try {
      return bcrypt.matches(rawPassword, encodedHash);
    } catch (Exception e) {
      return false;
    }
  }
  final Map<String, Attempts> attempts = new ConcurrentHashMap<>();
  final String bootstrapUser, bootstrapPassword;
  final boolean secure;

  record Attempts(long since, int count) {}

  Auth(
      Store s,
      @Value("${GMSSL_BOOTSTRAP_USERNAME:}") String u,
      @Value("${GMSSL_BOOTSTRAP_PASSWORD:}") String p,
      @Value("${GMSSL_SESSION_COOKIE_SECURE:false}") boolean secure) {
    this.s = s;
    bootstrapUser = u;
    bootstrapPassword = p;
    this.secure = secure;
  }

  @PostConstruct
  void init() {
    if (s.db.queryForObject("select count(*) from app_users", Integer.class) == 0) {
      if (bootstrapUser.isBlank() || bootstrapPassword.isBlank())
        throw new IllegalStateException("Bootstrap credentials required for empty database");
      createUser(bootstrapUser, bootstrapPassword, "ADMIN");
    }
  }

  void password(String p) {
    if (p == null || p.isEmpty()) {
      throw ApiError.bad("Password cannot be empty");
    }
  }

  Map<String, Object> createUser(String u, String p, String role) {
    password(p);
    if (u == null || !u.matches("[A-Za-z0-9_.@-]{1,100}")) throw ApiError.bad("Invalid username");
    if (!Set.of("ADMIN", "USER").contains(role)) throw ApiError.bad("Invalid role");
    String id = s.id();
    try {
      s.db.update(
          "insert into app_users values(?,?,?,?,?,?)",
          id,
          u,
          encodePassword(p),
          role,
          true,
          s.now());
    } catch (org.springframework.dao.DuplicateKeyException e) {
      throw new ApiError(409, "CONFLICT", "Username exists");
    }
    return user(id);
  }

  Map<String, Object> user(String id) {
    var r = s.one("select * from app_users where id=?", id);
    return Map.of(
        "id",
        id,
        "username",
        r.get("username"),
        "role",
        r.get("role"),
        "enabled",
        r.get("enabled"),
        "createdAt",
        r.get("created_at"));
  }

  static String hash(String token) {
    try {
      return HexFormat.of()
          .formatHex(
              MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.UTF_8)));
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  String random() {
    byte[] b = new byte[32];
    rng.nextBytes(b);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
  }

  String cookie(HttpServletRequest req) {
    if (req.getCookies() != null)
      for (var c : req.getCookies()) if (c.getName().equals("GMSSL_SESSION")) return c.getValue();
    return "";
  }

  String uid(HttpServletRequest req) {
    return (String) req.getAttribute("uid");
  }

  boolean admin(HttpServletRequest req) {
    return "ADMIN".equals(req.getAttribute("role"));
  }

  void adminRequired(HttpServletRequest req) {
    if (!admin(req)) throw ApiError.denied();
  }

  String project(HttpServletRequest req, String pid, int required) {
    s.one("select id from projects where id=?", pid);
    String role;
    if (admin(req)) {
      role = "OWNER";
      s.audit(pid, uid(req), "ADMIN_ACCESS", "PROJECT", pid, "ALLOWED");
    } else {
      var ms =
          s.rows("select role from memberships where project_id=? and user_id=?", pid, uid(req));
      if (ms.isEmpty()) throw ApiError.denied();
      role = Store.str(ms.getFirst(), "role");
    }
    int level =
        switch (role) {
          case "OWNER" -> 3;
          case "EDITOR" -> 2;
          default -> 1;
        };
    if (level < required) throw ApiError.denied();
    return role;
  }

  public void addInterceptors(InterceptorRegistry r) {
    r.addInterceptor(this).addPathPatterns("/api/v1/**");
  }

  public boolean preHandle(HttpServletRequest req, HttpServletResponse res, Object handler) {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Cache-Control", "no-store");
    if (req.getRequestURI().equals("/api/v1/auth/login") && req.getMethod().equals("POST"))
      return true;
    String token = cookie(req);
    var rows =
        s.rows(
            "select a.id,a.role,t.csrf from sessions t join app_users a on a.id=t.user_id where"
                + " t.token_hash=? and t.expires_at>? and a.enabled=?",
            hash(token),
            System.currentTimeMillis(),
            Boolean.TRUE);
    if (rows.isEmpty()) throw new ApiError(401, "UNAUTHENTICATED", "Login required");
    var r = rows.getFirst();
    req.setAttribute("uid", r.get("id"));
    req.setAttribute("role", r.get("role"));
    req.setAttribute("csrf", r.get("csrf"));
    if (!Set.of("GET", "HEAD", "OPTIONS").contains(req.getMethod())) {
      String csrf = req.getHeader("X-CSRF-Token");
      if (csrf == null
          || !MessageDigest.isEqual(
              csrf.getBytes(StandardCharsets.UTF_8),
              r.get("csrf").toString().getBytes(StandardCharsets.UTF_8)))
        throw new ApiError(403, "CSRF_INVALID", "CSRF token required");
    }
    return true;
  }

  Map<String, Object> login(String u, String p, HttpServletRequest req, HttpServletResponse res) {
    String key = req.getRemoteAddr();
    long now = System.currentTimeMillis();
    if (attempts.size() > 10000)
      attempts.entrySet().removeIf(e -> now - e.getValue().since > 60000);
    Attempts a =
        attempts.compute(
            key,
            (k, v) ->
                v == null || now - v.since > 60000
                    ? new Attempts(now, 1)
                    : new Attempts(v.since, v.count + 1));
    if (a.count > 10) throw new ApiError(429, "RATE_LIMITED", "Too many login attempts");
    var rows = s.rows("select * from app_users where username=? and enabled=?", u, Boolean.TRUE);
    String dummy = "{pbkdf2}d7Z947Vp0X0Rk+Q93F+7q5iLzV+1rZ9N1V0Z7Q8M4J3Y6X5W2T1S0R9P8O7N6M5L";
    String h = rows.isEmpty() ? dummy : Store.str(rows.getFirst(), "password_hash");
    if (p == null
        || !matchesPassword(p, h)
        || rows.isEmpty()) throw new ApiError(401, "INVALID_CREDENTIALS", "Invalid credentials");
    String token = random(), csrf = random(), id = Store.str(rows.getFirst(), "id");
    s.db.update("insert into sessions values(?,?,?,?)", hash(token), id, csrf, now + 8 * 3600000L);
    setCookie(res, token, 28800);
    s.audit(null, id, "LOGIN", "USER", id, "SUCCESS");
    return Map.of(
        "user",
        Map.of("id", id, "username", u, "role", rows.getFirst().get("role")),
        "csrfToken",
        csrf);
  }

  void setCookie(HttpServletResponse r, String token, int age) {
    r.addHeader(
        "Set-Cookie",
        "GMSSL_SESSION="
            + token
            + "; Path=/; HttpOnly; SameSite=Strict; Max-Age="
            + age
            + (secure ? "; Secure" : ""));
  }
}