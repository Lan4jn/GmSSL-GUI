package org.gmssl.gui.platform;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

class PasswordPolicyAndEncodingTest {

  @Test
  void testPasswordPolicyAllowsShortAndLongPasswords() {
    Auth auth = new Auth(null, "admin", "admin123456", false);

    // 1. Rejects null or empty string
    assertThrows(ApiError.class, () -> auth.password(null));
    assertThrows(ApiError.class, () -> auth.password(""));

    // 2. Allows 1-byte short password
    assertDoesNotThrow(() -> auth.password("a"));

    // 3. Allows 8-byte password (previously failed <12)
    assertDoesNotThrow(() -> auth.password("12345678"));

    // 4. Allows 73-byte password (previously failed >72)
    String p73 = "a".repeat(73);
    assertDoesNotThrow(() -> auth.password(p73));

    // 5. Allows 128-byte password
    String p128 = "b".repeat(128);
    assertDoesNotThrow(() -> auth.password(p128));

    // 6. Allows multi-byte UTF-8 string (>72 bytes)
    String pUtf8 = "密".repeat(30); // 30 * 3 = 90 bytes
    assertTrue(pUtf8.getBytes(StandardCharsets.UTF_8).length > 72);
    assertDoesNotThrow(() -> auth.password(pUtf8));
  }

  @Test
  void testNewPasswordEncodingFitsColumnAndAuthenticatesWithoutTruncation() {
    Auth auth = new Auth(null, "admin", "admin123456", false);

    // 1. Encode short password
    String hashShort = auth.encodePassword("1");
    assertTrue(hashShort.startsWith("{pbkdf2}"));
    assertTrue(hashShort.length() <= 100, "Hash must fit in VARCHAR(100)");
    assertTrue(auth.matchesPassword("1", hashShort));
    assertFalse(auth.matchesPassword("2", hashShort));

    // 2. Encode long password (e.g. 200 chars)
    String longPass = "k".repeat(200);
    String hashLong = auth.encodePassword(longPass);
    assertTrue(hashLong.length() <= 100, "Hash must fit in VARCHAR(100)");
    assertTrue(auth.matchesPassword(longPass, hashLong));

    // 3. Trailing difference on long password must fail (proves NO truncation to 72 bytes)
    assertFalse(auth.matchesPassword(longPass + "x", hashLong));
    assertFalse(auth.matchesPassword(longPass.substring(0, 199) + "z", hashLong));
  }

  @Test
  void testLegacyBcryptFallbackSupport() {
    Auth auth = new Auth(null, "admin", "admin123456", false);
    BCryptPasswordEncoder legacyBcrypt = new BCryptPasswordEncoder(12);

    // 1. Legacy bcrypt hash without prefix
    String legacyHash = legacyBcrypt.encode("legacyPassword123");
    assertFalse(legacyHash.startsWith("{"));
    assertTrue(auth.matchesPassword("legacyPassword123", legacyHash));
    assertFalse(auth.matchesPassword("wrongPassword123", legacyHash));

    // 2. Long password against legacy bcrypt hash must safely return false, never throw 500
    String longPass = "a".repeat(200);
    assertDoesNotThrow(() -> {
      boolean matched = auth.matchesPassword(longPass, legacyHash);
      assertFalse(matched);
    });
  }
  @Test
  void testUserCreateLoginUpdateFullLifecycle() throws Exception {
    org.springframework.jdbc.core.JdbcTemplate jdbc = org.mockito.Mockito.mock(org.springframework.jdbc.core.JdbcTemplate.class);
    Store store = org.mockito.Mockito.spy(new Store(jdbc));
    java.util.Map<String, String> dbMap = new java.util.HashMap<>();

    org.mockito.Mockito.when(store.id()).thenReturn("u-123");
    org.mockito.Mockito.when(store.now()).thenReturn("2026-10-20T10:00:00Z");
    org.mockito.Mockito.doAnswer(inv -> {
      String id = inv.getArgument(1);
      String u = inv.getArgument(2);
      String hash = inv.getArgument(3);
      dbMap.put(u, hash);
      return 1;
    }).when(store.db).update(org.mockito.ArgumentMatchers.startsWith("insert into app_users"),
        org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any(),
        org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any(),
        org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any());

    org.mockito.Mockito.doReturn(java.util.Map.of("id", "u-123", "username", "alice", "role", "USER", "enabled", true, "created_at", "2026-10-20T10:00:00Z"))
        .when(store).one(org.mockito.ArgumentMatchers.eq("select * from app_users where id=?"), org.mockito.ArgumentMatchers.any());
    org.mockito.Mockito.doNothing().when(store).audit(org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any());

    Auth auth = new Auth(store, "admin", "admin123456", false);

    // 1. Create user with short password "1"
    auth.createUser("alice", "1", "USER");
    String hash1 = dbMap.get("alice");
    assertNotNull(hash1);
    assertTrue(hash1.startsWith("{pbkdf2}"));

    // 2. Login verification mock
    org.mockito.Mockito.when(store.rows(org.mockito.ArgumentMatchers.contains("select * from app_users where username=?"),
        org.mockito.ArgumentMatchers.eq("alice"), org.mockito.ArgumentMatchers.any()))
        .thenAnswer(inv -> List.of(java.util.Map.of("id", "u-123", "username", "alice", "role", "USER", "password_hash", dbMap.get("alice"), "enabled", true)));

    jakarta.servlet.http.HttpServletRequest req = org.mockito.Mockito.mock(jakarta.servlet.http.HttpServletRequest.class);
    org.mockito.Mockito.when(req.getRemoteAddr()).thenReturn("127.0.0.1");
    jakarta.servlet.http.HttpServletResponse res = org.mockito.Mockito.mock(jakarta.servlet.http.HttpServletResponse.class);

    // Login with short password succeeds
    var loginResult1 = auth.login("alice", "1", req, res);
    assertNotNull(loginResult1);
    assertEquals("alice", ((java.util.Map<?, ?>) loginResult1.get("user")).get("username"));

    // Login with wrong password fails with 401 INVALID_CREDENTIALS
    ApiError errWrong = assertThrows(ApiError.class, () -> auth.login("alice", "wrong", req, res));
    assertEquals(401, errWrong.status);
    assertEquals("INVALID_CREDENTIALS", errWrong.code);

    // 3. Reset password to 200-char long password
    String longPassword = "L".repeat(200);
    auth.password(longPassword);
    dbMap.put("alice", auth.encodePassword(longPassword));

    // Login with long password succeeds
    var loginResult2 = auth.login("alice", longPassword, req, res);
    assertNotNull(loginResult2);

    // Login with trailing difference fails with 401
    ApiError errDiff = assertThrows(ApiError.class, () -> auth.login("alice", longPassword + "x", req, res));
    assertEquals(401, errDiff.status);
    assertEquals("INVALID_CREDENTIALS", errDiff.code);

    // 4. Test legacy bcrypt user in database can login and fails on wrong/long passwords safely
    BCryptPasswordEncoder legacyBcrypt = new BCryptPasswordEncoder(12);
    dbMap.put("bob", legacyBcrypt.encode("legacySecret123"));
    org.mockito.Mockito.when(store.rows(org.mockito.ArgumentMatchers.contains("select * from app_users where username=?"),
        org.mockito.ArgumentMatchers.eq("bob"), org.mockito.ArgumentMatchers.any()))
        .thenAnswer(inv -> List.of(java.util.Map.of("id", "u-456", "username", "bob", "role", "USER", "password_hash", dbMap.get("bob"), "enabled", true)));

    // Correct legacy password succeeds
    var loginResultBob = auth.login("bob", "legacySecret123", req, res);
    assertNotNull(loginResultBob);

    // Wrong legacy password fails with 401
    ApiError errBobWrong = assertThrows(ApiError.class, () -> auth.login("bob", "wrongSecret", req, res));
    assertEquals(401, errBobWrong.status);

    // 200-char password against legacy account safely returns 401 without throwing 500 / exception
    ApiError errBobLong = assertThrows(ApiError.class, () -> auth.login("bob", "a".repeat(200), req, res));
    assertEquals(401, errBobLong.status);
    assertEquals("INVALID_CREDENTIALS", errBobLong.code);
  }
}