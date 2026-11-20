package org.gmssl.gui.platform;

import jakarta.servlet.http.*;
import java.util.*;
import org.springframework.http.*;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1")
class AccountController {
  final Store s;
  final Auth auth;
  final TransactionTemplate tx;

  AccountController(Store s, Auth a, TransactionTemplate t) {
    this.s = s;
    auth = a;
    tx = t;
  }

  @PostMapping("/auth/login")
  Object login(@RequestBody Map<String, String> b, HttpServletRequest r, HttpServletResponse out) {
    return auth.login(b.get("username"), b.get("password"), r, out);
  }

  @GetMapping("/auth/me")
  Object me(HttpServletRequest r) {
    var u = auth.user(auth.uid(r));
    return Map.of(
        "user",
        Map.of("id", u.get("id"), "username", u.get("username"), "role", u.get("role")),
        "csrfToken",
        r.getAttribute("csrf"));
  }

  @PostMapping("/auth/logout")
  ResponseEntity<?> logout(HttpServletRequest r, HttpServletResponse out) {
    s.db.update("delete from sessions where token_hash=?", Auth.hash(auth.cookie(r)));
    auth.setCookie(out, "", 0);
    return ResponseEntity.noContent().build();
  }

  @GetMapping("/users")
  Object users(HttpServletRequest r) {
    auth.adminRequired(r);
    return s.rows("select id from app_users order by created_at").stream()
        .map(m -> auth.user(Store.str(m, "id")))
        .toList();
  }

  @PostMapping("/users")
  Object createUser(@RequestBody Map<String, String> b, HttpServletRequest r) {
    auth.adminRequired(r);
    var u = auth.createUser(b.get("username"), b.get("password"), b.getOrDefault("role", "USER"));
    s.audit(null, auth.uid(r), "CREATE_USER", "USER", (String) u.get("id"), "SUCCESS");
    return u;
  }

  @PatchMapping("/users/{id}")
  Object updateUser(
      @PathVariable String id, @RequestBody Map<String, Object> b, HttpServletRequest r) {
    auth.adminRequired(r);
    tx.executeWithoutResult(
        t -> {
          var u = s.one("select * from app_users where id=? for update", id);
          String role = b.getOrDefault("role", u.get("role")).toString();
          if (!Set.of("ADMIN", "USER").contains(role)) throw ApiError.bad("Invalid role");
          boolean enabled =
              b.containsKey("enabled")
                  ? Boolean.TRUE.equals(b.get("enabled"))
                  : Store.bool(u, "enabled");
          if ("ADMIN".equals(u.get("role"))
              && (!enabled || !role.equals("ADMIN"))
              && s.db.queryForObject(
                      "select count(*) from app_users where role='ADMIN' and enabled=?",
                      Integer.class,
                      Boolean.TRUE)
                  <= 1) throw ApiError.bad("Last enabled administrator protected");
          s.db.update("update app_users set role=?,enabled=? where id=?", role, enabled, id);
          if (b.containsKey("password")) {
            String p = b.get("password").toString();
            auth.password(p);
            s.db.update(
                "update app_users set password_hash=? where id=?", auth.encodePassword(p), id);
          }
          s.db.update("delete from sessions where user_id=?", id);
        });
    s.audit(null, auth.uid(r), "UPDATE_USER", "USER", id, "SUCCESS");
    return auth.user(id);
  }

  Map<String, Object> project(String id, String role) {
    var p = s.one("select * from projects where id=?", id);
    return Map.of(
        "id",
        id,
        "name",
        p.get("name"),
        "description",
        p.get("description"),
        "createdAt",
        p.get("created_at"),
        "role",
        role);
  }

  @GetMapping("/projects")
  Object projects(HttpServletRequest r) {
    return (auth.admin(r)
            ? s.rows("select id from projects order by created_at")
            : s.rows("select project_id as id from memberships where user_id=?", auth.uid(r)))
        .stream()
            .map(
                p -> {
                  String id = Store.str(p, "id");
                  return project(id, auth.project(r, id, 1));
                })
            .toList();
  }

  @PostMapping("/projects")
  Object create(@RequestBody Map<String, String> b, HttpServletRequest r) {
    String name = bounded(b.get("name"), 200, true),
        desc = bounded(b.getOrDefault("description", ""), 2000, false),
        id = s.id();
    tx.executeWithoutResult(
        t -> {
          s.db.update("insert into projects values(?,?,?,?)", id, name, desc, s.now());
          s.db.update("insert into memberships values(?,?,?)", id, auth.uid(r), "OWNER");
          s.audit(id, auth.uid(r), "CREATE_PROJECT", "PROJECT", id, "SUCCESS");
        });
    return project(id, "OWNER");
  }

  @GetMapping("/projects/{pid}")
  Object get(@PathVariable String pid, HttpServletRequest r) {
    return project(pid, auth.project(r, pid, 1));
  }

  @GetMapping("/projects/{pid}/members")
  Object members(@PathVariable String pid, HttpServletRequest r) {
    auth.project(r, pid, 1);
    return s.rows(
        "select m.user_id as \"userId\",u.username,m.role from memberships m join app_users u on"
            + " u.id=m.user_id where m.project_id=?",
        pid);
  }

  @PutMapping("/projects/{pid}/members/{uid}")
  Object member(
      @PathVariable String pid,
      @PathVariable String uid,
      @RequestBody Map<String, String> b,
      HttpServletRequest r) {
    auth.project(r, pid, 3);
    String role = b.get("role");
    if (!Set.of("OWNER", "EDITOR", "VIEWER").contains(role))
      throw ApiError.bad("Invalid project role");
    auth.user(uid);
    tx.executeWithoutResult(
        t -> {
          s.one("select id from projects where id=? for update", pid);
          protectOwner(pid, uid, role);
          s.db.update("delete from memberships where project_id=? and user_id=?", pid, uid);
          s.db.update("insert into memberships values(?,?,?)", pid, uid, role);
          s.audit(pid, auth.uid(r), "SET_MEMBER", "USER", uid, "SUCCESS");
        });
    return Map.of("userId", uid, "username", auth.user(uid).get("username"), "role", role);
  }

  @DeleteMapping("/projects/{pid}/members/{uid}")
  ResponseEntity<?> remove(
      @PathVariable String pid, @PathVariable String uid, HttpServletRequest r) {
    auth.project(r, pid, 3);
    tx.executeWithoutResult(
        t -> {
          s.one("select id from projects where id=? for update", pid);
          protectOwner(pid, uid, "");
          s.db.update("delete from memberships where project_id=? and user_id=?", pid, uid);
          s.audit(pid, auth.uid(r), "REMOVE_MEMBER", "USER", uid, "SUCCESS");
        });
    return ResponseEntity.noContent().build();
  }

  void protectOwner(String p, String u, String role) {
    if (!role.equals("OWNER")
        && s.db.queryForObject(
                "select count(*) from memberships where project_id=? and user_id=? and"
                    + " role='OWNER'",
                Integer.class,
                p,
                u)
            > 0
        && s.db.queryForObject(
                "select count(*) from memberships where project_id=? and role='OWNER'",
                Integer.class,
                p)
            <= 1) throw ApiError.bad("Last owner protected");
  }

  @GetMapping("/projects/{pid}/audit")
  Object audit(@PathVariable String pid, HttpServletRequest r) {
    auth.project(r, pid, 3);
    return s.rows(
        "select id,actor,action,resource_type as \"resourceType\",resource_id as"
            + " \"resourceId\",outcome,created_at as \"createdAt\" from audit_events where"
            + " project_id=? order by created_at desc",
        pid);
  }

  static String bounded(String v, int max, boolean required) {
    if (v == null || v.length() > max || (required && v.isBlank()))
      throw ApiError.bad("Invalid text field");
    return v;
  }
}