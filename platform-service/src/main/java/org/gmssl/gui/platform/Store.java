package org.gmssl.gui.platform;

import java.time.Instant;
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

@Component
class Store {
  final JdbcTemplate db;

  Store(JdbcTemplate db) {
    this.db = db;
  }

  String id() {
    return UUID.randomUUID().toString();
  }

  String now() {
    return Instant.now().toString();
  }

  Map<String, Object> one(String sql, Object... args) {
    var r = db.queryForList(sql, args);
    if (r.isEmpty()) throw ApiError.missing();
    return r.getFirst();
  }

  List<Map<String, Object>> rows(String sql, Object... args) {
    return db.queryForList(sql, args);
  }

  void audit(String project, String user, String action, String type, String id, String outcome) {
    db.update(
        "insert into audit_events values(?,?,?,?,?,?,?,?)",
        id(),
        project,
        user,
        action,
        type,
        id,
        outcome,
        now());
  }

  static String str(Map<String, Object> m, String key) {
    Object o = m.get(key);
    return o == null ? null : o.toString();
  }

  static boolean bool(Map<String, Object> m, String key) {
    return Boolean.TRUE.equals(m.get(key));
  }
}