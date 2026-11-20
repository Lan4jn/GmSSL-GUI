package org.gmssl.gui.platform;

import java.util.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

@Service
final class StandardClientLedger {
  private final Store s;
  private final StandardClientIssuer issuer;
  private final TransactionTemplate tx;
  private static final String TABLE = "standard_client_certs";
  private static final String BASE = " from " + TABLE + " where project_id=?";
  private static final String TYPE = "STANDARD_CERT";

  StandardClientLedger(Store s, StandardClientIssuer issuer, TransactionTemplate tx) {
    this.s = s;
    this.issuer = issuer;
    this.tx = tx;
  }

  record Entry(
      String id,
      String projectId,
      String requestId,
      String deviceLabel,
      String fingerprint,
      String serial,
      long expiresAt,
      String status,
      String certificatePem,
      String chainPem) {}

  private Entry entry(Map<String, Object> r) {
    long expiresAt = ((Number) r.get("expires_at")).longValue();
    String status =
        r.get("revoked_at") != null
            ? "REVOKED"
            : expiresAt <= System.currentTimeMillis() ? "EXPIRED" : "VALID";
    return new Entry(
        Store.str(r, "id"),
        Store.str(r, "project_id"),
        Store.str(r, "request_id"),
        Store.str(r, "device_label"),
        Store.str(r, "fingerprint"),
        Store.str(r, "serial_hex"),
        expiresAt,
        status,
        Store.str(r, "certificate_pem"),
        Store.str(r, "chain_pem"));
  }

  Entry issue(String pid, String actor, String rid, String csr, String label) {
    if (rid == null
        || !rid.matches("[A-Za-z0-9._:-]{1,100}")
        || label == null
        || label.isBlank()
        || label.length() > 200
        || label.chars().anyMatch(Character::isISOControl))
      throw ApiError.bad("Invalid requestId or deviceLabel");
    StandardClientIssuer.Request req;
    try {
      req = issuer.verify(csr);
    } catch (ApiError e) {
      s.audit(pid, actor, "STANDARD_CERT_ISSUE", TYPE, null, "INVALID_CSR");
      throw e;
    }
    // The project row exists before the first request. A database lock coordinates all instances,
    // including simultaneous first requests; the unique constraint is a second line of defense.
    Entry result =
        tx.execute(
            t -> {
              s.one("select id from projects where id=? for update", pid);
              var rows = s.rows("select *" + BASE + " and request_id=?", pid, rid);
              if (!rows.isEmpty()) {
                var r = rows.getFirst();
                boolean same =
                    req.digest().equals(r.get("csr_digest")) && label.equals(r.get("device_label"));
                s.audit(
                    pid,
                    actor,
                    "STANDARD_CERT_ISSUE",
                    TYPE,
                    Store.str(r, "id"),
                    same ? "REPLAY" : "CONFLICT");
                return same ? entry(r) : null;
              }
              var cert = issuer.sign(req, label);
              String id = s.id();
              s.db.update(
                  "insert into "
                      + TABLE
                      + " (id,project_id,request_id,csr_digest,device_label,fingerprint,serial_hex,expires_at,certificate_pem,chain_pem,issued_at)"
                      + " values(?,?,?,?,?,?,?,?,?,?,?)",
                  id,
                  pid,
                  rid,
                  req.digest(),
                  label,
                  cert.fingerprint(),
                  cert.serial(),
                  cert.expiresAt(),
                  cert.certificatePem(),
                  cert.chainPem(),
                  System.currentTimeMillis());
              s.audit(pid, actor, "STANDARD_CERT_ISSUE", TYPE, id, "SUCCESS");
              return byId(pid, id);
            });
    // Commit conflict audit without committing a new certificate.
    if (result == null)
      throw new ApiError(
          409, "IDEMPOTENCY_CONFLICT", "requestId already used with different inputs");
    return result;
  }

  private Entry byId(String pid, String id) {
    return entry(s.one("select *" + BASE + " and id=?", pid, id));
  }

  Entry get(String pid, String actor, String id) {
    var e = byId(pid, id);
    s.audit(pid, actor, "STANDARD_CERT_READ", TYPE, id, "SUCCESS");
    return e;
  }

  Entry revoke(String pid, String actor, String id) {
    return tx.execute(
        t -> {
          var r = s.one("select *" + BASE + " and id=? for update", pid, id);
          boolean first = r.get("revoked_at") == null;
          if (first)
            s.db.update(
                "update " + TABLE + " set revoked_at=? where project_id=? and id=?",
                System.currentTimeMillis(),
                pid,
                id);
          s.audit(pid, actor, "STANDARD_CERT_REVOKE", TYPE, id, first ? "SUCCESS" : "REPLAY");
          return byId(pid, id);
        });
  }

  record Page(List<Entry> items, long total) {}

  Page list(String pid, String actor, String fp, int page, int size) {
    if ("".equals(fp)) fp = null;
    if (page < 0 || size < 1 || size > 100 || (fp != null && !fp.matches("[0-9a-f]{64}")))
      throw ApiError.bad("Invalid pagination or SHA-256 fingerprint");
    String where = BASE;
    List<Object> args = new ArrayList<>(List.of(pid));
    if (fp != null) {
      where += " and fingerprint=?";
      args.add(fp);
    }
    long total = s.db.queryForObject("select count(*)" + where, Long.class, args.toArray());
    args.add((long) page * size);
    args.add(size);
    var items =
        s
            .rows(
                "select *"
                    + where
                    + " order by issued_at desc,id offset ? rows fetch next ? rows only",
                args.toArray())
            .stream()
            .map(this::entry)
            .toList();
    s.audit(pid, actor, "STANDARD_CERT_LIST", TYPE, null, "SUCCESS");
    return new Page(items, total);
  }
}
