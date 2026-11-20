package org.gmssl.gui.platform;

import jakarta.servlet.http.HttpServletRequest;
import java.util.*;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1")
class JobController {
  final Jobs jobs;
  final Auth auth;
  final Materials m;
  final Store s;
  final Engine engine;

  JobController(Jobs j, Auth a, Materials m, Store s, Engine e) {
    jobs = j;
    auth = a;
    this.m = m;
    this.s = s;
    engine = e;
  }

  @GetMapping("/capabilities")
  Object capabilities() {
    return engine.catalog();
  }

  @PostMapping("/projects/{pid}/jobs")
  ResponseEntity<?> submit(
      @PathVariable String pid, @RequestBody Map<String, Object> b, HttpServletRequest r) {
    return ResponseEntity.accepted().body(jobs.submit(pid, b, r));
  }

  @GetMapping("/projects/{pid}/jobs")
  Object list(@PathVariable String pid, HttpServletRequest r) {
    boolean canEdit = !auth.project(r, pid, 1).equals("VIEWER");
    return s.rows("select id from jobs where project_id=? order by created_at desc", pid).stream()
        .map(j -> jobs.dto(pid, Store.str(j, "id"), canEdit))
        .toList();
  }

  @GetMapping("/projects/{pid}/jobs/{id}")
  Object get(@PathVariable String pid, @PathVariable String id, HttpServletRequest r) {
    boolean canEdit = !auth.project(r, pid, 1).equals("VIEWER");
    return jobs.dto(pid, id, canEdit);
  }

  @PostMapping("/projects/{pid}/jobs/{id}/cancel")
  Object cancel(@PathVariable String pid, @PathVariable String id, HttpServletRequest r) {
    return jobs.cancel(pid, id, r);
  }

  Map<String, Object> artifact(String pid, String jid, String aid) {
    var mat = m.raw(pid, aid, "ARTIFACT");
    var a =
        s.one(
            "select a.* from artifacts a join jobs j on j.id=a.job_id where a.id=? and a.job_id=?"
                + " and j.project_id=? and j.status='SUCCEEDED'",
            aid,
            jid,
            pid);
    var combined = new HashMap<>(mat);
    combined.put("sensitive", a.get("sensitive"));
    combined.put("stateful_private", a.get("stateful_private"));
    combined.put("stateful_source", a.get("stateful_source"));
    return combined;
  }

  @GetMapping("/projects/{pid}/jobs/{jid}/artifacts/{aid}/download")
  ResponseEntity<byte[]> download(
      @PathVariable String pid,
      @PathVariable String jid,
      @PathVariable String aid,
      HttpServletRequest r) {
    auth.project(r, pid, 1);
    var a = artifact(pid, jid, aid);
    if (Store.bool(a, "stateful_private")) throw ApiError.denied();
    if (Store.bool(a, "sensitive")) auth.project(r, pid, 2);
    s.audit(pid, auth.uid(r), "DOWNLOAD_ARTIFACT", "ARTIFACT", aid, "SUCCESS");
    return MaterialController.binary(m.vault.read(pid, aid), Store.str(a, "name"));
  }

  @PostMapping("/projects/{pid}/jobs/{jid}/artifacts/{aid}/save-key")
  Object save(
      @PathVariable String pid,
      @PathVariable String jid,
      @PathVariable String aid,
      @RequestBody Map<String, String> b,
      HttpServletRequest r) {
    auth.project(r, pid, 2);
    if ("true".equalsIgnoreCase(b.get("temporary")))
      throw ApiError.bad("Temporary is only allowed for FILE");
    var source = artifact(pid, jid, aid);
    Map<String, Object> result;
    if (Store.bool(source, "stateful_private")) {
      if (!Store.bool(source, "stateful_source")) throw ApiError.denied();
      result =
          jobs.tx.execute(
              t -> {
                s.one("select id from artifacts where id=? for update", aid);
                if (!s.rows(
                        "select source_artifact_id from stateful_promotions where"
                            + " source_artifact_id=?",
                        aid)
                    .isEmpty())
                  throw new ApiError(
                      409, "ALREADY_PROMOTED", "Stateful private output was already promoted");
                String tool =
                    Store.str(
                        s.one("select tool_id from jobs where id=? and project_id=?", jid, pid),
                        "tool_id");
                String algorithm = Jobs.STATEFUL_GENERATORS.get(tool);
                if (algorithm == null) throw ApiError.denied();
                Map<String, String> controlled = new HashMap<>(b);
                controlled.put("algorithm", algorithm);
                controlled.put("keyKind", "STATEFUL_PRIVATE_KEY");
                var key =
                    m.createControlled(
                        pid,
                        "KEY",
                        b.get("name"),
                        "application/octet-stream",
                        m.vault.read(pid, aid),
                        controlled);
                s.db.update(
                    "insert into stateful_promotions values(?,?,?)", aid, key.get("id"), s.now());
                return key;
              });
    } else {
      result =
          m.create(
              pid, "KEY", b.get("name"), "application/octet-stream", m.vault.read(pid, aid), b);
    }
    s.audit(pid, auth.uid(r), "SAVE_KEY", "KEY", result.get("id").toString(), "SUCCESS");
    return result;
  }
}

@RestController
class HealthController {
  @GetMapping("/actuator/health")
  Object health() {
    return Map.of("status", "UP");
  }
}
