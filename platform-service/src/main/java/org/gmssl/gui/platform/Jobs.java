package org.gmssl.gui.platform;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.annotation.*;
import jakarta.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.stream.Collectors;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionTemplate;

@Component
class Jobs {
  static final Map<String, String> STATEFUL_GENERATORS =
      Map.of(
          "lmskeygen", "LMS", "hsskeygen", "HSS", "xmsskeygen", "XMSS", "xmssmtkeygen", "XMSSMT");
  final Store s;
  final Auth auth;
  final Materials materials;
  final Engine engine;
  final TransactionTemplate tx;
  final CredentialService credentials;
  final ThreadPoolExecutor pool =
      new ThreadPoolExecutor(
          2,
          2,
          0,
          TimeUnit.SECONDS,
          new ArrayBlockingQueue<>(16),
          new ThreadPoolExecutor.AbortPolicy());
  final ConcurrentMap<String, Work> active = new ConcurrentHashMap<>();

  record Ref(String id, String type, boolean stateful, boolean temporary) {}

  static class Work {
    String id, pid, uid, tool;
    JsonNode definition;
    Map<String, Object> params;
    Map<String, Ref> refs = new LinkedHashMap<>();
    byte[] stdin;
    int timeout;
    boolean sensitive;
    volatile boolean cancelled;
  }

  Jobs(Store s, Auth a, Materials m, Engine e, TransactionTemplate tx, CredentialService credentials) {
    this.s = s;
    auth = a;
    materials = m;
    engine = e;
    this.tx = tx;
    this.credentials = credentials;
  }

  @PostConstruct
  void recover() {
    var unclosed = s.rows("select id from jobs where status in ('QUEUED','RUNNING')");
    s.db.update(
        "update jobs set status='FAILED',error_text='Service restarted before"
            + " completion',finished_at=? where status in ('QUEUED','RUNNING')",
        s.now());
    for (var job : unclosed) {
      cleanupTemporaryFiles(job.get("id").toString());
    }
    for (var row :
        s.rows(
            "select id, project_id from materials where temporary=? and bound_job_id in"
                + " (select id from jobs where status in ('FAILED','CANCELLED','SUCCEEDED'))",
            Boolean.TRUE)) {
      String id = row.get("id").toString();
      try {
        materials.delete(row.get("project_id").toString(), id);
      } catch (Exception e) {
        System.err.println(
            "Startup temporary file cleanup retry for " + id + ": " + e.getMessage());
      }
    }
  }

  @PreDestroy
  void close() {
    pool.shutdownNow();
  }

  Map<String, Object> dto(String pid, String id) {
    return dto(pid, id, true);
  }

  Map<String, Object> dto(String pid, String id, boolean canEdit) {
    var m = s.one("select * from jobs where project_id=? and id=?", pid, id);
    Map<String, Object> r = new LinkedHashMap<>();
    for (String[] p :
        new String[][] {
          {"id", "id"},
          {"projectId", "project_id"},
          {"toolId", "tool_id"},
          {"status", "status"},
          {"createdAt", "created_at"},
          {"startedAt", "started_at"},
          {"finishedAt", "finished_at"},
          {"exitCode", "exit_code"},
          {"durationMs", "duration_ms"},
          {"error", "error_text"},
          {"stdoutPreview", "stdout_preview"},
          {"stderrPreview", "stderr_preview"},
          {"truncated", "truncated"}
        }) r.put(p[0], m.get(p[1]));
    boolean succeeded = "SUCCEEDED".equals(m.get("status"));
    List<Map<String, Object>> artifacts = new ArrayList<>();
    for (var a :
        s.rows(
            "select"
                + " m.id,m.name,m.byte_size,m.media_type,a.sensitive,a.stateful_private,a.stateful_source"
                + " from artifacts a join materials m on m.id=a.id where a.job_id=? and"
                + " m.project_id=?",
            id,
            pid)) {
      String aid = a.get("id").toString();
      boolean privateState = Store.bool(a, "stateful_private");
      boolean consumed =
          !s.rows(
                  "select source_artifact_id from stateful_promotions where source_artifact_id=?",
                  aid)
              .isEmpty();
      artifacts.add(
          Map.of(
              "id",
              aid,
              "name",
              a.get("name"),
              "size",
              a.get("byte_size"),
              "mediaType",
              a.get("media_type"),
              "sensitive",
              a.get("sensitive"),
              "statefulPrivate",
              privateState,
              "downloadable",
              succeeded && !privateState && (!Store.bool(a, "sensitive") || canEdit),
              "promotable",
              succeeded
                  && canEdit
                  && (!privateState || (Store.bool(a, "stateful_source") && !consumed))));
    }
    r.put("artifacts", artifacts);
    return r;
  }

  synchronized Map<String, Object> submit(
      String pid, Map<String, Object> b, HttpServletRequest req) {
    auth.project(req, pid, 2);
    String uid = auth.uid(req);
    boolean isAdmin = false;
    try {
      auth.adminRequired(req);
      isAdmin = true;
    } catch (Exception ignored) {
    }
    return submitDirect(pid, uid, b, isAdmin);
  }

  synchronized Map<String, Object> submitDirect(
      String pid, String uid, Map<String, Object> b, boolean isAdmin) {
    if (active.values().stream().filter(w -> w.uid.equals(uid)).count() >= 2)
      throw new ApiError(429, "CONCURRENCY_LIMIT", "Per-user task limit reached");
    Work w = new Work();
    w.id = s.id();
    w.pid = pid;
    w.uid = uid;
    w.tool = Objects.toString(b.get("toolId"), "");
    w.definition = engine.tool(w.tool);
    if ((w.definition.path("adminOnly").asBoolean()
            || w.definition.path("category").asText().equals("protocol"))
        && !isAdmin) {
      throw ApiError.denied();
    }
    Object params = b.getOrDefault("parameters", Map.of());
    if (!(params instanceof Map<?, ?> map)) throw ApiError.bad("Parameters must be an object");
    w.params = new LinkedHashMap<>();
    Map<String, JsonNode> definitions = new HashMap<>();
    for (JsonNode p : w.definition.path("parameters")) definitions.put(p.path("name").asText(), p);
    for (var en : map.entrySet()) {
      String name = en.getKey().toString();
      JsonNode p = definitions.get(name);
      if (p == null) throw ApiError.bad("Unknown parameter");
      Object value = en.getValue();
      w.sensitive |= p.path("secret").asBoolean() || p.path("type").asText().equals("SECRET");
      if (value instanceof List<?> list) {
        if (!p.path("repeatable").asBoolean() || list.size() > 32)
          throw ApiError.bad("Invalid repeated parameter");
        List<Object> values = new ArrayList<>();
        for (Object v : list) values.add(resolve(w, p, v));
        w.params.put(name, values);
      } else w.params.put(name, resolve(w, p, value));
    }
    for (var def : definitions.values()) {
      String credKeyParam = def.path("credentialKeyParameter").asText(null);
      if (credKeyParam != null && !credKeyParam.isBlank()) {
        String passParamName = def.path("name").asText();
        Object explicitVal = w.params.get(passParamName);
        if (explicitVal == null || explicitVal.toString().isBlank()) {
          Object keyRefVal = map.get(credKeyParam);
          if (keyRefVal instanceof String keyRefStr
              && (keyRefStr.startsWith("key:") || keyRefStr.startsWith("file:"))) {
            try {
              Ref ref = reference(pid, keyRefStr);
              if (credentials.hasPassphrase(ref.id)) {
                String pass = credentials.getPassphrase(pid, ref.id);
                if (pass != null && !pass.isBlank()) {
                  w.params.put(passParamName, pass);
                  w.sensitive = true;
                }
              }
            } catch (Exception ignored) {
            }
          }
        }
      }
    }
    if (STATEFUL_GENERATORS.containsKey(w.tool)) {
      if (!definitions.containsKey("out")
          || !definitions.get("out").path("type").asText().equals("OUTPUT_FILE"))
        throw ApiError.bad("Controlled key generation output is unavailable");
      w.params.putIfAbsent("out", "stateful-private.key");
    }
    Set<Object> outputNames = new HashSet<>();
    for (var def : definitions.entrySet())
      if (def.getValue().path("type").asText().equals("OUTPUT_FILE")
          && w.params.containsKey(def.getKey())) {
        Object value = w.params.get(def.getKey());
        if (!outputNames.add(value)) throw ApiError.bad("Output filenames must be distinct");
      }
    if (b.get("stdinText") != null && b.get("stdinFileRef") != null)
      throw ApiError.bad("stdin inputs are mutually exclusive");
    if (b.get("stdinText") != null)
      w.stdin = b.get("stdinText").toString().getBytes(StandardCharsets.UTF_8);
    if (b.get("stdinFileRef") != null) {
      Ref ref = reference(pid, b.get("stdinFileRef").toString());
      if (ref.stateful) throw ApiError.bad("Stateful key cannot be stdin");
      w.stdin = materials.vault.read(pid, ref.id);
      w.sensitive |= ref.type.equals("KEY");
      w.refs.put(ref.id, ref);
    }
    if (w.stdin != null && w.stdin.length > Vault.LIMIT) throw ApiError.bad("Input too large");
    int def = w.definition.path("defaultTimeoutSeconds").asInt(30),
        max = Math.min(300, w.definition.path("maxTimeoutSeconds").asInt(300));
    try {
      w.timeout =
          b.get("timeoutSeconds") == null
              ? def
              : Integer.parseInt(b.get("timeoutSeconds").toString());
    } catch (Exception e) {
      throw ApiError.bad("Invalid timeout");
    }
    if (w.timeout < 1 || w.timeout > max) throw ApiError.bad("Invalid timeout");
    if (w.definition.path("stateful").asBoolean()
        && w.refs.values().stream().noneMatch(Ref::stateful))
      throw ApiError.bad("Stateful signing requires a managed stateful private key");
    Set<String> tempFileIds =
        w.refs.values().stream().filter(Ref::temporary).map(Ref::id).collect(Collectors.toSet());
    List<String> boundTemps = new ArrayList<>();
    try {
      for (String tempId : tempFileIds) {
        int n =
            s.db.update(
                "update materials set bound_job_id=? where id=? and project_id=?"
                    + " and object_type='FILE' and temporary=? and (bound_job_id is null or"
                    + " bound_job_id=?)",
                w.id,
                tempId,
                w.pid,
                Boolean.TRUE,
                w.id);
        if (n != 1)
          throw new ApiError(409, "FILE_BOUND", "Temporary file is already bound to another job");
        boundTemps.add(tempId);
      }
      s.db.update(
          "insert into jobs(id,project_id,user_id,tool_id,status,created_at,truncated)"
              + " values(?,?,?,?,?,?,?)",
          w.id,
          pid,
          uid,
          w.tool,
          "QUEUED",
          s.now(),
          false);
      active.put(w.id, w);
      try {
        pool.execute(() -> run(w));
      } catch (RejectedExecutionException e) {
        active.remove(w.id);
        s.db.update(
            "update jobs set status='FAILED',finished_at=?,error_text='Queue capacity reached'"
                + " where id=?",
            s.now(),
            w.id);
        throw new ApiError(429, "QUEUE_FULL", "Task queue full");
      }
    } catch (Exception e) {
      if (!active.containsKey(w.id)) {
        for (String tempId : boundTemps) {
          try {
            s.db.update(
                "update materials set bound_job_id=null where id=? and bound_job_id=?",
                tempId,
                w.id);
          } catch (Exception ignored) {
          }
        }
      }
      throw e;
    }
    s.audit(pid, uid, "SUBMIT_JOB", "JOB", w.id, "SUCCESS");
    return dto(pid, w.id);
  }

  Object resolve(Work w, JsonNode p, Object value) {
    if (value == null) throw ApiError.bad("Null parameter");
    String type = p.path("type").asText(), v = value.toString();
    if (type.equals("INPUT_FILE")) {
      Ref ref = reference(w.pid, v);
      var material = materials.raw(w.pid, ref.id);
      String kind = Store.str(material, "key_kind");
      boolean stateful = w.definition.path("stateful").asBoolean();
      if (ref.type.equals("KEY")) {
        boolean allowed = false;
        for (JsonNode k : p.path("allowedKeyKinds")) if (k.asText().equals(kind)) allowed = true;
        if (!allowed) throw ApiError.bad("Key kind is not accepted by parameter");
      }
      if (stateful && p.path("name").asText().equals("key")) {
        if (!ref.type.equals("KEY") || !"STATEFUL_PRIVATE_KEY".equals(kind))
          throw ApiError.bad("Stateful signing requires managed stateful key");
        ref = new Ref(ref.id, ref.type, true, false);
      } else if (ref.stateful)
        throw ApiError.bad("Stateful private key only accepted by stateful signing");
      String token = "i" + w.refs.size();
      w.refs.put(token, ref);
      w.sensitive |= ref.type.equals("KEY") && !"PUBLIC_KEY".equals(kind);
      return "input:" + token;
    }
    if (v.startsWith("key:")) {
      if (!type.equals("HEX") || !p.path("allowKeyReference").asBoolean())
        throw ApiError.bad("Key reference not supported");
      Ref ref = reference(w.pid, v);
      var m = materials.raw(w.pid, ref.id, "KEY");
      if (!"SYMMETRIC_KEY".equals(m.get("key_kind"))) throw ApiError.bad("Symmetric key required");
      byte[] bytes = materials.vault.read(w.pid, ref.id);
      v =
          switch (Store.str(m, "encoding")) {
            case "RAW" -> HexFormat.of().formatHex(bytes);
            case "HEX" -> new String(bytes, StandardCharsets.US_ASCII).trim();
            default -> throw ApiError.bad("Symmetric key encoding must be RAW or HEX");
          };
      w.sensitive = true;
    }
    if (type.equals("HEX") && !v.matches("(?:[a-fA-F0-9]{2})+"))
      throw ApiError.bad("Invalid HEX value");
    if (type.equals("OUTPUT_FILE") && !v.matches("[A-Za-z0-9][A-Za-z0-9_.-]{0,119}"))
      throw ApiError.bad("Invalid output filename");
    if (v.length() > 65536) throw ApiError.bad("Parameter too large");
    return type.equals("HEX") ? v : value;
  }

  Ref reference(String pid, String value) {
    if (!value.matches("(key|file):[0-9a-fA-F-]{36}"))
      throw ApiError.bad("Expected project material reference");
    String[] p = value.split(":", 2);
    String type = p[0].equals("key") ? "KEY" : "FILE";
    var m = materials.raw(pid, p[1], type);
    return new Ref(p[1], type, Store.bool(m, "stateful"), Store.bool(m, "temporary"));
  }

  void cleanupTemporaryFiles(String jobId) {
    var rows =
        s.rows(
            "select id, project_id from materials where bound_job_id=? and temporary=?", jobId, Boolean.TRUE);
    for (var row : rows) {
      String id = row.get("id").toString();
      try {
        materials.delete(row.get("project_id").toString(), id);
      } catch (Exception e) {
        System.err.println(
            "Temporary file cleanup retry for job "
                + jobId
                + ", file "
                + id
                + ": "
                + e.getMessage());
      }
    }
  }

  void run(Work w) {
    List<String> locked = new ArrayList<>();
    List<String> created = new ArrayList<>();
    try {
      executionPermission(w);
      synchronized (w) {
        if (w.cancelled) return;
        s.db.update(
            "update jobs set status='RUNNING',started_at=? where id=? and status='QUEUED'",
            s.now(),
            w.id);
      }
      Map<String, Object> inputs = new LinkedHashMap<>();
      long inputSize = 0;
      for (var e : w.refs.entrySet()) {
        Ref ref = e.getValue();
        if (ref.stateful) {
          if (locked.contains(ref.id)) throw ApiError.bad("Stateful key referenced twice");
          int n =
              s.db.update(
                  "update materials set pending=? where id=? and project_id=? and"
                      + " object_type='KEY' and key_kind='STATEFUL_PRIVATE_KEY' and pending=?",
                  Boolean.TRUE,
                  ref.id,
                  w.pid,
                  Boolean.FALSE);
          if (n != 1)
            throw new ApiError(409, "KEY_PENDING", "Stateful key is busy or requires recovery");
          locked.add(ref.id);
        }
        var mat = materials.raw(w.pid, ref.id, ref.type);
        byte[] bytes = materials.vault.read(w.pid, ref.id);
        inputSize += bytes.length;
        if (inputSize + (w.stdin == null ? 0 : w.stdin.length) > Vault.LIMIT)
          throw ApiError.bad("Total input too large");
        inputs.put(
            e.getKey(),
            Map.of(
                "name",
                mat.get("name"),
                "contentBase64",
                Base64.getEncoder().encodeToString(bytes)));
      }
      Map<String, Object> request = new LinkedHashMap<>();
      request.put("id", w.id);
      request.put("toolId", w.tool);
      request.put("parameters", w.params);
      request.put("inputs", inputs);
      request.put("timeoutSeconds", w.timeout);
      if (w.stdin != null) request.put("stdinBase64", Base64.getEncoder().encodeToString(w.stdin));
      synchronized (w) {
        if (w.cancelled) {
          finish(w, "CANCELLED", null, 0, "Task cancelled", null, null, false);
          return;
        }
      }
      JsonNode result = engine.request("POST", "/executions", request, w.timeout + 15);
      if (!result.path("id").asText().equals(w.id))
        throw new IllegalStateException("Execution identity mismatch");
      String status = result.path("status").asText();
      if (!Set.of("SUCCEEDED", "FAILED", "CANCELLED", "TIMED_OUT").contains(status))
        throw new IllegalStateException("Invalid execution status");
      Map<String, byte[]> updates = new LinkedHashMap<>();
      for (JsonNode u : result.path("updatedInputs")) {
        String token = u.path("token").asText();
        Ref ref = w.refs.get(token);
        if (ref == null
            || !ref.stateful
            || updates.putIfAbsent(ref.id, decode(u.path("contentBase64").asText())) != null)
          throw new IllegalStateException("Unexpected input update");
      }
      synchronized (w) {
        if (status.equals("SUCCEEDED") && !w.cancelled) {
          if (!updates.keySet().equals(new HashSet<>(locked)))
            throw new IllegalStateException("Missing stateful key update");
          for (var en : updates.entrySet()) {
            if (Arrays.equals(materials.vault.read(w.pid, en.getKey()), en.getValue()))
              throw new IllegalStateException("Stateful input did not advance");
            materials.registerState(en.getKey(), en.getValue());
            materials.vault.write(w.pid, en.getKey(), en.getValue(), true);
          }
          long output = 0;
          boolean sensitive =
              w.sensitive
                  || w.definition.path("sensitiveOutput").asBoolean()
                  || STATEFUL_GENERATORS.containsKey(w.tool);
          for (JsonNode a : result.path("artifacts")) {
            byte[] bytes = decode(a.path("contentBase64").asText());
            output += bytes.length;
            if (output > Vault.LIMIT) throw new IllegalStateException();
            String id =
                artifact(
                    w,
                    a.path("name").asText("output"),
                    a.path("mediaType").asText("application/octet-stream"),
                    bytes,
                    sensitive);
            created.add(id);
          }
          byte[] stdout = decode(result.path("stdoutBase64").asText(""));
          output += stdout.length;
          if (output > Vault.LIMIT) throw new IllegalStateException();
          if (stdout.length > 0)
            created.add(
                artifact(
                    w,
                    w.definition.path("stdoutFilename").asText("stdout.txt"),
                    w.definition.path("stdoutMediaType").asText("text/plain"),
                    stdout,
                    sensitive,
                    true));
          String preview = sensitive ? null : new String(stdout, StandardCharsets.UTF_8);
          tx.executeWithoutResult(
              t -> {
                for (var en : updates.entrySet())
                  s.db.update(
                      "update materials set pending=?,byte_size=?,updated_at=? where"
                          + " project_id=? and id=? and pending=?",
                      Boolean.FALSE,
                      en.getValue().length,
                      s.now(),
                      w.pid,
                      en.getKey(),
                      Boolean.TRUE);
                finish(
                    w,
                    status,
                    result.path("exitCode").isNull() ? null : result.path("exitCode").asInt(),
                    result.path("durationMs").asLong(),
                    null,
                    preview,
                    null,
                    result.path("truncated").asBoolean());
              });
        } else
          finish(
              w,
              w.cancelled ? "CANCELLED" : status,
              result.path("exitCode").isNull() ? null : result.path("exitCode").asInt(),
              result.path("durationMs").asLong(),
              "Engine execution did not succeed",
              null,
              result.path("stderr").isTextual() ? result.path("stderr").asText() : null,
              result.path("truncated").asBoolean());
      }
    } catch (Exception e) {
      for (String id : created)
        try {
          materials.delete(w.pid, id);
        } catch (Exception ignored) {
        }
      finish(
          w,
          w.cancelled ? "CANCELLED" : "FAILED",
          null,
          0,
          e instanceof ApiError ae
              ? ae.getMessage()
              : "Execution result could not be safely committed",
          null,
          null,
          false);
    } finally {
      active.remove(w.id);
      w.params = null;
      w.stdin = null;
      cleanupTemporaryFiles(w.id);
    }
  }

  void executionPermission(Work w) {
    var u = s.one("select role,enabled from app_users where id=?", w.uid);
    if (!Store.bool(u, "enabled")) throw ApiError.denied();
    boolean admin = "ADMIN".equals(u.get("role"));
    if ((w.definition.path("adminOnly").asBoolean()
            || w.definition.path("category").asText().equals("protocol"))
        && !admin) throw ApiError.denied();
    if (!admin
        && s.rows(
                "select role from memberships where project_id=? and user_id=? and role in"
                    + " ('OWNER','EDITOR')",
                w.pid,
                w.uid)
            .isEmpty()) throw ApiError.denied();
  }

  byte[] decode(String b64) {
    if (b64.length() > ((Vault.LIMIT + 2) / 3) * 4) throw ApiError.bad("Engine output too large");
    byte[] b = Base64.getDecoder().decode(b64);
    if (b.length > Vault.LIMIT) throw ApiError.bad("Engine output too large");
    return b;
  }

  String artifact(Work w, String name, String media, byte[] bytes, boolean sensitive) {
    return artifact(w, name, media, bytes, sensitive, false);
  }

  String artifact(
      Work w, String name, String media, byte[] bytes, boolean sensitive, boolean stdout) {
    var m =
        materials.create(
            w.pid, "ARTIFACT", name, AccountController.bounded(media, 120, true), bytes, Map.of());
    String id = m.get("id").toString();
    try {
      boolean restricted =
          STATEFUL_GENERATORS.containsKey(w.tool)
              && (stdout || !name.equals(Objects.toString(w.params.get("pubout"), "")));
      boolean source =
          STATEFUL_GENERATORS.containsKey(w.tool) && !stdout && name.equals(w.params.get("out"));
      s.db.update(
          "insert into artifacts values(?,?,?,?,?)", id, w.id, sensitive, restricted, source);
    } catch (RuntimeException e) {
      materials.delete(w.pid, id);
      throw e;
    }
    return id;
  }

  void finish(
      Work w,
      String status,
      Integer exit,
      long duration,
      String error,
      String preview,
      String stderrPreview,
      boolean truncated) {
    String p = preview == null ? null : preview.substring(0, Math.min(7900, preview.length()));
    String errP = sanitizeStderr(stderrPreview);
    s.db.update(
        "update jobs set"
            + " status=?,finished_at=?,exit_code=?,duration_ms=?,error_text=?,stdout_preview=?,stderr_preview=?,truncated=?"
            + " where id=?",
        status,
        s.now(),
        exit,
        duration,
        error,
        p,
        errP,
        truncated || (preview != null && preview.length() > 7900) || (stderrPreview != null && stderrPreview.length() > 7900),
        w.id);
    cleanupTemporaryFiles(w.id);
    s.audit(w.pid, w.uid, "JOB_" + status, "JOB", w.id, status);
  }

  static String sanitizeStderr(String stderr) {
    if (stderr == null || stderr.isBlank()) return null;
    String clean = stderr.replaceAll("[\\p{Cntrl}&&[^\\n\\t]]", "?");
    return clean.substring(0, Math.min(7900, clean.length()));
  }

  Object cancel(String pid, String id, HttpServletRequest req) {
    auth.project(req, pid, 2);
    dto(pid, id);
    Work w = active.get(id);
    if (w == null) return dto(pid, id);
    boolean running;
    synchronized (w) {
      String status = s.one("select status from jobs where id=?", id).get("status").toString();
      if (!Set.of("QUEUED", "RUNNING").contains(status)) return dto(pid, id);
      w.cancelled = true;
      running = status.equals("RUNNING");
      if (!running) {
        finish(w, "CANCELLED", null, 0, "Task cancelled", null, null, false);
        cleanupTemporaryFiles(w.id);
      }
    }
    if (running) {
      ApiError failure = null;
      for (int attempt = 0; attempt < 5; attempt++) {
        try {
          engine.request("POST", "/executions/" + id + "/cancel", Map.of(), 10);
          failure = null;
          break;
        } catch (ApiError e) {
          failure = e;
          if (!active.containsKey(id)) {
            failure = null;
            break;
          }
          try {
            Thread.sleep(50);
          } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            break;
          }
        }
      }
      if (failure != null) throw failure;
    }
    s.audit(pid, auth.uid(req), "CANCEL_JOB", "JOB", id, "REQUESTED");
    return dto(pid, id);
  }
}