package org.gmssl.gui.platform;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.servlet.http.HttpServletRequest;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Pattern;
import org.springframework.stereotype.Service;

@Service
public class CertificateWorkflowService {
  private final Jobs jobs;
  private final Materials materials;
  private final Store store;
  private final Vault vault;
  private final KeyGenerationService keyGenerationService;
  private final CredentialService credentialService;
  private final Auth auth;
  private final java.util.concurrent.Semaphore workflowSlots = new java.util.concurrent.Semaphore(4);
  private long workflowTimeoutMillis = 120_000;
  private final ThreadLocal<Run> currentRun = new ThreadLocal<>();
  private static final class Run {
    final long deadline;
    Run(long millis) { deadline = System.nanoTime() + java.util.concurrent.TimeUnit.MILLISECONDS.toNanos(millis); }
    CertificateWorkflowRequest request;
    final Map<String, Map<String,Object>> certificateInputs = new HashMap<>();
    final Map<String, byte[]> publicKeys = new HashMap<>();
    final Set<String> temporary = new LinkedHashSet<>();
    final Set<String> jobs = new LinkedHashSet<>();
    long remainingMillis() { return java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(deadline - System.nanoTime()); }
  }
  private void checkBudget() {
    Run run = currentRun.get();
    if (run != null && (run.remainingMillis() <= 0 || Thread.currentThread().isInterrupted()))
      throw new WorkflowException("deadline", null, "Workflow execution budget exhausted");
  }

  private static final Pattern DNS_PATTERN =
      Pattern.compile(
          "^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,}$|^localhost$|^\\*\\.(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,}$");
  private static final Pattern IPV4_PATTERN =
      Pattern.compile("^(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(?:\\.(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}$");
  private static final Pattern IPV6_PATTERN = Pattern.compile("^[0-9a-fA-F:]+$");
  private static final Pattern REF_PATTERN = Pattern.compile("^(key|file):[0-9a-fA-F-]{36}$");

  public CertificateWorkflowService(
      Jobs jobs,
      Materials materials,
      Store store,
      Vault vault,
      KeyGenerationService keyGenerationService,
      CredentialService credentialService,
      Auth auth) {
    this.jobs = jobs;
    this.materials = materials;
    this.store = store;
    this.vault = vault;
    this.keyGenerationService = keyGenerationService;
    this.credentialService = credentialService;
    this.auth = auth;
  }

  @JsonIgnoreProperties(ignoreUnknown = true)
  public record CertificateSubject(
      String CN,
      String C,
      String ST,
      String L,
      String O,
      String OU
  ) {}

  @JsonIgnoreProperties(ignoreUnknown = true)
  public record CertificateWorkflowRequest(
      String profile,
      String name,
      CertificateSubject subject,
      List<String> sanDns,
      List<String> sanIps,
      Integer days,
      String provider,
      String keyRef,
      String keyPassword,
      String issuerCertRef,
      String issuerKeyRef,
      String issuerPassword,
      String csrRef,
      String purpose,
      Map<String, Object> advanced
  ) {}

  public record WorkflowStage(
      String name,
      String jobId,
      String status
  ) {}

  public record CertificateWorkflowResponse(
      String workflowId,
      String status,
      List<WorkflowStage> stages,
      List<Map<String, Object>> keys,
      List<Map<String, Object>> files,
      List<Map<String, Object>> artifacts,
      List<String> warnings,
      String error
  ) {}

  public static class WorkflowException extends RuntimeException {
    final String stage;
    final String jobId;

    public WorkflowException(String stage, String jobId, String message) {
      super(message);
      this.stage = stage;
      this.jobId = jobId;
    }
  }

  public CertificateWorkflowResponse execute(
      String pid, CertificateWorkflowRequest req, HttpServletRequest httpReq) {
    String workflowId = store.id();
    String uid = auth.uid(httpReq);
    validateRequest(pid, req);

    List<WorkflowStage> stages = new ArrayList<>();
    List<Map<String, Object>> keys = new ArrayList<>();
    List<Map<String, Object>> files = new ArrayList<>();
    List<Map<String, Object>> artifacts = new ArrayList<>();
    List<String> warnings = new ArrayList<>();



    String profile = req.profile().toUpperCase(Locale.ROOT).trim();
    if ((req.sanIps() != null && !req.sanIps().isEmpty()) ||
        ("CSR".equals(profile) && req.sanDns() != null && !req.sanDns().isEmpty())) {
      var catalog = jobs.engine.catalog();
      String tool = "CSR".equals(profile) ? "reqgen" :
          (Set.of("CA_SIGN", "INTERMEDIATE_CA", "TLCP", "QUICK_ISSUE").contains(profile) ? "reqsign" : "certgen");
      for (String parameter : List.of("subject_ip", "subject_dns_name")) {
        if ("subject_ip".equals(parameter) && (req.sanIps() == null || req.sanIps().isEmpty())) continue;
        if ("subject_dns_name".equals(parameter) && (req.sanDns() == null || req.sanDns().isEmpty())) continue;
        boolean supported = false;
        for (var t : catalog.path("tools")) if (tool.equals(t.path("id").asText()))
          for (var def : t.path("parameters")) if (parameter.equals(def.path("name").asText())) supported = true;
        if (!supported) throw ApiError.bad("Native tool " + tool + " lacks required SAN capability " + parameter);
      }
    }
    String status = "SUCCEEDED";
    String error = null;

    if (!workflowSlots.tryAcquire()) throw new ApiError(429, "WORKFLOW_BUSY", "Certificate workflow capacity reached");
    Run run = new Run(workflowTimeoutMillis);
    run.request = req;
    currentRun.set(run);
    try {
      switch (profile) {
        case "ROOT_CA" -> executeRootCa(pid, uid, req, httpReq, stages, keys, files, artifacts, warnings);
        case "SELF_SIGNED" -> executeSelfSigned(pid, uid, req, httpReq, stages, keys, files, artifacts, warnings);
        case "INTERMEDIATE_CA" -> executeIntermediateCa(pid, uid, req, httpReq, stages, keys, files, artifacts, warnings);
        case "CSR" -> executeCsr(pid, uid, req, httpReq, stages, keys, files, artifacts, warnings);
        case "CA_SIGN", "QUICK_ISSUE" -> executeCaSign(pid, uid, req, httpReq, stages, keys, files, artifacts, warnings);
        case "TLCP" -> executeTlcp(pid, uid, req, httpReq, stages, keys, files, artifacts, warnings);
        default -> throw ApiError.bad("Unsupported certificate profile: " + profile);
      }
      inspectOutputs(pid, req, httpReq, stages, files, artifacts);
      checkBudget();
    } catch (WorkflowException e) {
      status = "FAILED";
      error = "[" + e.stage + "] " + e.getMessage();
    } catch (ApiError e) {
      status = "FAILED";
      error = e.getMessage();
    } catch (Exception e) {
      status = "FAILED";
      error = "Certificate workflow failed; consult workflow stages and workflowId";
    }

    try {
      if ("FAILED".equals(status)) {
        for (String jobId : run.jobs) {
          try { jobs.cancel(pid, jobId, httpReq); }
          catch (Exception ignored) { warnings.add("Cancellation pending for job " + jobId); }
        }
        warnings.add("Earlier successful materials are retained; workflow did not complete");
      }
    } finally {
      for (String id : run.temporary) {
        try { materials.delete(pid, id); } catch (Exception ignored) { warnings.add("Cleanup pending for material " + id); }
      }
      currentRun.remove();
      workflowSlots.release();
    }
    store.audit(pid, uid, "CERTIFICATE_WORKFLOW", "WORKFLOW", workflowId, status);

    return new CertificateWorkflowResponse(
        workflowId,
        status,
        stages,
        keys,
        files,
        artifacts,
        warnings,
        error);
  }

  private void validateRequest(String pid, CertificateWorkflowRequest req) {
    if (req == null) throw ApiError.bad("Request body is required");
    if (req.profile() == null || req.profile().isBlank()) {
      throw ApiError.bad("Profile is required");
    }
    String p = req.profile().toUpperCase().trim();
    if (!Set.of("SELF_SIGNED", "ROOT_CA", "INTERMEDIATE_CA", "CSR", "CA_SIGN", "TLCP", "QUICK_ISSUE").contains(p)) {
      throw ApiError.bad("Unknown certificate profile: " + req.profile());
    }

    if (req.name() == null || req.name().isBlank()) {
      throw ApiError.bad("Workflow name is required");
    }
    if (req.name().length() > 200) {
      throw ApiError.bad("Workflow name too long (max 200 chars)");
    }

    boolean requiresSubject = !("CA_SIGN".equals(p) && req.csrRef() != null && !req.csrRef().isBlank());
    if (requiresSubject) {
      if (req.subject() == null) {
        throw ApiError.bad("Certificate subject is required");
      }
      if (req.subject().CN() == null || req.subject().CN().isBlank()) {
        throw ApiError.bad("Subject Common Name (CN) is required");
      }
      if (req.subject().CN().length() > 128) {
        throw ApiError.bad("Subject Common Name (CN) too long (max 128 chars)");
      }
    } else {
      if (req.subject() != null && req.subject().CN() != null && req.subject().CN().length() > 128) {
        throw ApiError.bad("Subject Common Name (CN) too long (max 128 chars)");
      }
    }

    if (req.days() != null && (req.days() < 1 || req.days() > 36500)) {
      throw ApiError.bad("Validity days must be between 1 and 36500");
    }

    if ((req.sanDns() == null ? 0 : req.sanDns().size()) + (req.sanIps() == null ? 0 : req.sanIps().size()) > 64)
      throw ApiError.bad("At most 64 SAN entries are supported");
    if (req.sanDns() != null) {
      for (String dns : req.sanDns()) {
        String trimmed = dns == null ? "" : dns;
        if (trimmed.isEmpty() || trimmed.length() > 253 || !DNS_PATTERN.matcher(trimmed).matches()) {
          throw ApiError.bad("Invalid SAN DNS name: " + dns);
        }
      }
    }

    if (req.sanIps() != null) {
      for (String ip : req.sanIps()) {
        String trimmed = ip == null ? "" : ip;
        boolean isV4 = IPV4_PATTERN.matcher(trimmed).matches();
        boolean isV6 = validIpv6(trimmed);
        if (!isV4 && !isV6) {
          throw ApiError.bad("Invalid SAN IP address: " + ip);
        }
      }
    }

    if (req.purpose() != null && !Set.of("SERVER", "CLIENT", "SIGNING").contains(req.purpose().toUpperCase(Locale.ROOT)))
      throw ApiError.bad("Invalid certificate purpose");
    if (req.advanced() != null && req.advanced().get("sm2Id") != null) {
      String id = req.advanced().get("sm2Id").toString();
      if (id.isEmpty() || id.length() > 128 || !id.matches("[ -~]+"))
        throw ApiError.bad("SM2 ID must be 1..128 printable ASCII characters");
    }
    if (req.keyRef() != null && !req.keyRef().isBlank()) {
      validateReference(pid, req.keyRef(), "key", "KEY", "PRIVATE_KEY");
    }
    if (req.issuerCertRef() != null && !req.issuerCertRef().isBlank()) {
      validateReference(pid, req.issuerCertRef(), "file", "FILE", null);
    }
    if (req.issuerKeyRef() != null && !req.issuerKeyRef().isBlank()) {
      validateReference(pid, req.issuerKeyRef(), "key", "KEY", "PRIVATE_KEY");
    }
    if (req.csrRef() != null && !req.csrRef().isBlank()) {
      validateReference(pid, req.csrRef(), "file", "FILE", null);
      byte[] csrBytes = vault.read(pid, parseId(req.csrRef()));
      try {
        byte[] csrDer = decodePem(csrBytes, "CERTIFICATE REQUEST");
        Der csr = Der.read(csrDer, 0, csrDer.length);
        if (csr.tag != 48 || csr.end != csrDer.length || csr.children().size() != 3) {
          throw new IllegalArgumentException();
        }
      } catch (Exception e) {
        throw ApiError.bad("待签发 CSR 材料无效：必须包含 -----BEGIN CERTIFICATE REQUEST----- 的合规 CSR 请求文件");
      }
    }

    if ("INTERMEDIATE_CA".equals(p) || "CA_SIGN".equals(p) || "QUICK_ISSUE".equals(p)) {
      if (req.issuerCertRef() == null || req.issuerCertRef().isBlank()) {
        throw ApiError.bad("Profile " + p + " requires issuerCertRef");
      }
      if (req.issuerKeyRef() == null || req.issuerKeyRef().isBlank()) {
        throw ApiError.bad("Profile " + p + " requires issuerKeyRef");
      }
    }

    if (req.issuerCertRef() != null && !req.issuerCertRef().isBlank()) {
      Cert issuer;
      try { issuer = new Cert(vault.read(pid, parseId(req.issuerCertRef()))); }
      catch (Exception e) { throw ApiError.bad("颁发者证书无效：必须是合法的 SM2 X.509 证书文件"); }
      if (!issuer.ca || !issuer.usage(5)) throw ApiError.bad("颁发者必须具备 CA 资质且包含 keyCertSign 证书签名用途");
      java.time.Instant now = java.time.Instant.now();
      if (now.isBefore(issuer.before) || !now.isBefore(issuer.after))
        throw ApiError.bad("颁发者证书不在有效期内，已过期或尚未生效");
      int requestedDays = req.days() != null ? req.days() : ("INTERMEDIATE_CA".equals(p) ? 1825 : 365);
      java.time.Instant targetExpiry = now.plus(java.time.Duration.ofDays(requestedDays));
      if (targetExpiry.isAfter(issuer.after))
        throw ApiError.bad("申请证书有效期超出颁发者 CA 证书剩余有效期");
      if ("INTERMEDIATE_CA".equals(p) && issuer.pathLen != null && issuer.pathLen == 0)
        throw ApiError.bad("颁发者 CA 证书的 pathLenConstraint 限制禁止签发下级 CA");
    }
    if (req.advanced() != null) {
      for (String key : req.advanced().keySet()) {
        if (!Set.of("pathLenConstraint", "sm2Id", "serialLen").contains(key)) {
          throw ApiError.bad("Unauthorized advanced option: " + key);
        }
      }
      if (req.advanced().containsKey("pathLenConstraint")) {
        try {
          int plc = Integer.parseInt(req.advanced().get("pathLenConstraint").toString());
          if (plc < 0 || plc > 10) throw new IllegalArgumentException();
        } catch (Exception e) {
          throw ApiError.bad("pathLenConstraint must be an integer between 0 and 10");
        }
      }
      if (req.advanced().containsKey("serialLen")) {
        try {
          int sl = Integer.parseInt(req.advanced().get("serialLen").toString());
          if (sl < 1 || sl > 20) throw new IllegalArgumentException();
        } catch (Exception e) {
          throw ApiError.bad("serialLen must be an integer between 1 and 20");
        }
      }
    }
  }

  private void validateReference(
      String pid, String ref, String prefix, String expectedType, String expectedKind) {
    if (!REF_PATTERN.matcher(ref).matches() || !ref.startsWith(prefix + ":")) {
      throw ApiError.bad("Invalid reference format: " + ref);
    }
    String id = parseId(ref);
    Map<String, Object> mat;
    try {
      mat = materials.raw(pid, id, expectedType);
    } catch (Exception e) {
      throw ApiError.bad("Referenced " + prefix + " not found in current project: " + ref);
    }
    if ("KEY".equals(expectedType) && !"SM2".equalsIgnoreCase(String.valueOf(mat.get("algorithm"))))
      throw ApiError.bad("Certificate workflows require an SM2 key");
    if (expectedKind != null && !expectedKind.equals(mat.get("key_kind"))) {
      throw ApiError.bad("Referenced key must be of kind " + expectedKind + ": " + ref);
    }
  }

  private static String parseId(String ref) {
    if (ref == null) return null;
    int idx = ref.indexOf(':');
    return idx >= 0 ? ref.substring(idx + 1) : ref;
  }

  private String resolvePrivateKeyPassword(String pid, String keyRef, String explicitPass) {
    if (explicitPass != null && !explicitPass.isBlank()) {
      return explicitPass;
    }
    String keyId = parseId(keyRef);
    String managed = credentialService.getPassphrase(pid, keyId);
    if (managed != null && !managed.isBlank()) {
      return managed;
    }
    throw ApiError.bad("Private key password required for " + keyRef);
  }

  private Map<String, Object> buildSubjectParams(CertificateSubject sub) {
    Map<String, Object> p = new LinkedHashMap<>();
    if (sub == null) return p;
    if (sub.CN() != null && !sub.CN().isBlank()) p.put("CN", sub.CN().trim());
    if (sub.C() != null && !sub.C().isBlank()) p.put("C", sub.C().trim());
    if (sub.ST() != null && !sub.ST().isBlank()) p.put("ST", sub.ST().trim());
    if (sub.L() != null && !sub.L().isBlank()) p.put("L", sub.L().trim());
    if (sub.O() != null && !sub.O().isBlank()) p.put("O", sub.O().trim());
    if (sub.OU() != null && !sub.OU().isBlank()) p.put("OU", sub.OU().trim());
    return p;
  }

  private int resolveSerialLen(Map<String, Object> adv) {
    if (adv != null && adv.containsKey("serialLen")) {
      try {
        return Integer.parseInt(adv.get("serialLen").toString());
      } catch (Exception ignored) {}
    }
    return 16;
  }

  private Map<String, Object> generateKey(String pid, String uid, Map<String, Object> body) {
    checkBudget();
    long remaining = currentRun.get().remainingMillis();
    if (remaining < 1000) throw new WorkflowException("deadline", null, "Workflow execution budget exhausted");
    var result = keyGenerationService.generateWithTimeout(pid, uid, body, (int)Math.min(30, remaining / 1000));
    if (result.get("publicKey") instanceof Map<?, ?> publicKey) {
      currentRun.get().publicKeys.put(result.get("reference").toString(), vault.read(pid, publicKey.get("id").toString()));
      if (result.get("key") instanceof Map<?, ?> privateKey) {
        Map<String,Object> key = new LinkedHashMap<>();
        privateKey.forEach((k,v) -> key.put(k.toString(), v));
        key.put("publicKey", publicKey);
        result = new LinkedHashMap<>(result);
        result.put("key", key);
      }
    }
    checkBudget();
    return result;
  }

  static boolean validIpv6(String ip) {
    if (ip == null || !ip.contains(":") || ip.length() > 45 || !ip.matches("[0-9a-fA-F:.]+")) return false;
    try { return java.net.InetAddress.getByName(ip).getAddress().length == 16; }
    catch (java.net.UnknownHostException e) { return false; }
  }

  private String saveFile(
      String pid,
      String filename,
      String mediaType,
      byte[] content,
      List<Map<String, Object>> files) {
    checkBudget();
    var fileMaterial = materials.create(pid, "FILE", filename, mediaType, content, Map.of("temporary", "false"));
    var dto = fileMaterial;
    files.add(dto);
    return "file:" + dto.get("id");
  }

  private byte[] getArtifactBytes(String pid, Map<String, Object> jobDto, String expectedName) {
    Object artsObj = jobDto.get("artifacts");
    if (artsObj instanceof List<?> arts) {
      for (Object item : arts) {
        if (item instanceof Map<?, ?> m) {
          if (expectedName.equals(m.get("name"))) {
            return vault.read(pid, m.get("id").toString());
          }
        }
      }
      if (!arts.isEmpty() && arts.getFirst() instanceof Map<?, ?> first) {
        return vault.read(pid, first.get("id").toString());
      }
    }
    throw new IllegalStateException("Artifact " + expectedName + " not found in job output");
  }

  private Map<String, Object> runJob(
      String pid,
      String stageName,
      String toolId,
      Map<String, Object> parameters,
      HttpServletRequest req,
      List<WorkflowStage> stages,
      List<Map<String, Object>> artifactsOut) {
    checkBudget();
    if (Set.of("certgen", "reqgen", "reqsign").contains(toolId)) {
      CertificateWorkflowRequest input = currentRun.get().request;
      if (input.sanDns() != null && !input.sanDns().isEmpty()) parameters.put("subject_dns_name", input.sanDns());
      if (input.sanIps() != null && !input.sanIps().isEmpty()) parameters.put("subject_ip", input.sanIps());
    }
    Map<String, Object> jobBody = new LinkedHashMap<>();
    jobBody.put("toolId", toolId);
    jobBody.put("parameters", parameters);
    jobBody.put("timeoutSeconds", Math.max(1, Math.min(30, currentRun.get().remainingMillis() / 1000)));

    if (Set.of("certgen", "reqsign").contains(toolId))
      currentRun.get().certificateInputs.put(parameters.get("out").toString(), new LinkedHashMap<>(parameters));
    Map<String, Object> submitted;
    try { submitted = jobs.submit(pid, jobBody, req); }
    catch (Exception e) {
      stages.add(new WorkflowStage(stageName, null, "FAILED"));
      throw new WorkflowException(stageName, null, "Job submission failed");
    }
    String jobId = (String) submitted.get("id");

    currentRun.get().jobs.add(jobId);
    long deadline = System.currentTimeMillis() + Math.min(30_000, currentRun.get().remainingMillis());
    while (System.currentTimeMillis() < deadline) {
      Map<String, Object> current = jobs.dto(pid, jobId);
      String status = (String) current.get("status");
      if ("SUCCEEDED".equals(status)) {
        currentRun.get().jobs.remove(jobId);
        stages.add(new WorkflowStage(stageName, jobId, "SUCCEEDED"));
        if (current.get("artifacts") instanceof List<?> arts) {
          for (Object art : arts) {
            if (art instanceof Map<?, ?> artMap) {
              artifactsOut.add((Map<String, Object>) artMap);
            }
          }
        }
        return current;
      }
      if ("FAILED".equals(status) || "CANCELLED".equals(status) || "TIMED_OUT".equals(status)) {
        stages.add(new WorkflowStage(stageName, jobId, "FAILED"));
        currentRun.get().jobs.remove(jobId);
        String err = (String) current.get("error");
        throw new WorkflowException(stageName, jobId, err != null ? err : ("Job " + status));
      }
      try {
        Thread.sleep(30);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        stages.add(new WorkflowStage(stageName, jobId, "FAILED"));
        throw new WorkflowException(stageName, jobId, "Workflow execution interrupted");
      }
    }
    stages.add(new WorkflowStage(stageName, jobId, "FAILED"));
    throw new WorkflowException(stageName, jobId, "Job execution timed out");
  }

  // 1. ROOT_CA
  private void executeRootCa(
      String pid,
      String uid,
      CertificateWorkflowRequest req,
      HttpServletRequest httpReq,
      List<WorkflowStage> stages,
      List<Map<String, Object>> keys,
      List<Map<String, Object>> files,
      List<Map<String, Object>> artifacts,
      List<String> warnings) {
    String keyRef = req.keyRef();
    String keyPass;
    if (keyRef == null || keyRef.isBlank()) {
      var genRes =
          generateKey(
              pid,
              uid,
              Map.of(
                  "algorithm", "SM2",
                  "storage", "MANAGED",
                  "name", req.name() + "-root-key",
                  "provider", req.provider() != null ? req.provider() : "gmssl"));
      keyRef = (String) genRes.get("reference");
      keys.add((Map<String, Object>) genRes.get("key"));
      keyPass = credentialService.getPassphrase(pid, parseId(keyRef));
      stages.add(new WorkflowStage("generate_key", null, "SUCCEEDED"));
    } else {
      keyPass = resolvePrivateKeyPassword(pid, keyRef, req.keyPassword() != null ? req.keyPassword() : req.issuerPassword());
    }

    int days = req.days() != null ? req.days() : 3650;
    String outFileName = req.name() + "_root_ca.pem";

    Map<String, Object> certParams = buildSubjectParams(req.subject());
    certParams.put("days", days);
    certParams.put("key", keyRef);
    certParams.put("pass", keyPass);
    certParams.put("ca", true);
    certParams.put("key_usage", List.of("keyCertSign", "cRLSign"));
    certParams.put("serial_len", resolveSerialLen(req.advanced()));
    certParams.put("out", outFileName);

    if (req.advanced() != null && req.advanced().get("sm2Id") != null) {
      certParams.put("sm2_id", req.advanced().get("sm2Id").toString());
    }

    var certJob = runJob(pid, "generate_root_ca", "certgen", certParams, httpReq, stages, artifacts);
    byte[] certBytes = getArtifactBytes(pid, certJob, outFileName);

    String certRef = saveFile(pid, outFileName, "application/x-x509-ca-cert", certBytes, files);

    runJob(
        pid,
        "parse_certificate",
        "certparse",
        Map.of("in", certRef, "out", "certparse.txt"),
        httpReq,
        stages,
        artifacts);
  }

  // 2. SELF_SIGNED
  private void executeSelfSigned(
      String pid,
      String uid,
      CertificateWorkflowRequest req,
      HttpServletRequest httpReq,
      List<WorkflowStage> stages,
      List<Map<String, Object>> keys,
      List<Map<String, Object>> files,
      List<Map<String, Object>> artifacts,
      List<String> warnings) {
    String keyRef = req.keyRef();
    String keyPass;
    if (keyRef == null || keyRef.isBlank()) {
      var genRes =
          generateKey(
              pid,
              uid,
              Map.of(
                  "algorithm", "SM2",
                  "storage", "MANAGED",
                  "name", req.name() + "-key",
                  "provider", req.provider() != null ? req.provider() : "gmssl"));
      keyRef = (String) genRes.get("reference");
      keys.add((Map<String, Object>) genRes.get("key"));
      keyPass = credentialService.getPassphrase(pid, parseId(keyRef));
      stages.add(new WorkflowStage("generate_key", null, "SUCCEEDED"));
    } else {
      keyPass = resolvePrivateKeyPassword(pid, keyRef, req.keyPassword() != null ? req.keyPassword() : req.issuerPassword());
    }

    int days = req.days() != null ? req.days() : 365;
    String purpose = req.purpose() != null ? req.purpose().toUpperCase().trim() : "SERVER";
    List<String> keyUsages;
    List<String> extKeyUsages;

    switch (purpose) {
      case "CLIENT" -> {
        keyUsages = List.of("digitalSignature");
        extKeyUsages = List.of("clientAuth");
      }
      case "SIGNING" -> {
        keyUsages = List.of("digitalSignature", "nonRepudiation");
        extKeyUsages = List.of("codeSigning");
      }
      default -> {
        keyUsages = List.of("digitalSignature", "keyEncipherment");
        extKeyUsages = List.of("serverAuth");
      }
    }

    String outFileName = req.name() + "_cert.pem";
    Map<String, Object> certParams = buildSubjectParams(req.subject());
    certParams.put("days", days);
    certParams.put("key", keyRef);
    certParams.put("pass", keyPass);
    certParams.put("ca", false);
    certParams.put("key_usage", keyUsages);
    certParams.put("ext_key_usage", extKeyUsages);
    certParams.put("serial_len", resolveSerialLen(req.advanced()));
    certParams.put("out", outFileName);

    if (req.sanDns() != null && !req.sanDns().isEmpty()) {
      certParams.put("subject_dns_name", req.sanDns());
    }
    if (req.advanced() != null && req.advanced().get("sm2Id") != null) {
      certParams.put("sm2_id", req.advanced().get("sm2Id").toString());
    }

    var certJob = runJob(pid, "generate_certificate", "certgen", certParams, httpReq, stages, artifacts);
    byte[] certBytes = getArtifactBytes(pid, certJob, outFileName);

    String certRef = saveFile(pid, outFileName, "application/x-x509-ca-cert", certBytes, files);

    runJob(
        pid,
        "parse_certificate",
        "certparse",
        Map.of("in", certRef, "out", "certparse.txt"),
        httpReq,
        stages,
        artifacts);
  }

  // 3. INTERMEDIATE_CA
  private void executeIntermediateCa(
      String pid,
      String uid,
      CertificateWorkflowRequest req,
      HttpServletRequest httpReq,
      List<WorkflowStage> stages,
      List<Map<String, Object>> keys,
      List<Map<String, Object>> files,
      List<Map<String, Object>> artifacts,
      List<String> warnings) {
    String issuerPass = resolvePrivateKeyPassword(pid, req.issuerKeyRef(), req.issuerPassword());

    String keyRef = req.keyRef();
    String keyPass;
    if (keyRef == null || keyRef.isBlank()) {
      var genRes =
          generateKey(
              pid,
              uid,
              Map.of(
                  "algorithm", "SM2",
                  "storage", "MANAGED",
                  "name", req.name() + "-intermediate-key",
                  "provider", req.provider() != null ? req.provider() : "gmssl"));
      keyRef = (String) genRes.get("reference");
      keys.add((Map<String, Object>) genRes.get("key"));
      keyPass = credentialService.getPassphrase(pid, parseId(keyRef));
      stages.add(new WorkflowStage("generate_key", null, "SUCCEEDED"));
    } else {
      keyPass = resolvePrivateKeyPassword(pid, keyRef, req.keyPassword());
    }

    // Step A: CSR
    String reqFileName = req.name() + "_csr.pem";
    Map<String, Object> reqGenParams = buildSubjectParams(req.subject());
    reqGenParams.put("key", keyRef);
    reqGenParams.put("pass", keyPass);
    reqGenParams.put("out", reqFileName);

    var reqJob = runJob(pid, "generate_csr", "reqgen", reqGenParams, httpReq, stages, artifacts);
    byte[] csrBytes = getArtifactBytes(pid, reqJob, reqFileName);
    String csrFileRef = saveFile(pid, reqFileName, "application/pkcs10", csrBytes, files);

    // Step B: Sign Intermediate CA
    int days = req.days() != null ? req.days() : 1825;
    int pathLen = 0;
    if (req.advanced() != null && req.advanced().get("pathLenConstraint") != null) {
      pathLen = Integer.parseInt(req.advanced().get("pathLenConstraint").toString());
    }

    String outFileName = req.name() + "_intermediate_ca.pem";
    Map<String, Object> signParams = new LinkedHashMap<>();
    signParams.put("in", csrFileRef);
    signParams.put("cacert", req.issuerCertRef());
    signParams.put("key", req.issuerKeyRef());
    signParams.put("pass", issuerPass);
    signParams.put("days", days);
    signParams.put("ca", true);
    signParams.put("key_usage", List.of("keyCertSign", "cRLSign"));
    signParams.put("path_len_constraint", pathLen);
    signParams.put("serial_len", resolveSerialLen(req.advanced()));
    signParams.put("out", outFileName);

    var signJob = runJob(pid, "sign_intermediate_ca", "reqsign", signParams, httpReq, stages, artifacts);
    byte[] certBytes = getArtifactBytes(pid, signJob, outFileName);
    String certRef = saveFile(pid, outFileName, "application/x-x509-ca-cert", certBytes, files);

    runJob(
        pid,
        "parse_certificate",
        "certparse",
        Map.of("in", certRef, "out", "certparse.txt"),
        httpReq,
        stages,
        artifacts);
  }

  // 4. CSR
  private void executeCsr(
      String pid,
      String uid,
      CertificateWorkflowRequest req,
      HttpServletRequest httpReq,
      List<WorkflowStage> stages,
      List<Map<String, Object>> keys,
      List<Map<String, Object>> files,
      List<Map<String, Object>> artifacts,
      List<String> warnings) {
    String keyRef = req.keyRef();
    String keyPass;
    if (keyRef == null || keyRef.isBlank()) {
      var genRes =
          generateKey(
              pid,
              uid,
              Map.of(
                  "algorithm", "SM2",
                  "storage", "MANAGED",
                  "name", req.name() + "-key",
                  "provider", req.provider() != null ? req.provider() : "gmssl"));
      keyRef = (String) genRes.get("reference");
      keys.add((Map<String, Object>) genRes.get("key"));
      keyPass = credentialService.getPassphrase(pid, parseId(keyRef));
      stages.add(new WorkflowStage("generate_key", null, "SUCCEEDED"));
    } else {
      keyPass = resolvePrivateKeyPassword(pid, keyRef, req.keyPassword() != null ? req.keyPassword() : req.issuerPassword());
    }

    String outFileName = req.name() + ".csr";
    Map<String, Object> reqGenParams = buildSubjectParams(req.subject());
    reqGenParams.put("key", keyRef);
    reqGenParams.put("pass", keyPass);
    reqGenParams.put("out", outFileName);

    if (req.advanced() != null && req.advanced().get("sm2Id") != null) {
      reqGenParams.put("sm2_id", req.advanced().get("sm2Id").toString());
    }

    var reqJob = runJob(pid, "generate_csr", "reqgen", reqGenParams, httpReq, stages, artifacts);
    byte[] csrBytes = getArtifactBytes(pid, reqJob, outFileName);

    String csrRef = saveFile(pid, outFileName, "application/pkcs10", csrBytes, files);

    runJob(
        pid,
        "parse_csr",
        "reqparse",
        Map.of("in", csrRef, "out", "reqparse.txt"),
        httpReq,
        stages,
        artifacts);
  }

  // 5. CA_SIGN
  private void executeCaSign(
      String pid,
      String uid,
      CertificateWorkflowRequest req,
      HttpServletRequest httpReq,
      List<WorkflowStage> stages,
      List<Map<String, Object>> keys,
      List<Map<String, Object>> files,
      List<Map<String, Object>> artifacts,
      List<String> warnings) {
    String issuerPass = resolvePrivateKeyPassword(pid, req.issuerKeyRef(), req.issuerPassword());

    String csrFileRef = req.csrRef();
    if (csrFileRef == null || csrFileRef.isBlank()) {
      // Generate key & CSR
      String keyRef = req.keyRef();
      String keyPass;
      if (keyRef == null || keyRef.isBlank()) {
        var genRes =
            generateKey(
                pid,
                uid,
                Map.of(
                    "algorithm", "SM2",
                    "storage", "MANAGED",
                    "name", req.name() + "-key",
                    "provider", req.provider() != null ? req.provider() : "gmssl"));
        keyRef = (String) genRes.get("reference");
        keys.add((Map<String, Object>) genRes.get("key"));
        keyPass = credentialService.getPassphrase(pid, parseId(keyRef));
        stages.add(new WorkflowStage("generate_key", null, "SUCCEEDED"));
      } else {
        keyPass = resolvePrivateKeyPassword(pid, keyRef, null);
      }

      String reqFileName = req.name() + "_csr.pem";
      Map<String, Object> reqGenParams = buildSubjectParams(req.subject());
      reqGenParams.put("key", keyRef);
      reqGenParams.put("pass", keyPass);
      reqGenParams.put("out", reqFileName);

      var reqJob = runJob(pid, "generate_csr", "reqgen", reqGenParams, httpReq, stages, artifacts);
      byte[] csrBytes = getArtifactBytes(pid, reqJob, reqFileName);
      csrFileRef = saveFile(pid, reqFileName, "application/pkcs10", csrBytes, files);
    }

    int days = req.days() != null ? req.days() : 365;
    String purpose = req.purpose() != null ? req.purpose().toUpperCase().trim() : "SERVER";
    List<String> keyUsages;
    List<String> extKeyUsages;

    switch (purpose) {
      case "CLIENT" -> {
        keyUsages = List.of("digitalSignature");
        extKeyUsages = List.of("clientAuth");
      }
      case "SIGNING" -> {
        keyUsages = List.of("digitalSignature", "nonRepudiation");
        extKeyUsages = List.of("codeSigning");
      }
      default -> {
        keyUsages = List.of("digitalSignature", "keyEncipherment");
        extKeyUsages = List.of("serverAuth");
      }
    }

    String outFileName = req.name() + "_cert.pem";
    Map<String, Object> signParams = new LinkedHashMap<>();
    signParams.put("in", csrFileRef);
    signParams.put("cacert", req.issuerCertRef());
    signParams.put("key", req.issuerKeyRef());
    signParams.put("pass", issuerPass);
    signParams.put("days", days);
    signParams.put("ca", false);
    signParams.put("key_usage", keyUsages);
    signParams.put("ext_key_usage", extKeyUsages);
    signParams.put("serial_len", resolveSerialLen(req.advanced()));
    signParams.put("out", outFileName);

    if (req.sanDns() != null && !req.sanDns().isEmpty()) {
      signParams.put("subject_dns_name", req.sanDns());
    }

    var signJob = runJob(pid, "sign_certificate", "reqsign", signParams, httpReq, stages, artifacts);
    byte[] certBytes = getArtifactBytes(pid, signJob, outFileName);
    String certRef = saveFile(pid, outFileName, "application/x-x509-ca-cert", certBytes, files);

    runJob(
        pid,
        "parse_certificate",
        "certparse",
        Map.of("in", certRef, "out", "certparse.txt"),
        httpReq,
        stages,
        artifacts);

    if (!"SIGNING".equals(purpose)) {
      Map<String, Object> verifyParams = new LinkedHashMap<>();
      verifyParams.put("in", certRef);
      verifyParams.put("cacert", req.issuerCertRef());
      if ("CLIENT".equals(purpose)) {
        verifyParams.put("client", true);
      } else {
        verifyParams.put("server", true);
      }
      if (!"CLIENT".equals(purpose) && req.sanDns() != null && !req.sanDns().isEmpty()) {
        verifyParams.put("hostname", req.sanDns().getFirst());
      }
      runJob(pid, "verify_certificate", "certverify", verifyParams, httpReq, stages, artifacts);
    }

    if ("QUICK_ISSUE".equalsIgnoreCase(req.profile())) {
      byte[] caCertBytes = vault.read(pid, parseId(req.issuerCertRef()));
      byte[] chainBytes = concatenatePem(certBytes, caCertBytes);
      String chainFileName = req.name() + "_chain.pem";
      saveFile(pid, chainFileName, "application/x-pem-file", chainBytes, files);
      stages.add(new WorkflowStage("build_chain", null, "SUCCEEDED"));
    }
  }

  // 6. TLCP
  private void executeTlcp(
      String pid,
      String uid,
      CertificateWorkflowRequest req,
      HttpServletRequest httpReq,
      List<WorkflowStage> stages,
      List<Map<String, Object>> keys,
      List<Map<String, Object>> files,
      List<Map<String, Object>> artifacts,
      List<String> warnings) {
    String caCertRef = req.issuerCertRef();
    String caKeyRef = req.issuerKeyRef();
    String caPass;
    byte[] caCertBytes;

    if (caCertRef != null && !caCertRef.isBlank() && caKeyRef != null && !caKeyRef.isBlank()) {
      caPass = resolvePrivateKeyPassword(pid, caKeyRef, req.issuerPassword() != null ? req.issuerPassword() : req.keyPassword());
      caCertBytes = vault.read(pid, parseId(caCertRef));
    } else {
      // Auto generate TLCP Root CA
      var caKeyRes =
          generateKey(
              pid,
              uid,
              Map.of(
                  "algorithm", "SM2",
                  "storage", "MANAGED",
                  "name", req.name() + "-tlcp-ca-key",
                  "provider", req.provider() != null ? req.provider() : "gmssl"));
      caKeyRef = (String) caKeyRes.get("reference");
      keys.add((Map<String, Object>) caKeyRes.get("key"));
      caPass = credentialService.getPassphrase(pid, parseId(caKeyRef));
      stages.add(new WorkflowStage("generate_ca_key", null, "SUCCEEDED"));

      String caCertName = req.name() + "_tlcp_ca_cert.pem";
      Map<String, Object> caCertParams = buildSubjectParams(req.subject());
      caCertParams.put("CN", req.subject().CN() + " TLCP CA");
      caCertParams.put("days", 3650);
      caCertParams.put("key", caKeyRef);
      caCertParams.put("pass", caPass);
      caCertParams.put("ca", true);
      caCertParams.put("key_usage", List.of("keyCertSign", "cRLSign"));
      caCertParams.put("serial_len", resolveSerialLen(req.advanced()));
      caCertParams.put("out", caCertName);

      var caCertJob = runJob(pid, "generate_ca_certificate", "certgen", caCertParams, httpReq, stages, artifacts);
      caCertBytes = getArtifactBytes(pid, caCertJob, caCertName);
      caCertRef = saveFile(pid, caCertName, "application/x-x509-ca-cert", caCertBytes, files);
    }

    byte[] entropy = new byte[32];
    new java.security.SecureRandom().nextBytes(entropy);
    String pairPassword = Base64.getUrlEncoder().withoutPadding().encodeToString(entropy);
    Arrays.fill(entropy, (byte) 0);

    // Independent key pairs share the single password accepted by tlcp_server.
    var signKeyRes =
        generateKey(
            pid,
            uid,
            Map.of(
                "algorithm", "SM2",
                "storage", "MANAGED",
                "name", req.name() + "-sign-key",
                "password", pairPassword,
                "provider", req.provider() != null ? req.provider() : "gmssl"));
    String signKeyRef = (String) signKeyRes.get("reference");
    keys.add((Map<String, Object>) signKeyRes.get("key"));
    String signKeyPass = credentialService.getPassphrase(pid, parseId(signKeyRef));
    stages.add(new WorkflowStage("generate_sign_key", null, "SUCCEEDED"));

    var encKeyRes =
        generateKey(
            pid,
            uid,
            Map.of(
                "algorithm", "SM2",
                "storage", "MANAGED",
                "name", req.name() + "-enc-key",
                "password", pairPassword,
                "provider", req.provider() != null ? req.provider() : "gmssl"));
    String encKeyRef = (String) encKeyRes.get("reference");
    keys.add((Map<String, Object>) encKeyRes.get("key"));
    String encKeyPass = credentialService.getPassphrase(pid, parseId(encKeyRef));
    stages.add(new WorkflowStage("generate_enc_key", null, "SUCCEEDED"));

    byte[] signPrivate = vault.read(pid, parseId(signKeyRef));
    byte[] encPrivate = vault.read(pid, parseId(encKeyRef));
    byte[] pairBytes = concatenatePem(signPrivate, encPrivate);
    try {
      String pairRef = saveFile(pid, req.name() + "_tlcp_keys.pem", "application/x-pem-file", pairBytes, files);
      credentialService.savePassphrase(pid, parseId(pairRef), pairPassword);
      files.set(files.size() - 1, materials.dto(materials.raw(pid, parseId(pairRef))));
    } finally {
      Arrays.fill(signPrivate, (byte) 0);
      Arrays.fill(encPrivate, (byte) 0);
      Arrays.fill(pairBytes, (byte) 0);
    }

    // Step B: Sign CSR
    String signReqName = req.name() + "_sign_req.pem";
    Map<String, Object> signReqParams = buildSubjectParams(req.subject());
    signReqParams.put("key", signKeyRef);
    signReqParams.put("pass", signKeyPass);
    signReqParams.put("out", signReqName);

    var signReqJob = runJob(pid, "generate_sign_csr", "reqgen", signReqParams, httpReq, stages, artifacts);
    byte[] signReqBytes = getArtifactBytes(pid, signReqJob, signReqName);
    String signReqRef = saveFile(pid, signReqName, "application/pkcs10", signReqBytes, files);

    // Step C: Enc CSR
    String encReqName = req.name() + "_enc_req.pem";
    Map<String, Object> encReqParams = buildSubjectParams(req.subject());
    encReqParams.put("key", encKeyRef);
    encReqParams.put("pass", encKeyPass);
    encReqParams.put("out", encReqName);

    var encReqJob = runJob(pid, "generate_enc_csr", "reqgen", encReqParams, httpReq, stages, artifacts);
    byte[] encReqBytes = getArtifactBytes(pid, encReqJob, encReqName);
    String encReqRef = saveFile(pid, encReqName, "application/pkcs10", encReqBytes, files);

    // Step D: Sign Sign Cert
    int days = req.days() != null ? req.days() : 365;
    String signCertName = req.name() + "_sign_cert.pem";
    Map<String, Object> signCertParams = new LinkedHashMap<>();
    signCertParams.put("in", signReqRef);
    signCertParams.put("cacert", caCertRef);
    signCertParams.put("key", caKeyRef);
    signCertParams.put("pass", caPass);
    signCertParams.put("days", days);
    signCertParams.put("ca", false);
    signCertParams.put("key_usage", List.of("digitalSignature"));
    signCertParams.put("ext_key_usage", List.of("serverAuth"));
    signCertParams.put("serial_len", resolveSerialLen(req.advanced()));
    signCertParams.put("out", signCertName);
    if (req.sanDns() != null && !req.sanDns().isEmpty()) {
      signCertParams.put("subject_dns_name", req.sanDns());
    }

    var signCertJob = runJob(pid, "sign_sign_certificate", "reqsign", signCertParams, httpReq, stages, artifacts);
    byte[] signCertBytes = getArtifactBytes(pid, signCertJob, signCertName);
    saveFile(pid, signCertName, "application/x-x509-ca-cert", signCertBytes, files);

    // Step E: Sign Enc Cert
    String encCertName = req.name() + "_enc_cert.pem";
    Map<String, Object> encCertParams = new LinkedHashMap<>();
    encCertParams.put("in", encReqRef);
    encCertParams.put("cacert", caCertRef);
    encCertParams.put("key", caKeyRef);
    encCertParams.put("pass", caPass);
    encCertParams.put("days", days);
    encCertParams.put("ca", false);
    encCertParams.put("key_usage", List.of("keyEncipherment"));
    encCertParams.put("ext_key_usage", List.of("serverAuth"));
    encCertParams.put("serial_len", resolveSerialLen(req.advanced()));
    encCertParams.put("out", encCertName);
    if (req.sanDns() != null && !req.sanDns().isEmpty()) {
      encCertParams.put("subject_dns_name", req.sanDns());
    }

    var encCertJob = runJob(pid, "sign_enc_certificate", "reqsign", encCertParams, httpReq, stages, artifacts);
    byte[] encCertBytes = getArtifactBytes(pid, encCertJob, encCertName);
    saveFile(pid, encCertName, "application/x-x509-ca-cert", encCertBytes, files);

    // Step F: TLCP bundle [sign_cert, enc_cert, ca_cert]
    byte[] bundleBytes = concatenatePem(signCertBytes, encCertBytes, caCertBytes);
    String bundleName = req.name() + "_tlcp_certs.pem";
    String bundleRef = saveFile(pid, bundleName, "application/x-pem-file", bundleBytes, files);

    // Step G: certparse
    runJob(
        pid,
        "parse_certificates",
        "certparse",
        Map.of("in", bundleRef, "out", "certparse.txt"),
        httpReq,
        stages,
        artifacts);

    // Step H: certverify -tlcp_server
    Map<String, Object> verifyParams = new LinkedHashMap<>();
    verifyParams.put("in", bundleRef);
    verifyParams.put("cacert", caCertRef);
    verifyParams.put("tlcp_server", true);
    if (req.sanDns() != null && !req.sanDns().isEmpty()) {
      verifyParams.put("hostname", req.sanDns().getFirst());
    }
    runJob(pid, "verify_tlcp", "certverify", verifyParams, httpReq, stages, artifacts);
  }

  /** Bounded DER traversal: every child is confined to its parent's content. */
  private record Der(byte[] bytes, int tag, int start, int body, int end) {
    static Der read(byte[] bytes, int at, int limit) {
      if (at < 0 || at + 2 > limit || limit > bytes.length) throw new IllegalArgumentException("Malformed DER");
      int tag = bytes[at] & 255, p = at + 1, len = bytes[p++] & 255;
      if ((len & 128) != 0) {
        int count = len & 127;
        if (count == 0 || count > 3 || p + count > limit || bytes[p] == 0) throw new IllegalArgumentException("Malformed DER length");
        len = 0;
        for (int i = 0; i < count; i++) len = (len << 8) | (bytes[p++] & 255);
        if (len < 128) throw new IllegalArgumentException("Nonminimal DER length");
      }
      if (len > limit - p) throw new IllegalArgumentException("DER boundary exceeded");
      return new Der(bytes, tag, at, p, p + len);
    }
    List<Der> children() {
      List<Der> result = new ArrayList<>();
      for (int at = body; at < end;) {
        Der child = read(bytes, at, end);
        result.add(child); at = child.end;
        if (result.size() > 128) throw new IllegalArgumentException("Too many DER elements");
      }
      return result;
    }
    byte[] value() { return Arrays.copyOfRange(bytes, body, end); }
    byte[] encoded() { return Arrays.copyOfRange(bytes, start, end); }
    boolean oid(String hex) { return tag == 6 && HexFormat.of().formatHex(value()).equals(hex); }
  }

  private static byte[] decodePem(byte[] bytes, String label) {
    String text = new String(bytes, StandardCharsets.US_ASCII);
    String begin = "-----BEGIN " + label + "-----", end = "-----END " + label + "-----";
    int a = text.indexOf(begin), b = text.indexOf(end);
    if (a < 0 || b < a || bytes.length > 1024 * 1024) throw new IllegalArgumentException("Invalid PEM");
    return Base64.getDecoder().decode(text.substring(a + begin.length(), b).replaceAll("\\s", ""));
  }

  private static final class Cert {
    final Der tbs, spki, issuer, subject;
    final byte[] signature;
    final java.time.Instant before, after;
    boolean ca;
    Integer pathLen;
    byte[] keyUsage;
    final Set<String> eku = new HashSet<>();
    final Set<String> dns = new HashSet<>();
    final Set<String> ips = new HashSet<>();
    Cert(byte[] pem) {
      byte[] der = decodePem(pem, "CERTIFICATE");
      Der root = Der.read(der, 0, der.length);
      if (root.tag != 48 || root.end != der.length) throw new IllegalArgumentException("Invalid certificate");
      var outer = root.children();
      if (outer.size() != 3 || outer.get(2).tag != 3 || outer.get(2).value()[0] != 0)
        throw new IllegalArgumentException("Invalid certificate signature");
      tbs = outer.get(0);
      signature = Arrays.copyOfRange(outer.get(2).bytes, outer.get(2).body + 1, outer.get(2).end);
      var fields = tbs.children(); int i = fields.getFirst().tag == 160 ? 1 : 0;
      if (!outer.get(1).children().getFirst().oid("2a811ccf55018375") ||
          !Arrays.equals(fields.get(i + 1).encoded(), outer.get(1).encoded()))
        throw new IllegalArgumentException("Certificate must use SM2 with SM3");
      issuer = fields.get(i + 2);
      var validity = fields.get(i + 3).children();
      if (validity.size() != 2) throw new IllegalArgumentException("Invalid validity");
      before = time(validity.get(0)); after = time(validity.get(1));
      subject = fields.get(i + 4); spki = fields.get(i + 5);
      var alg = spki.children().getFirst().children();
      if (alg.size() != 2 || !alg.get(0).oid("2a8648ce3d0201") || !alg.get(1).oid("2a811ccf5501822d"))
        throw new IllegalArgumentException("Certificate must bind SM2 curve");
      Set<String> extensions = new HashSet<>();
      for (int j = i + 6; j < fields.size(); j++) if (fields.get(j).tag == 163) {
        for (Der extension : fields.get(j).children().getFirst().children()) {
          var parts = extension.children();
          String oid = HexFormat.of().formatHex(parts.getFirst().value());
          if (!extensions.add(oid)) throw new IllegalArgumentException("Duplicate certificate extension");
          Der wrapped = parts.getLast();
          if (wrapped.tag != 4) throw new IllegalArgumentException("Invalid extension encoding");
          Der content = Der.read(der, wrapped.body, wrapped.end);
          if (content.end != wrapped.end) throw new IllegalArgumentException("Trailing extension data");
          if (oid.equals("551d13")) {
            var bc = content.children(); int k = 0;
            if (!bc.isEmpty() && bc.getFirst().tag == 1) { ca = Arrays.equals(bc.getFirst().value(), new byte[]{(byte)255}); k++; }
            if (k < bc.size()) {
              if (bc.get(k).tag != 2) throw new IllegalArgumentException("Invalid path length");
              pathLen = new java.math.BigInteger(bc.get(k).value()).intValueExact();
              if (!ca || pathLen < 0) throw new IllegalArgumentException("Invalid CA path length");
            }
          } else if (oid.equals("551d11")) {
            for (Der name : content.children()) {
              if (name.tag == 130) dns.add(new String(name.value(), StandardCharsets.US_ASCII));
              if (name.tag == 135) {
                if (name.value().length != 4 && name.value().length != 16) throw new IllegalArgumentException("Invalid IP GeneralName");
                ips.add(HexFormat.of().formatHex(name.value()));
              }
            }
          } else if (oid.equals("551d0f")) keyUsage = content.value();
          else if (oid.equals("551d25")) for (Der usage : content.children()) eku.add(HexFormat.of().formatHex(usage.value()));
        }
      }
    }
    boolean usage(int bit) { return keyUsage != null && keyUsage.length > 1 + bit / 8 && (keyUsage[1 + bit / 8] & (128 >> (bit % 8))) != 0; }
    static java.time.Instant time(Der time) {
      String value = new String(time.value(), StandardCharsets.US_ASCII);
      if (time.tag == 23 && value.matches("[0-9]{12}Z")) {
        int year = Integer.parseInt(value.substring(0, 2));
        value = (year >= 50 ? "19" : "20") + value;
      } else if (time.tag != 24 || !value.matches("[0-9]{14}Z")) throw new IllegalArgumentException("Invalid X509 time");
      return java.time.LocalDateTime.parse(value, java.time.format.DateTimeFormatter.ofPattern("uuuuMMddHHmmss'Z'"))
          .toInstant(java.time.ZoneOffset.UTC);
    }
  }

  private void inspectOutputs(String pid, CertificateWorkflowRequest req, HttpServletRequest http,
      List<WorkflowStage> stages, List<Map<String,Object>> files, List<Map<String,Object>> artifacts) {
    if (req.profile().equalsIgnoreCase("TLCP")) {
      List<Cert> pair = new ArrayList<>();
      for (var file : files) if (file.get("name").toString().endsWith("_sign_cert.pem") || file.get("name").toString().endsWith("_enc_cert.pem"))
        pair.add(new Cert(vault.read(pid, file.get("id").toString())));
      if (pair.size() != 2 || Arrays.equals(pair.get(0).spki.encoded(), pair.get(1).spki.encoded()))
        throw new WorkflowException("inspect_tlcp_keys", null, "TLCP requires two distinct public keys");
    }
    for (var file : List.copyOf(files)) {
      if (!"application/x-x509-ca-cert".equals(file.get("mediaType"))) continue;
      String ref = "file:" + file.get("id");
      Cert cert = new Cert(vault.read(pid, file.get("id").toString()));
      var input = currentRun.get().certificateInputs.get(file.get("name").toString());
      if (input != null && input.get("in") != null) {
        byte[] csrDer = decodePem(vault.read(pid, parseId(input.get("in").toString())), "CERTIFICATE REQUEST");
        Der csr = Der.read(csrDer, 0, csrDer.length);
        Der requestedSpki = csr.children().getFirst().children().get(2);
        if (!Arrays.equals(cert.spki.encoded(), requestedSpki.encoded()))
          throw new WorkflowException("inspect_certificate", null, "Certificate public key differs from CSR");
      } else if (input != null) {
        String keyRef = input.get("key").toString();
        byte[] publicPem = currentRun.get().publicKeys.get(keyRef);
        if (publicPem != null && !Arrays.equals(cert.spki.encoded(), decodePem(publicPem, "PUBLIC KEY")))
          throw new WorkflowException("inspect_certificate", null, "Certificate public key differs from generated key");
        if (publicPem == null) {
          String proofData = scratch(pid, "key_match_data.der", cert.tbs.encoded());
          var proof = runJob(pid, "prove_private_key", "sm2sign", new LinkedHashMap<>(Map.of("key", keyRef,
              "pass", input.get("pass"), "in", proofData, "out", "key_match.sig")), http, stages, artifacts);
          String proofSig = scratch(pid, "key_match.sig", getArtifactBytes(pid, proof, "key_match.sig"));
          runJob(pid, "verify_private_key_match", "sm2verify", new LinkedHashMap<>(Map.of("cert", ref,
              "in", proofData, "sig", proofSig)), http, stages, artifacts);
        }
      }
      boolean authority = req.profile().equalsIgnoreCase("ROOT_CA") || req.profile().equalsIgnoreCase("INTERMEDIATE_CA") || (req.profile().equalsIgnoreCase("TLCP") && file.get("name").toString().endsWith("_tlcp_ca_cert.pem"));
      if (cert.ca != authority || (authority && !cert.usage(5))) throw new WorkflowException("inspect_certificate", null, "Certificate CA constraints do not match profile");
      if (req.sanDns() != null && !cert.dns.containsAll(req.sanDns()))
        throw new WorkflowException("inspect_certificate", null, "Requested DNS SAN missing from certificate");
      if (req.sanIps() != null) for (String ip : req.sanIps()) {
        try {
          if (!cert.ips.contains(HexFormat.of().formatHex(java.net.InetAddress.getByName(ip).getAddress())))
            throw new WorkflowException("inspect_certificate", null, "Requested IP SAN missing from certificate");
        } catch (java.net.UnknownHostException e) { throw new IllegalArgumentException("Invalid IP literal"); }
      }
      java.time.Instant now = java.time.Instant.now();
      if (cert.before.isAfter(now.plusSeconds(5)) || !cert.after.isAfter(now) || !cert.after.isAfter(cert.before))
        throw new WorkflowException("inspect_certificate", null, "Invalid certificate validity");
      String issuerRef = req.issuerCertRef();
      if (Arrays.equals(cert.subject.encoded(), cert.issuer.encoded())) issuerRef = ref;
      else if (issuerRef == null && req.profile().equalsIgnoreCase("TLCP")) {
        for (var ca : files) if (ca.get("name").toString().endsWith("_tlcp_ca_cert.pem")) issuerRef = "file:" + ca.get("id");
      }
      if (issuerRef == null) throw new WorkflowException("inspect_certificate", null, "Missing issuer certificate");
      Cert issuer = new Cert(vault.read(pid, parseId(issuerRef)));
      if (!Arrays.equals(cert.issuer.encoded(), issuer.subject.encoded()) || cert.after.isAfter(issuer.after))
        throw new WorkflowException("inspect_certificate", null, "Issuer or certificate validity mismatch");
      if (req.profile().equalsIgnoreCase("INTERMEDIATE_CA")) {
        int path = req.advanced() != null && req.advanced().get("pathLenConstraint") != null ? Integer.parseInt(req.advanced().get("pathLenConstraint").toString()) : 0;
        if (!Objects.equals(cert.pathLen, path) || (issuer.pathLen != null && path >= issuer.pathLen))
          throw new WorkflowException("inspect_certificate", null, "CA path length mismatch");
      }
      if (!authority) {
        String purpose = req.purpose() == null ? "SERVER" : req.purpose().toUpperCase(Locale.ROOT);
        boolean enc = file.get("name").toString().endsWith("_enc_cert.pem");
        if ((enc && (!cert.usage(2) || cert.usage(0))) || (!enc && !cert.usage(0)) || cert.usage(5))
          throw new WorkflowException("inspect_certificate", null, "Certificate key usage does not match profile");
        if ("SERVER".equals(purpose) && !cert.eku.contains("2b06010505070301"))
          throw new WorkflowException("inspect_certificate", null, "Server authentication EKU missing");
        if ("CLIENT".equals(purpose) && !cert.eku.contains("2b06010505070302"))
          throw new WorkflowException("inspect_certificate", null, "Client authentication EKU missing");
        if ("SIGNING".equals(purpose) && !cert.eku.contains("2b06010505070303"))
          throw new WorkflowException("inspect_certificate", null, "Code signing EKU missing");
      }
    }
  }

  private String scratch(String pid, String name, byte[] bytes) {
    var file = materials.create(pid, "FILE", name, "application/octet-stream", bytes, Map.of("temporary", "true"));
    String id = file.get("id").toString();
    currentRun.get().temporary.add(id);
    return "file:" + id;
  }

  private static byte[] concatenatePem(byte[]... parts) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    for (byte[] p : parts) {
      if (p == null || p.length == 0) continue;
      try {
        out.write(p);
        if (p[p.length - 1] != '\n') out.write('\n');
      } catch (IOException ignored) {}
    }
    return out.toByteArray();
  }
}
