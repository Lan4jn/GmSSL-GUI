package org.gmssl.gui.platform;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;
import org.springframework.stereotype.Service;

@Service
public class CertificateTreeService {

  public record CertificateNodeDto(
      String id,
      String fingerprint,
      String name,
      String category,
      String subjectCN,
      String issuerCN,
      String serialNumber,
      String validBefore,
      String validAfter,
      String validityStatus,
      String revocationStatus,
      boolean isCa,
      boolean selectableAsIssuer,
      List<String> parentRefs,
      List<String> materialRefs,
      String downloadRef,
      String error,
      List<String> matchedCsrRefs,
      String csrMatchEvidence
  ) {}

  public record CsrNodeDto(
      String id,
      String name,
      String subjectCN,
      String createdAt,
      String spkiFingerprint,
      List<String> matchedCertIds,
      String matchKind,
      boolean ambiguous,
      String error
  ) {}

  public record BundleNodeDto(
      String id,
      String name,
      List<String> containsCertIds
  ) {}

  public record CertificatesResponse(
      List<CertificateNodeDto> nodes,
      List<CsrNodeDto> csrs,
      List<BundleNodeDto> bundles
  ) {}

  private static class CachedCertNode {
    String id;
    String fingerprint;
    String name;
    X509CertificateParser.Category category;
    String subjectCN;
    String issuerCN;
    byte[] subjectDer;
    byte[] issuerDer;
    byte[] rawDer;
    byte[] tbsDer;
    byte[] signature;
    String serialNumber;
    Instant notBefore;
    Instant notAfter;
    boolean isCa;
    boolean allowsCertSigning;
    byte[] spkiDer;
    String spkiFingerprint;
    List<String> matchedCsrRefs = new ArrayList<>();
    String csrMatchEvidence;
    List<String> parentRefs = new ArrayList<>();
    Set<String> materialRefs = new LinkedHashSet<>();
    String downloadRef;
    String error;
  }

  private static class CachedCsrNode {
    String fileRef;
    String fileName;
    String subjectCN;
    String createdAt;
    byte[] subjectDer;
    byte[] spkiDer;
    byte[] criDer;
    byte[] signature;
    String spkiFingerprint;
    String error;
    List<String> matchedCertIds = new ArrayList<>();
    String matchKind = "UNMATCHED";
    boolean ambiguous = false;
  }

  private static class ProjectCertCache {
    final String snapshotKey;
    final List<CachedCertNode> certs;
    final List<CsrNodeDto> csrs;
    final List<BundleNodeDto> bundles;

    ProjectCertCache(String snapshotKey, List<CachedCertNode> certs, List<CsrNodeDto> csrs, List<BundleNodeDto> bundles) {
      this.snapshotKey = snapshotKey;
      this.certs = certs;
      this.csrs = csrs;
      this.bundles = bundles;
    }
  }

  private final Store s;
  private final Materials materials;
  private final Vault vault;
  private final Engine engine;
  private final ObjectMapper json;

  private final LinkedHashMap<String, ProjectCertCache> cache =
      new LinkedHashMap<>(16, 0.75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, ProjectCertCache> eldest) {
          return size() > 100;
        }
      };

  public CertificateTreeService(Store s, Materials materials, Vault vault, Engine engine, ObjectMapper json) {
    this.s = s;
    this.materials = materials;
    this.vault = vault;
    this.engine = engine;
    this.json = json;
  }

  public synchronized void invalidateProject(String pid) {
    cache.remove(pid);
  }

  public synchronized CertificatesResponse getCertificates(String pid) {
    List<Map<String, Object>> files =
        s.rows(
            "select id, name, media_type, byte_size, updated_at, created_at from materials where project_id=? and object_type='FILE' and temporary=? order by id",
            pid,
            Boolean.FALSE);

    StringBuilder sb = new StringBuilder();
    for (var f : files) {
      sb.append(f.get("id")).append(":")
        .append(f.get("byte_size")).append(":")
        .append(f.get("updated_at")).append(";");
    }
    String snapshotKey = sb.toString();

    ProjectCertCache entry = cache.get(pid);
    if (entry == null || !snapshotKey.equals(entry.snapshotKey)) {
      entry = rebuildProjectCache(pid, files, snapshotKey);
      cache.put(pid, entry);
    }

    Instant now = Instant.now();
    List<CertificateNodeDto> nodes = new ArrayList<>();
    for (CachedCertNode c : entry.certs) {
      String validityStatus = "UNKNOWN";
      if (c.notBefore != null && c.notAfter != null) {
        if (now.isBefore(c.notBefore)) validityStatus = "NOT_YET_VALID";
        else if (now.isAfter(c.notAfter)) validityStatus = "EXPIRED";
        else validityStatus = "VALID";
      }

      boolean selectableAsIssuer = false;
      if (c.category == X509CertificateParser.Category.ROOT_CA || c.category == X509CertificateParser.Category.INTERMEDIATE_CA) {
        if (c.isCa && c.allowsCertSigning && "VALID".equals(validityStatus) && c.downloadRef != null) {
          selectableAsIssuer = true;
        }
      }

      nodes.add(new CertificateNodeDto(
          c.id,
          c.fingerprint,
          c.name,
          c.category.name(),
          c.subjectCN,
          c.issuerCN,
          c.serialNumber,
          c.notBefore != null ? c.notBefore.toString() : null,
          c.notAfter != null ? c.notAfter.toString() : null,
          validityStatus,
          "UNCHECKED",
          c.isCa,
          selectableAsIssuer,
          c.parentRefs,
          new ArrayList<>(c.materialRefs),
          c.downloadRef,
          c.error,
          c.matchedCsrRefs,
          c.csrMatchEvidence
      ));
    }

    return new CertificatesResponse(nodes, entry.csrs, entry.bundles);
  }

  private ProjectCertCache rebuildProjectCache(String pid, List<Map<String, Object>> files, String snapshotKey) {
    Map<String, CachedCertNode> certMap = new LinkedHashMap<>();
    List<CachedCsrNode> csrNodes = new ArrayList<>();
    List<BundleNodeDto> bundles = new ArrayList<>();

    for (var f : files) {
      String fileId = f.get("id").toString();
      String fileName = f.get("name").toString();
      String createdAt = f.get("created_at") != null ? f.get("created_at").toString() : Instant.now().toString();
      String fileRef = "file:" + fileId;

      byte[] content;
      try {
        content = vault.read(pid, fileId);
      } catch (Exception e) {
        continue;
      }

      List<byte[]> certDers = X509CertificateParser.extractAllCertificateDers(content);
      if (certDers.isEmpty()) {
        // Try parsing as CSR
        X509CertificateParser.CsrResult csr = X509CertificateParser.parseCsr(content, fileName);
        if (csr.error() == null) {
          boolean sigOk = verifyCsrSignature(csr.criDer(), csr.signature(), csr.spkiDer());
          CachedCsrNode node = new CachedCsrNode();
          node.fileRef = fileRef;
          node.fileName = fileName;
          node.subjectCN = csr.subjectCN();
          node.createdAt = createdAt;
          node.subjectDer = csr.subjectDer();
          node.spkiDer = csr.spkiDer();
          node.criDer = csr.criDer();
          node.signature = csr.signature();
          node.spkiFingerprint = csr.spkiFingerprint();
          if (!sigOk) {
            node.error = "CSR 请求签名校验失败";
            node.matchKind = "INVALID_CSR";
          }
          csrNodes.add(node);
        } else {
          String media = Objects.toString(f.get("media_type"), "");
          if (fileName.endsWith(".csr") || "application/pkcs10".equals(media)) {
            CachedCsrNode node = new CachedCsrNode();
            node.fileRef = fileRef;
            node.fileName = fileName;
            node.subjectCN = "UNKNOWN";
            node.createdAt = createdAt;
            node.error = "文件格式非法或非有效证书请求";
            node.matchKind = "INVALID_CSR";
            csrNodes.add(node);
          } else if (fileName.endsWith(".pem") || fileName.endsWith(".crt") || fileName.endsWith(".cer")
              || "application/x-x509-ca-cert".equals(media)) {
            CachedCertNode errNode = new CachedCertNode();
            errNode.id = "invalid:" + fileId;
            errNode.fingerprint = null;
            errNode.name = fileName;
            errNode.category = X509CertificateParser.Category.UNSUPPORTED;
            errNode.subjectCN = "UNKNOWN";
            errNode.issuerCN = "UNKNOWN";
            errNode.isCa = false;
            errNode.allowsCertSigning = false;
            errNode.materialRefs.add(fileRef);
            errNode.downloadRef = null;
            errNode.error = "文件格式非法或非有效证书";
            certMap.put(errNode.id, errNode);
          }
        }
      } else if (certDers.size() == 1) {
        byte[] der = certDers.getFirst();
        X509CertificateParser.ParsedResult parsed = X509CertificateParser.parseDer(der, fileName);
        if (parsed.error() != null) {
          CachedCertNode errNode = new CachedCertNode();
          errNode.id = "invalid:" + fileId;
          errNode.name = fileName;
          errNode.category = X509CertificateParser.Category.UNSUPPORTED;
          errNode.subjectCN = "UNKNOWN";
          errNode.issuerCN = "UNKNOWN";
          errNode.isCa = false;
          errNode.allowsCertSigning = false;
          errNode.materialRefs.add(fileRef);
          errNode.error = "文件格式非法或非有效证书";
          certMap.put(errNode.id, errNode);
        } else {
          String certId = "cert:" + parsed.fingerprint();
          CachedCertNode node = certMap.computeIfAbsent(certId, k -> {
            CachedCertNode n = new CachedCertNode();
            n.id = certId;
            n.fingerprint = parsed.fingerprint();
            n.name = fileName;
            n.subjectCN = parsed.subjectCN();
            n.issuerCN = parsed.issuerCN();
            n.subjectDer = parsed.subjectDer();
            n.issuerDer = parsed.issuerDer();
            n.rawDer = parsed.rawDer();
            n.tbsDer = parsed.tbsDer();
            n.signature = parsed.signature();
            n.serialNumber = parsed.serialNumber();
            n.notBefore = parsed.notBefore();
            n.notAfter = parsed.notAfter();
            n.isCa = parsed.isCa();
            n.allowsCertSigning = parsed.allowsCertSigning();
            n.spkiDer = parsed.spkiDer();
            n.spkiFingerprint = X509CertificateParser.sha256Hex(parsed.spkiDer());
            return n;
          });
          node.materialRefs.add(fileRef);
          if (node.downloadRef == null) {
            node.downloadRef = fileRef;
          }
        }
      } else {
        // Multi-cert bundle
        List<String> bundleCertIds = new ArrayList<>();
        for (byte[] der : certDers) {
          X509CertificateParser.ParsedResult parsed = X509CertificateParser.parseDer(der, fileName);
          if (parsed.error() == null) {
            String certId = "cert:" + parsed.fingerprint();
            CachedCertNode node = certMap.computeIfAbsent(certId, k -> {
              CachedCertNode n = new CachedCertNode();
              n.id = certId;
              n.fingerprint = parsed.fingerprint();
              n.name = fileName;
              n.subjectCN = parsed.subjectCN();
              n.issuerCN = parsed.issuerCN();
              n.subjectDer = parsed.subjectDer();
              n.issuerDer = parsed.issuerDer();
              n.rawDer = parsed.rawDer();
              n.tbsDer = parsed.tbsDer();
              n.signature = parsed.signature();
              n.serialNumber = parsed.serialNumber();
              n.notBefore = parsed.notBefore();
              n.notAfter = parsed.notAfter();
              n.isCa = parsed.isCa();
              n.allowsCertSigning = parsed.allowsCertSigning();
              n.spkiDer = parsed.spkiDer();
              n.spkiFingerprint = X509CertificateParser.sha256Hex(parsed.spkiDer());
              return n;
            });
            node.materialRefs.add(fileRef);
            bundleCertIds.add(certId);
          }
        }
        bundles.add(new BundleNodeDto(fileRef, fileName, bundleCertIds));
      }
    }

    // Now establish topology and signature verification
    List<CachedCertNode> allCerts = new ArrayList<>(certMap.values());
    for (CachedCertNode c : allCerts) {
      if (c.category == X509CertificateParser.Category.UNSUPPORTED || c.rawDer == null) {
        continue;
      }

      boolean selfIssued = Arrays.equals(c.subjectDer, c.issuerDer);
      if (selfIssued) {
        boolean selfVerified = verifyCertSignature(c.tbsDer, c.signature, c.rawDer);
        if (selfVerified) {
          if (c.isCa) {
            c.category = X509CertificateParser.Category.ROOT_CA;
          } else {
            c.category = X509CertificateParser.Category.SELF_SIGNED_END_ENTITY;
          }
        } else {
          c.category = X509CertificateParser.Category.UNSUPPORTED;
          c.error = "自签名证书签名校验未通过";
        }
      } else {
        // Look for candidate parents
        for (CachedCertNode candidate : allCerts) {
          if (candidate == c || candidate.rawDer == null) continue;
          if (Arrays.equals(candidate.subjectDer, c.issuerDer) && candidate.isCa && candidate.allowsCertSigning) {
            boolean sigOk = verifyCertSignature(c.tbsDer, c.signature, candidate.rawDer);
            if (sigOk) {
              c.parentRefs.add(candidate.id);
            }
          }
        }

        if (!c.parentRefs.isEmpty()) {
          if (c.isCa) {
            c.category = X509CertificateParser.Category.INTERMEDIATE_CA;
          } else {
            c.category = X509CertificateParser.Category.ISSUED_CERT;
          }
        } else {
          c.category = X509CertificateParser.Category.ORPHAN;
        }
      }
    }

    // Build SPKI indexes for CSR-Certificate matching
    Map<String, List<CachedCsrNode>> validCsrsBySpki = new LinkedHashMap<>();
    for (CachedCsrNode csr : csrNodes) {
      if (csr.error == null && csr.spkiFingerprint != null) {
        validCsrsBySpki.computeIfAbsent(csr.spkiFingerprint, k -> new ArrayList<>()).add(csr);
      }
    }

    Map<String, List<CachedCertNode>> validCertsBySpki = new LinkedHashMap<>();
    for (CachedCertNode cert : allCerts) {
      if (cert.category != X509CertificateParser.Category.UNSUPPORTED && cert.spkiFingerprint != null) {
        validCertsBySpki.computeIfAbsent(cert.spkiFingerprint, k -> new ArrayList<>()).add(cert);
      }
    }

    // 1. Process CSR matching
    for (CachedCsrNode csr : csrNodes) {
      if (csr.error != null) {
        csr.matchKind = "INVALID_CSR";
        csr.ambiguous = false;
        csr.matchedCertIds = List.of();
        continue;
      }
      List<CachedCertNode> matchedCerts = validCertsBySpki.getOrDefault(csr.spkiFingerprint, List.of());
      int sameKeyCsrCount = validCsrsBySpki.getOrDefault(csr.spkiFingerprint, List.of()).size();
      if (matchedCerts.isEmpty()) {
        csr.matchKind = "UNMATCHED";
        csr.ambiguous = (sameKeyCsrCount > 1);
        csr.matchedCertIds = List.of();
      } else {
        csr.matchedCertIds = matchedCerts.stream().map(c -> c.id).toList();
        csr.ambiguous = (matchedCerts.size() > 1 || sameKeyCsrCount > 1);
        boolean allSubjectMatch = true;
        for (CachedCertNode c : matchedCerts) {
          if (csr.subjectDer == null || c.subjectDer == null || !Arrays.equals(csr.subjectDer, c.subjectDer)) {
            allSubjectMatch = false;
            break;
          }
        }
        csr.matchKind = allSubjectMatch ? "KEY_AND_SUBJECT_MATCH" : "KEY_MATCH_DIFFERENT_SUBJECT";
      }
    }

    // 2. Process Certificate matching
    for (CachedCertNode cert : allCerts) {
      if (cert.category == X509CertificateParser.Category.UNSUPPORTED || cert.spkiFingerprint == null) {
        cert.matchedCsrRefs = List.of();
        cert.csrMatchEvidence = null;
        continue;
      }
      List<CachedCsrNode> matchedCsrs = validCsrsBySpki.getOrDefault(cert.spkiFingerprint, List.of());
      if (matchedCsrs.isEmpty()) {
        cert.matchedCsrRefs = List.of();
        cert.csrMatchEvidence = null;
      } else {
        cert.matchedCsrRefs = matchedCsrs.stream().map(csr -> csr.fileRef).toList();
        if (matchedCsrs.size() > 1) {
          cert.csrMatchEvidence = "AMBIGUOUS_MATCH";
        } else {
          CachedCsrNode singleCsr = matchedCsrs.get(0);
          if (cert.subjectDer != null && singleCsr.subjectDer != null && Arrays.equals(cert.subjectDer, singleCsr.subjectDer)) {
            cert.csrMatchEvidence = "KEY_AND_SUBJECT_MATCH";
          } else {
            cert.csrMatchEvidence = "KEY_MATCH_DIFFERENT_SUBJECT";
          }
        }
      }
    }

    List<CsrNodeDto> csrs = new ArrayList<>();
    for (CachedCsrNode csr : csrNodes) {
      csrs.add(new CsrNodeDto(
          csr.fileRef,
          csr.fileName,
          csr.subjectCN,
          csr.createdAt,
          csr.spkiFingerprint,
          csr.matchedCertIds,
          csr.matchKind,
          csr.ambiguous,
          csr.error
      ));
    }

    return new ProjectCertCache(snapshotKey, allCerts, csrs, bundles);
  }

  private boolean verifyCsrSignature(byte[] criDer, byte[] signature, byte[] spkiDer) {
    if (criDer == null || signature == null || spkiDer == null) return false;
    try {
      String pubPem = "-----BEGIN PUBLIC KEY-----\n"
          + Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(spkiDer)
          + "\n-----END PUBLIC KEY-----\n";

      Map<String, Object> req = new LinkedHashMap<>();
      req.put("id", UUID.randomUUID().toString());
      req.put("toolId", "sm2verify");
      req.put("parameters", Map.of(
          "pubkey", "input:pubkey",
          "in", "input:cri",
          "sig", "input:sig"
      ));
      req.put("inputs", Map.of(
          "pubkey", Map.of("name", "pub.pem", "contentBase64", Base64.getEncoder().encodeToString(pubPem.getBytes(StandardCharsets.US_ASCII))),
          "cri", Map.of("name", "cri.der", "contentBase64", Base64.getEncoder().encodeToString(criDer)),
          "sig", Map.of("name", "sig.der", "contentBase64", Base64.getEncoder().encodeToString(signature))
      ));
      req.put("timeoutSeconds", 5);

      JsonNode res = engine.request("POST", "/executions", req, 5);
      return res != null && res.has("exitCode") && res.get("exitCode").asInt() == 0;
    } catch (Exception e) {
      return false;
    }
  }

  private boolean verifyCertSignature(byte[] certTbs, byte[] certSig, byte[] issuerCertDer) {
    if (certTbs == null || certSig == null || issuerCertDer == null) return false;
    try {
      String issuerPem = "-----BEGIN CERTIFICATE-----\n"
          + Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(issuerCertDer)
          + "\n-----END CERTIFICATE-----\n";

      Map<String, Object> req = new LinkedHashMap<>();
      req.put("id", UUID.randomUUID().toString());
      req.put("toolId", "sm2verify");
      req.put("parameters", Map.of(
          "cert", "input:cert",
          "in", "input:tbs",
          "sig", "input:sig"
      ));
      req.put("inputs", Map.of(
          "cert", Map.of("name", "cert.pem", "contentBase64", Base64.getEncoder().encodeToString(issuerPem.getBytes(StandardCharsets.US_ASCII))),
          "tbs", Map.of("name", "tbs.der", "contentBase64", Base64.getEncoder().encodeToString(certTbs)),
          "sig", Map.of("name", "sig.der", "contentBase64", Base64.getEncoder().encodeToString(certSig))
      ));
      req.put("timeoutSeconds", 5);

      JsonNode res = engine.request("POST", "/executions", req, 5);
      return res != null && res.has("exitCode") && res.get("exitCode").asInt() == 0;
    } catch (Exception e) {
      return false;
    }
  }
}
