package org.gmssl.gui.platform;

import com.fasterxml.jackson.databind.JsonNode;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicInteger;
import org.springframework.stereotype.Service;

@Service
public class KeyGenerationService {
  private final Engine engine;
  private final Materials materials;
  private final CredentialService credentials;
  private final Store store;
  private final SecureRandom rng = new SecureRandom();
  private final ConcurrentMap<String, AtomicInteger> activePerUser = new ConcurrentHashMap<>();

  private static final String PWD_CHARS =
      "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*";

  public KeyGenerationService(
      Engine engine, Materials materials, CredentialService credentials, Store store) {
    this.engine = engine;
    this.materials = materials;
    this.credentials = credentials;
    this.store = store;
  }

  public JsonNode getCapabilities() {
    return engine.keyGenerationCapabilities();
  }

  public String generateRandomPassword() {
    byte[] bytes = new byte[24];
    rng.nextBytes(bytes);
    StringBuilder sb = new StringBuilder(24);
    for (byte b : bytes) {
      sb.append(PWD_CHARS.charAt((b & 0xFF) % PWD_CHARS.length()));
    }
    return sb.toString();
  }

  public Map<String, Object> generate(String pid, String uid, Map<String, Object> req) {
    return generateWithTimeout(pid, uid, req, 30);
  }

  Map<String, Object> generateWithTimeout(
      String pid, String uid, Map<String, Object> req, int timeoutSeconds) {
    if (timeoutSeconds < 1) {
      throw new ApiError(504, "TIMED_OUT", "Key generation budget exhausted");
    }
    timeoutSeconds = Math.min(timeoutSeconds, 30);
    AtomicInteger userActive = activePerUser.computeIfAbsent(uid, u -> new AtomicInteger(0));
    if (userActive.incrementAndGet() > 2) {
      userActive.decrementAndGet();
      throw new ApiError(429, "CONCURRENCY_LIMIT", "Per-user key generation limit reached");
    }
    try {
      return doGenerate(pid, uid, req, timeoutSeconds);
    } finally {
      userActive.decrementAndGet();
    }
  }

  private Map<String, Object> doGenerate(
      String pid, String uid, Map<String, Object> req, int timeoutSeconds) {
    String provider = Objects.toString(req.getOrDefault("provider", "gmssl"), "gmssl").trim().toLowerCase();
    if (!Set.of("gmssl", "openssl").contains(provider)) {
      throw ApiError.bad("Unsupported provider: " + provider);
    }

    String algorithm = Objects.toString(req.get("algorithm"), "").trim();
    if (algorithm.isEmpty()) {
      throw ApiError.bad("Algorithm is required");
    }
    algorithm = AccountController.bounded(algorithm, 100, true);

    String upperAlgo = algorithm.toUpperCase();
    if (upperAlgo.startsWith("LMS")
        || upperAlgo.startsWith("XMSS")
        || upperAlgo.startsWith("HSS")
        || "STATEFUL_PRIVATE_KEY".equalsIgnoreCase(Objects.toString(req.get("keyKind"), ""))) {
      throw ApiError.bad("Stateful private keys must be generated via controlled platform jobs");
    }
    if (upperAlgo.startsWith("SPHINCS")
        || upperAlgo.startsWith("SM9")
        || upperAlgo.startsWith("DILITHIUM")
        || upperAlgo.startsWith("FALCON")) {
      throw ApiError.bad("Algorithm " + algorithm + " not supported by quick generation; use dedicated platform job");
    }
    if (provider.equals("openssl") && upperAlgo.startsWith("KYBER")) {
      throw ApiError.bad("OpenSSL does not support algorithm: Kyber");
    }

    String storage = Objects.toString(req.getOrDefault("storage", "MANAGED"), "MANAGED").trim().toUpperCase();
    if (!Set.of("MANAGED", "TEMPORARY").contains(storage)) {
      throw ApiError.bad("Storage must be MANAGED or TEMPORARY");
    }

    if (req.get("curve") != null) {
      AccountController.bounded(req.get("curve").toString(), 100, true);
    }
    if (req.get("bits") != null) {
      if (!(req.get("bits") instanceof Number num) || num.intValue() <= 0) {
        throw ApiError.bad("Invalid bits parameter: must be a positive integer");
      }
    }

    String customPassword = req.get("password") == null ? null : req.get("password").toString();
    if (customPassword != null && !customPassword.isEmpty()) {
      CredentialService.validatePassphrase(customPassword);
    }

    boolean isAsymmetric = isAsymmetricAlgorithm(algorithm);
    boolean requiresPassword = isAsymmetric && !upperAlgo.startsWith("KYBER");
    String passwordForEngine = null;
    if (requiresPassword) {
      passwordForEngine = (customPassword != null && !customPassword.isBlank()) ? customPassword : generateRandomPassword();
    }

    String name = req.get("name") != null && !req.get("name").toString().isBlank()
        ? AccountController.bounded(req.get("name").toString(), 200, false).replaceAll("[\\r\\n\\x00]", "_")
        : algorithm.toLowerCase() + "-" + (storage.equals("TEMPORARY") ? "temp" : "key");

    Map<String, Object> engineBody = new LinkedHashMap<>();
    engineBody.put("requestId", store.id());
    engineBody.put("provider", provider);
    engineBody.put("algorithm", algorithm);
    if (req.get("bits") != null) {
      engineBody.put("bits", req.get("bits"));
    }
    if (req.get("curve") != null) {
      engineBody.put("curve", req.get("curve"));
    }
    if (passwordForEngine != null) {
      engineBody.put("password", passwordForEngine);
    }
    engineBody.put("timeoutSeconds", timeoutSeconds);

    JsonNode engineRes = engine.keyGeneration(engineBody, timeoutSeconds);
    String keyKind = engineRes.path("keyKind").asText("SYMMETRIC_KEY");
    String encoding = engineRes.path("encoding").asText("HEX");
    List<String> warnings = new ArrayList<>();
    if (engineRes.has("warnings") && engineRes.path("warnings").isArray()) {
      for (JsonNode w : engineRes.path("warnings")) {
        warnings.add(w.asText());
      }
    }

    Map<String, Object> response = new LinkedHashMap<>();
    response.put("provider", provider);
    response.put("algorithm", algorithm);
    response.put("storage", storage);
    response.put("warnings", warnings);

    if ("SYMMETRIC_KEY".equalsIgnoreCase(keyKind)) {
      byte[] rawBytes;
      String valB64 = engineRes.path("valueBase64").asText("");
      if (!valB64.isBlank()) {
        rawBytes = Base64.getDecoder().decode(valB64);
      } else {
        throw new ApiError(500, "ENGINE_ERROR", "Missing generated symmetric key content");
      }

      String hexVal;
      if ("HEX".equalsIgnoreCase(encoding)) {
        String testStr = new String(rawBytes, StandardCharsets.US_ASCII).trim();
        if (!testStr.matches("(?:[0-9a-fA-F]{2})+")) {
          throw new ApiError(500, "ENGINE_ERROR", "Engine returned invalid HEX content");
        }
        hexVal = testStr;
      } else if ("RAW".equalsIgnoreCase(encoding)) {
        hexVal = HexFormat.of().formatHex(rawBytes);
      } else {
        throw new ApiError(500, "ENGINE_ERROR", "Unsupported symmetric key encoding from engine: " + encoding);
      }

      if (req.get("bits") instanceof Number numBits) {
        int expectedBytes = numBits.intValue() / 8;
        if (hexVal.length() / 2 != expectedBytes) {
          throw new ApiError(
              500,
              "ENGINE_ERROR",
              "Generated key length "
                  + (hexVal.length() / 2)
                  + " bytes does not match requested "
                  + expectedBytes
                  + " bytes");
        }
      }

      if ("MANAGED".equals(storage)) {
        byte[] hexBytes = hexVal.getBytes(StandardCharsets.US_ASCII);
        var keyDto = materials.createControlled(
            pid,
            "KEY",
            name,
            "application/octet-stream",
            hexBytes,
            Map.of(
                "keyKind", "SYMMETRIC_KEY",
                "algorithm", algorithm,
                "encoding", "HEX",
                "generationProvider", provider));
        response.put("reference", "key:" + keyDto.get("id"));
        response.put("key", keyDto);
      } else {
        response.put("valueHex", hexVal);
      }
    } else {
      String privB64 = engineRes.path("privateKeyBase64").asText("");
      if (privB64.isBlank()) {
        throw new ApiError(500, "ENGINE_ERROR", "Missing generated private key content");
      }
      byte[] privBytes = Base64.getDecoder().decode(privB64);

      String pubB64 = engineRes.path("publicKeyBase64").asText("");
      byte[] pubBytes = pubB64.isBlank() ? null : Base64.getDecoder().decode(pubB64);

      List<String> createdMaterialIds = new ArrayList<>();
      String generatedAlgorithm = algorithm;
      String generatedPassword = passwordForEngine;
      try {
        materials.tx.executeWithoutResult(status -> {
          if ("MANAGED".equals(storage)) {
            var privKeyDto = materials.createControlled(
                pid,
                "KEY",
                name,
                "application/x-pem-file",
                privBytes,
                Map.of(
                    "keyKind", "PRIVATE_KEY",
                    "algorithm", generatedAlgorithm,
                    "encoding", "PEM",
                    "generationProvider", provider));
            String privId = privKeyDto.get("id").toString();
            createdMaterialIds.add(privId);

            if (generatedPassword != null) {
              credentials.savePassphrase(pid, privId, generatedPassword);
            }

            Map<String, Object> pubKeyDto = null;
            if (pubBytes != null && pubBytes.length > 0) {
              pubKeyDto = materials.createControlled(
                  pid,
                  "KEY",
                  name + "-pub",
                  "application/x-pem-file",
                  pubBytes,
                  Map.of(
                      "keyKind", "PUBLIC_KEY",
                      "algorithm", generatedAlgorithm,
                      "encoding", "PEM",
                      "generationProvider", provider));
              createdMaterialIds.add(pubKeyDto.get("id").toString());
            }

            response.put("reference", "key:" + privId);
            response.put("key", materials.dto(materials.raw(pid, privId)));
            if (pubKeyDto != null) {
              response.put("publicKey", materials.dto(materials.raw(pid, pubKeyDto.get("id").toString())));
            }
          } else {
            var fileDto = materials.createControlled(
                pid,
                "FILE",
                name.endsWith(".pem") ? name : name + ".pem",
                "application/x-pem-file",
                privBytes,
                Map.of(
                    "temporary", "true",
                    "generationProvider", provider));
            String fileId = fileDto.get("id").toString();
            createdMaterialIds.add(fileId);

            if (generatedPassword != null) {
              credentials.savePassphrase(pid, fileId, generatedPassword);
            }

            Map<String, Object> tempPubFileDto = null;
            if (pubBytes != null && pubBytes.length > 0) {
              String pubFileName = name.endsWith(".pem")
                  ? name.substring(0, name.length() - 4) + "-pub.pem"
                  : name + "-pub.pem";
              tempPubFileDto = materials.createControlled(
                  pid,
                  "FILE",
                  pubFileName,
                  "application/x-pem-file",
                  pubBytes,
                  Map.of(
                      "temporary", "true",
                      "generationProvider", provider));
              createdMaterialIds.add(tempPubFileDto.get("id").toString());
            }

            response.put("reference", "file:" + fileId);
            response.put("temporaryFile", materials.dto(materials.raw(pid, fileId)));
            if (tempPubFileDto != null) {
              response.put("temporaryPublicKeyFile", materials.dto(materials.raw(pid, tempPubFileDto.get("id").toString())));
            }
          }
        });
      } catch (Exception e) {
        for (String matId : createdMaterialIds) {
          try {
            materials.vault.delete(matId);
          } catch (Exception cleanupFailure) {
            System.err.println("KEYGEN_VAULT_CLEANUP_FAILED project=" + pid + " material=" + matId);
          }
        }
        throw new ApiError(500, "KEY_PERSISTENCE_ERROR", "Generated key persistence failed");
      } finally {
        Arrays.fill(privBytes, (byte) 0);
        if (pubBytes != null) Arrays.fill(pubBytes, (byte) 0);
      }
    }

    return response;
  }

  private boolean isAsymmetricAlgorithm(String algo) {
    String u = algo.toUpperCase();
    return u.startsWith("SM2") || u.startsWith("EC") || u.startsWith("RSA") || u.startsWith("KYBER");
  }
}
