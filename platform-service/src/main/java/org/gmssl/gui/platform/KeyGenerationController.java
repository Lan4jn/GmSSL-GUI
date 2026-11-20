package org.gmssl.gui.platform;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;
import java.util.Objects;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1")
public class KeyGenerationController {
  private final KeyGenerationService keyGenService;
  private final CredentialService credentialService;
  private final Materials materials;
  private final Auth auth;
  private final Store store;

  public KeyGenerationController(
      KeyGenerationService keyGenService,
      CredentialService credentialService,
      Materials materials,
      Auth auth,
      Store store) {
    this.keyGenService = keyGenService;
    this.credentialService = credentialService;
    this.materials = materials;
    this.auth = auth;
    this.store = store;
  }

  @GetMapping("/key-generation-capabilities")
  public Object capabilities(HttpServletRequest r) {
    auth.uid(r);
    return keyGenService.getCapabilities();
  }

  @PostMapping("/projects/{pid}/keys/generate")
  public Object generate(
      @PathVariable String pid,
      @RequestBody Map<String, Object> body,
      HttpServletRequest r) {
    auth.project(r, pid, 2);
    String uid = auth.uid(r);
    var result = keyGenService.generate(pid, uid, body);
    String resourceId = null;
    if (result.get("key") instanceof Map<?, ?> k && k.get("id") != null) {
      resourceId = k.get("id").toString();
    } else if (result.get("temporaryFile") instanceof Map<?, ?> f && f.get("id") != null) {
      resourceId = f.get("id").toString();
    }
    store.audit(
        pid,
        uid,
        "GENERATE_KEY",
        "KEY",
        resourceId,
        "SUCCESS");
    return result;
  }

  @PostMapping({"/projects/{pid}/keys/{id}/passphrase", "/projects/{pid}/files/{id}/passphrase"})
  public Object setPassphrase(
      @PathVariable String pid,
      @PathVariable String id,
      @RequestBody Map<String, String> body,
      HttpServletRequest r) {
    auth.project(r, pid, 2);
    var material = materials.raw(pid, id);
    if ("STATEFUL_PRIVATE_KEY".equals(material.get("key_kind"))
        || Store.bool(material, "stateful")) {
      throw ApiError.bad("Stateful private key does not support passphrase");
    }
    String pass = body.get("password");
    if (pass == null) {
      pass = body.get("passphrase");
    }
    if (pass == null || pass.isEmpty()) {
      throw ApiError.bad("Password cannot be empty");
    }
    credentialService.savePassphrase(pid, id, pass);
    store.audit(pid, auth.uid(r), "UPDATE_KEY_CREDENTIAL", material.get("object_type").toString(), id, "SUCCESS");
    return Map.of(
        "success", true,
        "id", id,
        "hasManagedPassphrase", true,
        "note", "Managed credential updated; does not re-encrypt underlying key file");
  }

  @PostMapping({"/projects/{pid}/keys/{id}/reveal-passphrase", "/projects/{pid}/files/{id}/reveal-passphrase"})
  public ResponseEntity<Map<String, Object>> revealPassphrase(
      @PathVariable String pid,
      @PathVariable String id,
      HttpServletRequest r) {
    auth.project(r, pid, 2);
    var material = materials.raw(pid, id);
    if ("STATEFUL_PRIVATE_KEY".equals(material.get("key_kind"))
        || Store.bool(material, "stateful")) {
      throw ApiError.denied();
    }
    String pass = credentialService.getPassphrase(pid, id);
    if (pass == null) {
      throw new ApiError(404, "NO_PASSPHRASE", "No managed passphrase found for this key");
    }
    store.audit(pid, auth.uid(r), "REVEAL_KEY_PASSPHRASE", material.get("object_type").toString(), id, "SUCCESS");
    return ResponseEntity.ok()
        .header("Cache-Control", "no-store")
        .header("Pragma", "no-cache")
        .body(Map.of("id", id, "passphrase", pass));
  }
}
