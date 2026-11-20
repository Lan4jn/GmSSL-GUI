package org.gmssl.gui.platform;

import jakarta.servlet.http.HttpServletRequest;
import java.util.*;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api/v1/projects/{pid}")
class MaterialController {
  final Materials m;
  final Auth auth;
  final Store s;
  final CertificateTreeService certTreeService;

  MaterialController(Materials m, Auth a, Store s, CertificateTreeService certTreeService) {
    this.m = m;
    auth = a;
    this.s = s;
    this.certTreeService = certTreeService;
  }

  @GetMapping("/certificates")
  Object certificates(@PathVariable String pid, HttpServletRequest r) {
    auth.project(r, pid, 1);
    return certTreeService.getCertificates(pid);
  }

  @GetMapping({"/keys", "/files"})
  Object list(@PathVariable String pid, HttpServletRequest r) {
    auth.project(r, pid, 1);
    String type = r.getRequestURI().endsWith("/keys") ? "KEY" : "FILE";
    return s
        .rows(
            "select * from materials where project_id=? and object_type=? order by created_at",
            pid,
            type)
        .stream()
        .map(m::dto)
        .toList();
  }

  @PostMapping("/keys")
  Object key(
      @PathVariable String pid,
      @RequestParam MultipartFile file,
      @RequestParam Map<String, String> b,
      HttpServletRequest r)
      throws Exception {
    auth.project(r, pid, 2);
    if ("true".equalsIgnoreCase(b.get("temporary")))
      throw ApiError.bad("Temporary is only allowed for FILE");
    var result =
        m.create(pid, "KEY", b.get("name"), "application/octet-stream", file.getBytes(), b);
    s.audit(pid, auth.uid(r), "IMPORT_KEY", "KEY", result.get("id").toString(), "SUCCESS");
    return result;
  }

  @PostMapping("/files")
  Object file(
      @PathVariable String pid,
      @RequestParam MultipartFile file,
      @RequestParam(required = false, defaultValue = "false") boolean temporary,
      HttpServletRequest r)
      throws Exception {
    auth.project(r, pid, 2);
    var result =
        m.create(
            pid,
            "FILE",
            file.getOriginalFilename() == null ? "upload" : file.getOriginalFilename(),
            "application/octet-stream",
            file.getBytes(),
            Map.of("temporary", String.valueOf(temporary)));
    s.audit(pid, auth.uid(r), "UPLOAD", "FILE", result.get("id").toString(), "SUCCESS");
    return result;
  }

  @GetMapping({"/keys/{id}", "/files/{id}"})
  Object get(@PathVariable String pid, @PathVariable String id, HttpServletRequest r) {
    auth.project(r, pid, 1);
    return m.dto(m.raw(pid, id, r.getRequestURI().contains("/keys/") ? "KEY" : "FILE"));
  }

  @DeleteMapping({"/keys/{id}", "/files/{id}"})
  ResponseEntity<?> delete(
      @PathVariable String pid, @PathVariable String id, HttpServletRequest r) {
    auth.project(r, pid, 2);
    m.raw(pid, id, r.getRequestURI().contains("/keys/") ? "KEY" : "FILE");
    m.delete(pid, id);
    s.audit(pid, auth.uid(r), "DELETE_MATERIAL", "MATERIAL", id, "SUCCESS");
    return ResponseEntity.noContent().build();
  }

  @GetMapping({"/keys/{id}/download", "/files/{id}/download"})
  ResponseEntity<byte[]> download(
      @PathVariable String pid, @PathVariable String id, HttpServletRequest r) {
    auth.project(r, pid, 1);
    var material = m.raw(pid, id, r.getRequestURI().contains("/keys/") ? "KEY" : "FILE");
    if ("STATEFUL_PRIVATE_KEY".equals(material.get("key_kind"))) throw ApiError.denied();
    if (!"PUBLIC_KEY".equals(material.get("key_kind"))) auth.project(r, pid, 2);
    if (Store.bool(material, "pending"))
      throw new ApiError(409, "KEY_PENDING", "Stateful key requires recovery");
    s.audit(pid, auth.uid(r), "DOWNLOAD_MATERIAL", "MATERIAL", id, "SUCCESS");
    return binary(m.vault.read(pid, id), Store.str(material, "name"));
  }

  static ResponseEntity<byte[]> binary(byte[] bytes, String name) {
    return ResponseEntity.ok()
        .contentType(MediaType.APPLICATION_OCTET_STREAM)
        .header(
            "Content-Disposition",
            ContentDisposition.attachment()
                .filename(name, java.nio.charset.StandardCharsets.UTF_8)
                .build()
                .toString())
        .header("Cache-Control", "no-store")
        .body(bytes);
  }
}
