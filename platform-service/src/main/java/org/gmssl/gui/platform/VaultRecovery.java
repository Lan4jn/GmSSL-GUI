package org.gmssl.gui.platform;

import jakarta.annotation.PostConstruct;
import java.nio.file.*;
import java.time.*;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
class VaultRecovery {
  final Store s;
  final Vault vault;
  final Materials materials;

  VaultRecovery(Store s, Vault v, Materials m) {
    this.s = s;
    vault = v;
    materials = m;
  }

  @PostConstruct
  void cleanup() throws Exception {
    cleanupPhysicalOrphans();
    cleanupTemporaryFiles();
  }

  @Scheduled(fixedDelay = 60000)
  void periodicCleanup() {
    cleanupPhysicalOrphans();
    cleanupTemporaryFiles();
  }

  void cleanupPhysicalOrphans() {
    long cutoff = System.currentTimeMillis() - Duration.ofMinutes(5).toMillis();
    try (var files = Files.newDirectoryStream(vault.root)) {
      for (Path path : files) {
        if (Files.isSymbolicLink(path) || !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS))
          continue;
        if (Files.getLastModifiedTime(path, LinkOption.NOFOLLOW_LINKS).toMillis() > cutoff)
          continue;
        String name = path.getFileName().toString();
        if (name.matches("[0-9a-fA-F-]{36}\\.vault")) {
          String id = name.substring(0, 36);
          if (s.rows("select id from materials where id=?", id).isEmpty()) {
            try {
              vault.delete(id);
            } catch (Exception e) {
              System.err.println("Vault orphan cleanup error for " + id + ": " + e.getMessage());
            }
          }
        } else if (name.matches("staged-[A-Za-z0-9-]+\\.vault")
            && path.toAbsolutePath().normalize().getParent().equals(vault.root)) {
          try {
            Files.deleteIfExists(path);
          } catch (Exception e) {
            System.err.println("Vault staged cleanup error for " + path + ": " + e.getMessage());
          }
        }
      }
    } catch (Exception e) {
      System.err.println("Physical vault scan error: " + e.getMessage());
    }
  }

  void cleanupTemporaryFiles() {
    Instant cutoff = Instant.now().minus(Duration.ofHours(1));
    var unbounds =
        s.rows(
            "select id, project_id, created_at from materials where object_type='FILE' and"
                + " temporary=? and bound_job_id is null",
            Boolean.TRUE);
    for (var row : unbounds) {
      String id = row.get("id").toString();
      String pid = row.get("project_id").toString();
      String createdAt = row.get("created_at").toString();
      try {
        if (Instant.parse(createdAt).isBefore(cutoff)) {
          materials.delete(pid, id);
        }
      } catch (Exception e) {
        System.err.println(
            "Temporary file cleanup retry for " + id + ": " + e.getClass().getSimpleName());
      }
    }

    var terminalBound =
        s.rows(
            "select id, project_id from materials where object_type='FILE' and temporary=? and"
                + " bound_job_id in (select id from jobs where status in"
                + " ('SUCCEEDED','FAILED','CANCELLED','TIMED_OUT'))",
            Boolean.TRUE);
    for (var row : terminalBound) {
      String id = row.get("id").toString();
      String pid = row.get("project_id").toString();
      try {
        materials.delete(pid, id);
      } catch (Exception e) {
        System.err.println(
            "Terminal job temporary file cleanup retry for "
                + id
                + ": "
                + e.getClass().getSimpleName());
      }
    }
  }
}