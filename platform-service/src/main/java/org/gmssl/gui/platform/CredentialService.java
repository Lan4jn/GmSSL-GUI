package org.gmssl.gui.platform;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

@Service
public class CredentialService {
  private final Store s;
  private final Vault vault;
  private final TransactionTemplate tx;

  public CredentialService(Store s, Vault vault, TransactionTemplate tx) {
    this.s = s;
    this.vault = vault;
    this.tx = tx;
  }

  private byte[] aad(String pid, String materialId) {
    return (pid + ":" + materialId + ":KEY_PASSPHRASE").getBytes(StandardCharsets.UTF_8);
  }

  static void validatePassphrase(String passphrase) {
    if (passphrase == null || passphrase.isEmpty()) {
      throw ApiError.bad("Passphrase cannot be empty");
    }
    byte[] bytes = passphrase.getBytes(StandardCharsets.UTF_8);
    try {
      if (bytes.length > 512 || passphrase.indexOf(0) >= 0
          || passphrase.indexOf('\r') >= 0 || passphrase.indexOf('\n') >= 0) {
        throw ApiError.bad("Invalid passphrase: maximum 512 UTF-8 bytes and no CR/LF/NUL allowed");
      }
    } finally {
      Arrays.fill(bytes, (byte) 0);
    }
  }

  public void savePassphrase(String pid, String materialId, String passphrase) {
    validatePassphrase(passphrase);
    byte[] plain = passphrase.getBytes(StandardCharsets.UTF_8);
    byte[] encrypted;
    try {
      encrypted = vault.encryptWithAad(plain, aad(pid, materialId));
    } finally {
      Arrays.fill(plain, (byte) 0);
    }

    String now = s.now();
    tx.executeWithoutResult(
        status -> {
          // Verify ownership and acquire row lock
          s.one(
              "select id from materials where project_id=? and id=? for update",
              pid,
              materialId);

          List<Map<String, Object>> existing =
              s.rows("select material_id from key_credentials where material_id=?", materialId);
          if (!existing.isEmpty()) {
            s.db.update(
                "update key_credentials set encrypted_passphrase=?, updated_at=? where material_id=?",
                encrypted,
                now,
                materialId);
          } else {
            s.db.update(
                "insert into key_credentials(material_id, encrypted_passphrase, created_at, updated_at)"
                    + " values(?,?,?,?)",
                materialId,
                encrypted,
                now,
                now);
          }
        });
  }

  public String getPassphrase(String pid, String materialId) {
    // Validate material exists and belongs to this project
    s.one("select id from materials where project_id=? and id=?", pid, materialId);

    List<Map<String, Object>> rows =
        s.rows("select encrypted_passphrase from key_credentials where material_id=?", materialId);
    if (rows.isEmpty()) {
      return null;
    }
    byte[] encrypted = (byte[]) rows.getFirst().get("encrypted_passphrase");
    if (encrypted == null) {
      return null;
    }
    byte[] plain = vault.decryptWithAad(encrypted, aad(pid, materialId));
    try {
      return new String(plain, StandardCharsets.UTF_8);
    } finally {
      Arrays.fill(plain, (byte) 0);
    }
  }

  public boolean hasPassphrase(String materialId) {
    if (materialId == null || materialId.isBlank()) {
      return false;
    }
    return !s.rows("select 1 from key_credentials where material_id=?", materialId).isEmpty();
  }

  public void deletePassphrase(String materialId) {
    s.db.update("delete from key_credentials where material_id=?", materialId);
  }
}
