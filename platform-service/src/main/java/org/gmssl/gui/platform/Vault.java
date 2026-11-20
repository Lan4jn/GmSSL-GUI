package org.gmssl.gui.platform;

import jakarta.annotation.PostConstruct;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
class Vault {
  static final int LIMIT = 16 * 1024 * 1024;
  final Path root;
  final SecretKeySpec key;
  final SecureRandom random = new SecureRandom();

  Vault(
      @Value("${GMSSL_VAULT_DIR:./data/vault}") String path,
      @Value("${GMSSL_VAULT_MASTER_KEY:}") String master) {
    try {
      byte[] bytes = Base64.getDecoder().decode(master);
      if (bytes.length != 32) throw new IllegalArgumentException();
      key = new SecretKeySpec(bytes, "AES");
      Arrays.fill(bytes, (byte) 0);
      root = Path.of(path).toAbsolutePath().normalize();
    } catch (Exception e) {
      throw new IllegalStateException("A base64 encoded 32-byte vault master key is required");
    }
  }

  @PostConstruct
  void init() throws IOException {
    Files.createDirectories(root);
    if (Files.isSymbolicLink(root)) throw new IOException("Vault root symlink forbidden");
    try {
      Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"));
    } catch (UnsupportedOperationException ignored) {
    }
  }

  Path path(String id) {
    try {
      UUID.fromString(id);
    } catch (Exception e) {
      throw ApiError.bad("Invalid object id");
    }
    Path p = root.resolve(id + ".vault");
    if (Files.isSymbolicLink(p))
      throw new ApiError(500, "VAULT_INTEGRITY", "Vault integrity failure");
    return p;
  }

  byte[] encrypt(String project, String id, byte[] plain) {
    return encryptWithAad(plain, (project + ":" + id).getBytes(StandardCharsets.UTF_8));
  }

  byte[] encryptWithAad(byte[] plain, byte[] aad) {
    try {
      if (plain.length > LIMIT) throw ApiError.bad("Material exceeds size limit");
      byte[] nonce = new byte[12];
      random.nextBytes(nonce);
      Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
      c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, nonce));
      if (aad != null && aad.length > 0) {
        c.updateAAD(aad);
      }
      byte[] enc = c.doFinal(plain);
      return java.nio.ByteBuffer.allocate(nonce.length + enc.length).put(nonce).put(enc).array();
    } catch (GeneralSecurityException e) {
      throw new ApiError(500, "VAULT_ERROR", "Vault encryption failed");
    }
  }

  byte[] decryptWithAad(byte[] all, byte[] aad) {
    try {
      if (all == null || all.length < 28) throw new IOException("Invalid ciphertext");
      Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
      c.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, Arrays.copyOf(all, 12)));
      if (aad != null && aad.length > 0) {
        c.updateAAD(aad);
      }
      return c.doFinal(all, 12, all.length - 12);
    } catch (IOException | GeneralSecurityException e) {
      throw new ApiError(500, "VAULT_INTEGRITY", "Vault integrity verification failed");
    }
  }

  void write(String project, String id, byte[] plain, boolean replace) {
    Path dst = path(id), tmp = null;
    try {
      tmp =
          Files.createTempFile(
              root,
              "staged-",
              ".vault",
              PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
      Files.write(tmp, encrypt(project, id, plain));
      try (var channel = java.nio.channels.FileChannel.open(tmp, StandardOpenOption.WRITE)) {
        channel.force(true);
      }
      if (!replace && Files.exists(dst, LinkOption.NOFOLLOW_LINKS))
        throw new IOException("Object exists");
      if (replace)
        Files.move(tmp, dst, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
      else Files.move(tmp, dst, StandardCopyOption.ATOMIC_MOVE);
      try (var directory = java.nio.channels.FileChannel.open(root, StandardOpenOption.READ)) {
        directory.force(true);
      }
    } catch (IOException e) {
      throw new ApiError(500, "VAULT_ERROR", "Vault persistence failed");
    } finally {
      if (tmp != null && tmp.normalize().getParent().equals(root))
        try {
          Files.deleteIfExists(tmp);
        } catch (IOException ignored) {
        }
    }
  }

  byte[] read(String project, String id) {
    try {
      Path p = path(id);
      if (Files.size(p) > LIMIT + 28) throw new IOException();
      byte[] all = Files.readAllBytes(p);
      if (all.length < 28) throw new IOException();
      return decryptWithAad(all, (project + ":" + id).getBytes(StandardCharsets.UTF_8));
    } catch (IOException e) {
      throw new ApiError(500, "VAULT_INTEGRITY", "Vault integrity verification failed");
    }
  }

  String statefulDigest(byte[] data) {
    try {
      Mac derive = Mac.getInstance("HmacSHA256");
      derive.init(new SecretKeySpec(key.getEncoded(), "HmacSHA256"));
      byte[] subkey =
          derive.doFinal("gmssl-platform-stateful-dedup-v1".getBytes(StandardCharsets.US_ASCII));
      Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(new SecretKeySpec(subkey, "HmacSHA256"));
      Arrays.fill(subkey, (byte) 0);
      return HexFormat.of().formatHex(mac.doFinal(data));
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("Stateful identity check failed");
    }
  }

  void delete(String id) {
    try {
      Files.deleteIfExists(path(id));
    } catch (IOException e) {
      throw new ApiError(500, "VAULT_ERROR", "Vault cleanup failed");
    }
  }
}
