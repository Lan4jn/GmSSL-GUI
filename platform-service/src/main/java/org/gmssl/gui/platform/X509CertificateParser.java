package org.gmssl.gui.platform;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.*;

public class X509CertificateParser {

  public enum Category {
    ROOT_CA,
    INTERMEDIATE_CA,
    ISSUED_CERT,
    SELF_SIGNED_END_ENTITY,
    ORPHAN,
    UNSUPPORTED,
    ENGINE_PENDING
  }

  public enum ValidityStatus {
    VALID,
    EXPIRED,
    NOT_YET_VALID,
    UNKNOWN
  }

  public record ParsedResult(
      String fingerprint,
      String name,
      Category category,
      String subjectCN,
      String issuerCN,
      byte[] subjectDer,
      byte[] issuerDer,
      byte[] spkiDer,
      byte[] tbsDer,
      byte[] signature,
      byte[] rawDer,
      String serialNumber,
      Instant notBefore,
      Instant notAfter,
      ValidityStatus validityStatus,
      boolean isCa,
      byte[] keyUsage,
      boolean canSignCerts,
      Integer pathLen,
      String error
  ) {
    public boolean allowsCertSigning() {
      if (!isCa) return false;
      if (keyUsage == null) return true; // absent = not restricted
      return canSignCerts; // present = must have keyCertSign
    }
  }

  public record CsrResult(
      String name,
      String subjectCN,
      byte[] subjectDer,
      byte[] spkiDer,
      byte[] criDer,
      byte[] signature,
      String spkiFingerprint,
      String error
  ) {}

  public static record Der(byte[] bytes, int tag, int start, int body, int end) {
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
        result.add(child);
        at = child.end;
        if (result.size() > 128) throw new IllegalArgumentException("Too many DER elements");
      }
      return result;
    }

    byte[] value() { return Arrays.copyOfRange(bytes, body, end); }
    byte[] encoded() { return Arrays.copyOfRange(bytes, start, end); }
  }

  public static List<byte[]> extractAllCertificateDers(byte[] pemBytes) {
    List<byte[]> list = new ArrayList<>();
    String text = new String(pemBytes, StandardCharsets.US_ASCII);
    String begin = "-----BEGIN CERTIFICATE-----";
    String end = "-----END CERTIFICATE-----";
    int idx = 0;
    while (true) {
      int a = text.indexOf(begin, idx);
      if (a < 0) break;
      int b = text.indexOf(end, a + begin.length());
      if (b < 0) break;
      String b64 = text.substring(a + begin.length(), b).replaceAll("\\s", "");
      try {
        byte[] der = Base64.getDecoder().decode(b64);
        list.add(der);
      } catch (Exception ignored) {}
      idx = b + end.length();
    }
    return list;
  }

  public static String sha256Hex(byte[] der) {
    try {
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      byte[] digest = md.digest(der);
      return HexFormat.of().formatHex(digest);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  public static String extractCN(Der nameSeq) {
    try {
      for (Der rdnSet : nameSeq.children()) {
        for (Der atvSeq : rdnSet.children()) {
          var parts = atvSeq.children();
          if (parts.size() >= 2) {
            Der type = parts.get(0);
            Der value = parts.get(1);
            // OID 2.5.4.3 = 550403 (commonName)
            if (type.tag == 6 && "550403".equals(HexFormat.of().formatHex(type.value()))) {
              return new String(value.value(), StandardCharsets.UTF_8);
            }
          }
        }
      }
    } catch (Exception ignored) {}
    return "UNKNOWN";
  }

  public static Instant parseTime(Der time) {
    String value = new String(time.value(), StandardCharsets.US_ASCII);
    if (time.tag == 23 && value.matches("[0-9]{12}Z")) {
      int year = Integer.parseInt(value.substring(0, 2));
      value = (year >= 50 ? "19" : "20") + value;
    } else if (time.tag != 24 || !value.matches("[0-9]{14}Z")) {
      throw new IllegalArgumentException("Invalid X509 time");
    }
    return LocalDateTime.parse(value, DateTimeFormatter.ofPattern("uuuuMMddHHmmss'Z'"))
        .toInstant(ZoneOffset.UTC);
  }

  public static ParsedResult parseDer(byte[] der, String filename) {
    try {
      String fingerprint = sha256Hex(der);
      Der root = Der.read(der, 0, der.length);
      if (root.tag != 48 || root.end != der.length) throw new IllegalArgumentException("Invalid cert root sequence");
      var outer = root.children();
      if (outer.size() != 3 || outer.get(2).tag != 3 || outer.get(2).value().length == 0 || outer.get(2).value()[0] != 0)
        throw new IllegalArgumentException("Invalid certificate signature");

      Der tbs = outer.get(0);
      byte[] signature = Arrays.copyOfRange(outer.get(2).bytes, outer.get(2).body + 1, outer.get(2).end);
      var fields = tbs.children();
      int i = fields.getFirst().tag == 160 ? 1 : 0; // check for explicit version [0]

      Der serialDer = fields.get(i);
      String serialNumber = HexFormat.of().formatHex(serialDer.value());

      Der issuerDer = fields.get(i + 2);
      String issuerCN = extractCN(issuerDer);

      var validity = fields.get(i + 3).children();
      if (validity.size() != 2) throw new IllegalArgumentException("Invalid validity");
      Instant notBefore = parseTime(validity.get(0));
      Instant notAfter = parseTime(validity.get(1));

      Der subjectDer = fields.get(i + 4);
      String subjectCN = extractCN(subjectDer);

      Der spki = fields.get(i + 5);

      boolean isCa = false;
      Integer pathLen = null;
      byte[] keyUsage = null;

      for (int j = i + 6; j < fields.size(); j++) {
        Der field = fields.get(j);
        if (field.tag == 163) { // [3] extensions
          for (Der ext : field.children().getFirst().children()) {
            var parts = ext.children();
            String oid = HexFormat.of().formatHex(parts.getFirst().value());
            Der wrapped = parts.getLast();
            if (wrapped.tag == 4) {
              Der content = Der.read(der, wrapped.body, wrapped.end);
              if ("551d13".equals(oid)) { // basicConstraints
                var bc = content.children();
                int k = 0;
                if (!bc.isEmpty() && bc.getFirst().tag == 1) {
                  isCa = Arrays.equals(bc.getFirst().value(), new byte[]{(byte) 255});
                  k++;
                }
                if (k < bc.size() && bc.get(k).tag == 2) {
                  pathLen = new java.math.BigInteger(bc.get(k).value()).intValueExact();
                }
              } else if ("551d0f".equals(oid)) { // keyUsage
                keyUsage = content.value();
              }
            }
          }
        }
      }

      boolean canSignCerts = false;
      if (keyUsage != null && keyUsage.length > 1) {
        // In DER BIT STRING: keyUsage[0] is unused bits count, keyUsage[1] starts bit 0..7
        // keyCertSign is bit 5 (mask 0x04)
        canSignCerts = (keyUsage[1] & 4) != 0;
      }

      Instant now = Instant.now();
      ValidityStatus vs = ValidityStatus.VALID;
      if (now.isBefore(notBefore)) vs = ValidityStatus.NOT_YET_VALID;
      else if (now.isAfter(notAfter)) vs = ValidityStatus.EXPIRED;

      return new ParsedResult(
          fingerprint,
          filename,
          null,
          subjectCN,
          issuerCN,
          subjectDer.encoded(),
          issuerDer.encoded(),
          spki.encoded(),
          tbs.encoded(),
          signature,
          der,
          serialNumber,
          notBefore,
          notAfter,
          vs,
          isCa,
          keyUsage,
          canSignCerts,
          pathLen,
          null
      );
    } catch (Exception e) {
      return new ParsedResult(
          null, filename, Category.UNSUPPORTED, null, null, null, null, null, null, null, null, null, null, null, ValidityStatus.UNKNOWN, false, null, false, null, "文件格式非法或非有效证书"
      );
    }
  }

  public static ParsedResult parse(byte[] pemBytes, String filename) {
    List<byte[]> ders = extractAllCertificateDers(pemBytes);
    if (ders.isEmpty()) {
      return new ParsedResult(
          null, filename, Category.UNSUPPORTED, null, null, null, null, null, null, null, null, null, null, null, ValidityStatus.UNKNOWN, false, null, false, null, "文件格式非法或非有效证书"
      );
    }
    return parseDer(ders.getFirst(), filename);
  }

  public static CsrResult parseCsr(byte[] pemBytes, String filename) {
    try {
      String text = new String(pemBytes, StandardCharsets.US_ASCII);
      String begin = "-----BEGIN CERTIFICATE REQUEST-----";
      String end = "-----END CERTIFICATE REQUEST-----";
      int a = text.indexOf(begin), b = text.indexOf(end);
      if (a < 0 || b < a) throw new IllegalArgumentException("Not a CSR");
      byte[] der = Base64.getDecoder().decode(text.substring(a + begin.length(), b).replaceAll("\\s", ""));
      Der root = Der.read(der, 0, der.length);
      if (root.tag != 48 || root.end != der.length) throw new IllegalArgumentException("Invalid CSR root sequence");
      var outer = root.children();
      if (outer.size() != 3) throw new IllegalArgumentException("Invalid CSR structure");

      Der cri = outer.get(0);
      byte[] criDer = cri.encoded();

      Der sig = outer.get(2);
      if (sig.tag != 3 || sig.value().length == 0 || sig.value()[0] != 0) {
        throw new IllegalArgumentException("Invalid CSR signature element");
      }
      byte[] signature = Arrays.copyOfRange(sig.bytes, sig.body + 1, sig.end);

      var criFields = cri.children();
      if (criFields.size() < 3) throw new IllegalArgumentException("Invalid CertificationRequestInfo");
      Der subject = criFields.get(1);
      String subjectCN = extractCN(subject);
      Der spki = criFields.get(2);
      byte[] spkiDer = spki.encoded();
      String spkiFingerprint = sha256Hex(spkiDer);

      return new CsrResult(filename, subjectCN, subject.encoded(), spkiDer, criDer, signature, spkiFingerprint, null);
    } catch (Exception e) {
      return new CsrResult(filename, null, null, null, null, null, null, "文件格式非法或非有效证书请求");
    }
  }
}
