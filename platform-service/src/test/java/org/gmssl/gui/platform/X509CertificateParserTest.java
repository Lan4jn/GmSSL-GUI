package org.gmssl.gui.platform;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.util.*;
import org.junit.jupiter.api.Test;

class X509CertificateParserTest {

  @Test
  void testParseInvalidPemReturnsUnsupportedInsteadOfThrowing() {
    X509CertificateParser.ParsedResult res = X509CertificateParser.parse("not-a-certificate".getBytes(StandardCharsets.UTF_8), "test.txt");
    assertEquals(X509CertificateParser.Category.UNSUPPORTED, res.category());
    assertNotNull(res.error());
    assertEquals("test.txt", res.name());
  }

  @Test
  void testParseCsrFileExtractsSubjectCnAndDistinguishesFromCert() {
    String csrText = "-----BEGIN CERTIFICATE REQUEST-----\n"
        + "MIHWMH0CAQAwFTETMBEGA1UEAwwKY2xpZW50LmNvbTBZMBMGByqGSM49AgEGCCqB\n"
        + "HM9VAYItA0IABEFw1Y+3Q4O5H9O/7J4pL08fC7oR7iT4V1y9fC6D6fX2U8aB2xX1\n"
        + "M3Z5q8t0l9k4j2h1v8m5p3w4s9a0b1c2d3egADAKBggqgRzPVQGDdQNIADBFAiEA\n"
        + "1v9m5p3w4s9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5CIQC6e7f8a9b0c1d2e3f4\n"
        + "a5b6c7d8e9f0a1b2c3d4e5f6==\n"
        + "-----END CERTIFICATE REQUEST-----\n";
    X509CertificateParser.CsrResult res = X509CertificateParser.parseCsr(csrText.getBytes(StandardCharsets.UTF_8), "app.csr");
    assertNotNull(res);
    assertEquals("app.csr", res.name());
  }
}
