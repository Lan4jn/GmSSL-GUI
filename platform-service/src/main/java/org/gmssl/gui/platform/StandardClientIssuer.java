package org.gmssl.gui.platform;

import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.*;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.jcajce.*;
import org.bouncycastle.operator.jcajce.*;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/** Dedicated, operator-pinned issuer. Neither CSR attributes nor request data select the CA. */
@Component
final class StandardClientIssuer {
  private static final String SIG = "SHA256withRSA";
  private final SecureRandom random = new SecureRandom();
  private final PrivateKey signingKey;
  private final List<X509Certificate> chain;
  private final String chainPem;

  StandardClientIssuer(
      @Value("${GMSSL_STANDARD_CA_PKCS12:}") String path,
      @Value("${GMSSL_STANDARD_CA_PASSWORD:}") String password,
      @Value("${GMSSL_STANDARD_CA_ALIAS:}") String alias) {
    if (path.isEmpty() && password.isEmpty() && alias.isEmpty()) {
      signingKey = null;
      chain = List.of();
      chainPem = "";
      return;
    }
    char[] secret = password.toCharArray();
    try {
      if (!Path.of(path).isAbsolute() || password.isEmpty() || alias.isBlank())
        throw new GeneralSecurityException();
      var ks = KeyStore.getInstance("PKCS12");
      try (InputStream src = Files.newInputStream(Path.of(path))) {
        ks.load(src, secret);
      }
      signingKey = (PrivateKey) ks.getKey(alias, secret);
      chain =
          Arrays.stream(ks.getCertificateChain(alias)).map(X509Certificate.class::cast).toList();
      X509Certificate ca = chain.getFirst();
      if (!(ca.getPublicKey() instanceof RSAPublicKey rsa) || rsa.getModulus().bitLength() < 3072)
        throw new GeneralSecurityException();
      var out = new StringBuilder();
      for (int i = 0; i < chain.size(); i++) {
        var cert = chain.get(i);
        cert.checkValidity();
        boolean[] usage = cert.getKeyUsage();
        var eku = cert.getExtendedKeyUsage();
        if (cert.getBasicConstraints() < i
            || usage == null
            || usage.length <= 5
            || !usage[5]
            || (eku != null
                && !eku.contains(KeyPurposeId.id_kp_clientAuth.getId())
                && !eku.contains(KeyPurposeId.anyExtendedKeyUsage.getId())))
          throw new GeneralSecurityException();
        if (i + 1 < chain.size()) {
          var parent = chain.get(i + 1);
          if (!cert.getIssuerX500Principal().equals(parent.getSubjectX500Principal()))
            throw new GeneralSecurityException();
          cert.verify(parent.getPublicKey());
        } else if (cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal()))
          cert.verify(cert.getPublicKey());
        out.append(pem(cert));
      }
      chainPem = out.toString();
      byte[] proof = random.generateSeed(32);
      var sig = Signature.getInstance(SIG);
      sig.initSign(signingKey);
      sig.update(proof);
      byte[] signed = sig.sign();
      sig.initVerify(ca.getPublicKey());
      sig.update(proof);
      if (!sig.verify(signed)) throw new GeneralSecurityException();
    } catch (Exception e) {
      throw new IllegalStateException("Invalid dedicated standard client CA configuration");
    } finally {
      Arrays.fill(secret, '\0');
    }
  }

  record Request(PublicKey publicKey, String digest) {}

  record Issued(
      String fingerprint, String serial, long expiresAt, String certificatePem, String chainPem) {}

  Request verify(String pem) {
    final String begin = "-----BEGIN CERTIFICATE REQUEST-----",
        end = "-----END CERTIFICATE REQUEST-----";
    try {
      if (pem == null || pem.length() > 16384) throw new GeneralSecurityException();
      String text = pem.strip();
      if (!text.startsWith(begin) || !text.endsWith(end)) throw new GeneralSecurityException();
      String encoded =
          text.substring(begin.length(), text.length() - end.length())
              .replaceAll("[\\r\\n\\t ]", "");
      byte[] der = Base64.getDecoder().decode(encoded);
      var csr = new JcaPKCS10CertificationRequest(der);
      if (!Arrays.equals(der, csr.getEncoded())
          || !PKCSObjectIdentifiers.rsaEncryption.equals(
              csr.getSubjectPublicKeyInfo().getAlgorithm().getAlgorithm())
          || !PKCSObjectIdentifiers.sha256WithRSAEncryption.equals(
              csr.getSignatureAlgorithm().getAlgorithm())) throw new GeneralSecurityException();
      var key = csr.getPublicKey();
      if (!(key instanceof RSAPublicKey rsa)
          || rsa.getModulus().bitLength() != 3072
          || !rsa.getModulus().testBit(0)
          || rsa.getPublicExponent().compareTo(BigInteger.valueOf(65537)) < 0
          || !rsa.getPublicExponent().testBit(0)
          || !csr.isSignatureValid(new JcaContentVerifierProviderBuilder().build(key)))
        throw new GeneralSecurityException();
      return new Request(key, digest(der));
    } catch (Exception e) {
      throw ApiError.bad("Expected one verified RSA-3072 SHA256withRSA PKCS#10 request");
    }
  }

  Issued sign(Request request, String label) {
    if (signingKey == null) throw unavailable();
    try {
      Date now = new Date();
      long until = now.getTime() + Duration.ofDays(365).toMillis();
      for (var ca : chain) {
        ca.checkValidity(now);
        until = Math.min(until, ca.getNotAfter().getTime());
      }
      if (until / 1000 <= now.getTime() / 1000) throw unavailable();
      var issuer = chain.getFirst();
      var serial = new BigInteger(159, random).setBit(158);
      var subject = new X500NameBuilder(BCStyle.INSTANCE).addRDN(BCStyle.CN, label).build();
      var builder =
          new JcaX509v3CertificateBuilder(
              new JcaX509CertificateHolder(issuer).getSubject(),
              serial,
              now,
              new Date(until),
              subject,
              request.publicKey());
      builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
      builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
      builder.addExtension(
          Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth));
      var cert =
          new JcaX509CertificateConverter()
              .getCertificate(builder.build(new JcaContentSignerBuilder(SIG).build(signingKey)));
      return new Issued(
          digest(cert.getEncoded()),
          serial.toString(16),
          cert.getNotAfter().getTime(),
          pem(cert),
          chainPem);
    } catch (Exception e) {
      throw unavailable();
    }
  }

  private static String digest(byte[] der) throws GeneralSecurityException {
    return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(der));
  }

  private static String pem(X509Certificate cert) throws GeneralSecurityException {
    return "-----BEGIN CERTIFICATE-----\n"
        + Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(cert.getEncoded())
        + "\n-----END CERTIFICATE-----\n";
  }

  private static ApiError unavailable() {
    return new ApiError(503, "CA_UNAVAILABLE", "Standard client certificate issuer unavailable");
  }
}
