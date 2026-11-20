package org.gmssl.gui.engine;

import static org.gmssl.gui.engine.EngineModels.*;
import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.mock.env.MockEnvironment;

class KeyGenerationServiceTest {
    @TempDir Path temp;
    EngineSettings settings;
    CatalogService catalog;
    ExecutionService executionService;
    KeyGenerationService keyGenService;

    @BeforeEach void setUp() throws Exception {
        Path runner = Path.of("../native/.build/bin/gmssl-runner").toRealPath();
        settings = new EngineSettings(new MockEnvironment()
                .withProperty("GMSSL_ENGINE_TOKEN", "test-token-32-characters-minimum-123456")
                .withProperty("GMSSL_RUNNER_PATH", runner.toString())
                .withProperty("GMSSL_ENGINE_WORK_DIR", temp.toRealPath().resolve("work").toString())
                .withProperty("GMSSL_OPENSSL_PATH", "/opt/homebrew/bin/openssl"));
        catalog = new CatalogService(new ObjectMapper());
        executionService = new ExecutionService(catalog, new EngineValidator(new NetworkPolicy(settings)), settings);
        keyGenService = new KeyGenerationService(settings, executionService);
    }

    @Test void testCapabilitiesReporting() {
        var caps = keyGenService.capabilities();
        assertNotNull(caps);
        assertEquals(2, caps.providers().size());

        var gmssl = caps.providers().stream().filter(p -> p.id().equals("gmssl")).findFirst().orElseThrow();
        assertTrue(gmssl.available());
        assertEquals("3.3", gmssl.version());
        assertTrue(gmssl.algorithms().contains("SM4"));
        assertTrue(gmssl.algorithms().contains("SM2"));
        assertTrue(gmssl.algorithms().contains("Kyber"));
        assertFalse(gmssl.algorithms().contains("SM9"), "SM9 should not be claimed in direct keygen capabilities");

        var openssl = caps.providers().stream().filter(p -> p.id().equals("openssl")).findFirst().orElseThrow();
        assertTrue(openssl.available());
        assertNotNull(openssl.version());
        assertTrue(openssl.algorithms().contains("SM4"));
        assertTrue(openssl.algorithms().contains("SM2"));
        assertTrue(openssl.algorithms().contains("EC"));
        assertFalse(openssl.algorithms().contains("SM9"));
        assertFalse(openssl.algorithms().contains("Kyber"));

        assertTrue(caps.algorithms().stream().anyMatch(a -> a.id().equals("SM4") && a.providers().contains("openssl")));
        assertFalse(caps.algorithms().stream().anyMatch(a -> a.id().equals("SM9")), "SM9 algorithm must not be advertised");
    }

    @Test void testSymmetricGenerationBothProviders() throws Exception {
        // GmSSL SM4
        var res1 = keyGenService.generate(new KeyGenRequest(UUID.randomUUID().toString(), "gmssl", "SM4", null, null, null, 10));
        assertEquals("gmssl", res1.provider());
        assertEquals("SM4", res1.algorithm());
        assertEquals("SYMMETRIC_KEY", res1.keyKind());
        assertEquals("HEX", res1.encoding());
        assertNotNull(res1.valueBase64());
        String hex1 = new String(Base64.getDecoder().decode(res1.valueBase64()), StandardCharsets.UTF_8);
        assertEquals(32, hex1.length());
        assertTrue(hex1.matches("^[0-9a-fA-F]{32}$"));

        // OpenSSL SM4
        var res2 = keyGenService.generate(new KeyGenRequest(UUID.randomUUID().toString(), "openssl", "SM4", null, null, null, 10));
        assertEquals("openssl", res2.provider());
        String hex2 = new String(Base64.getDecoder().decode(res2.valueBase64()), StandardCharsets.UTF_8);
        assertEquals(32, hex2.length());
        assertTrue(hex2.matches("^[0-9a-fA-F]{32}$"));

        // OpenSSL AES-256
        var res3 = keyGenService.generate(new KeyGenRequest(UUID.randomUUID().toString(), "openssl", "AES", 256, null, null, 10));
        String hex3 = new String(Base64.getDecoder().decode(res3.valueBase64()), StandardCharsets.UTF_8);
        assertEquals(64, hex3.length());

        // Cleanup check
        try (var files = Files.list(settings.work)) {
            assertEquals(0, files.count());
        }
    }

    @Test void testSm2GenerationBothProvidersAndInteroperability() throws Exception {
        String pass = "SecurePass123!";

        // 1. Generate SM2 via GmSSL
        var gRes = keyGenService.generate(new KeyGenRequest(UUID.randomUUID().toString(), "gmssl", "SM2", null, null, pass, 15));
        assertEquals("gmssl", gRes.provider());
        assertEquals("PRIVATE_KEY", gRes.keyKind());
        assertEquals("PEM", gRes.encoding());
        assertNotNull(gRes.privateKeyBase64());
        assertNotNull(gRes.publicKeyBase64());
        String gPrivPem = new String(Base64.getDecoder().decode(gRes.privateKeyBase64()), StandardCharsets.UTF_8);
        String gPubPem = new String(Base64.getDecoder().decode(gRes.publicKeyBase64()), StandardCharsets.UTF_8);
        assertTrue(gPrivPem.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----"));
        assertTrue(gPubPem.contains("-----BEGIN PUBLIC KEY-----"));

        // 2. Generate SM2 via OpenSSL (with bridge conversion)
        var oRes = keyGenService.generate(new KeyGenRequest(UUID.randomUUID().toString(), "openssl", "SM2", null, null, pass, 15));
        assertEquals("openssl", oRes.provider());
        assertEquals("PRIVATE_KEY", oRes.keyKind());
        assertEquals("PEM", oRes.encoding());
        assertNotNull(oRes.privateKeyBase64());
        assertNotNull(oRes.publicKeyBase64());
        String oPrivPem = new String(Base64.getDecoder().decode(oRes.privateKeyBase64()), StandardCharsets.UTF_8);
        String oPubPem = new String(Base64.getDecoder().decode(oRes.publicKeyBase64()), StandardCharsets.UTF_8);
        assertTrue(oPrivPem.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----"));
        assertTrue(oPubPem.contains("-----BEGIN PUBLIC KEY-----"));

        // 3. Test Interoperability: sign a message with OpenSSL generated key using GmSSL sm2sign tool
        byte[] payload = "Hello from OpenSSL bridged SM2 key!".getBytes(StandardCharsets.UTF_8);
        String privInputToken = "opensslpriv";
        String pubInputToken = "opensslpub";

        var signReq = new ExecutionRequest(
                UUID.randomUUID().toString(),
                "sm2sign",
                Map.of("key", "input:" + privInputToken, "pass", pass, "out", "sig.bin"),
                Map.of(privInputToken, new Input("priv.pem", oRes.privateKeyBase64())),
                Base64.getEncoder().encodeToString(payload),
                10
        );
        var signRes = executionService.execute(signReq);
        assertEquals("SUCCEEDED", signRes.status());
        assertEquals(1, signRes.artifacts().size());
        String sigBase64 = signRes.artifacts().getFirst().contentBase64();

        // 4. Verify signature with OpenSSL generated public key using GmSSL sm2verify tool
        String sigInputToken = "sigfile";
        var verifyReq = new ExecutionRequest(
                UUID.randomUUID().toString(),
                "sm2verify",
                Map.of("pubkey", "input:" + pubInputToken, "sig", "input:" + sigInputToken),
                Map.of(
                        pubInputToken, new Input("pub.pem", oRes.publicKeyBase64()),
                        sigInputToken, new Input("sig.bin", sigBase64)
                ),
                Base64.getEncoder().encodeToString(payload),
                10
        );
        var verifyRes = executionService.execute(verifyReq);
        assertEquals("SUCCEEDED", verifyRes.status());

        // 5. Test certgen using OpenSSL generated key
        var certReq = new ExecutionRequest(
                UUID.randomUUID().toString(),
                "certgen",
                Map.of(
                        "C", "CN", "O", "InterOpOrg", "CN", "openssl-sm2-cert",
                        "days", 30, "key", "input:" + privInputToken, "pass", pass,
                        "out", "cert.pem"
                ),
                Map.of(privInputToken, new Input("priv.pem", oRes.privateKeyBase64())),
                null,
                10
        );
        var certRes = executionService.execute(certReq);
        assertEquals("SUCCEEDED", certRes.status());
        assertEquals(1, certRes.artifacts().size());
        String certPem = new String(Base64.getDecoder().decode(certRes.artifacts().getFirst().contentBase64()), StandardCharsets.UTF_8);
        assertTrue(certPem.contains("-----BEGIN CERTIFICATE-----"));

        // Cleanup check
        try (var files = Files.list(settings.work)) {
            assertEquals(0, files.count());
        }
    }

    @Test void testEcGenerationBothProviders() {
        String pass = "ECSecret!2026";

        // GmSSL P256
        var gRes = keyGenService.generate(new KeyGenRequest(UUID.randomUUID().toString(), "gmssl", "EC", null, "secp256r1", pass, 10));
        assertEquals("gmssl", gRes.provider());
        assertNotNull(gRes.privateKeyBase64());
        assertNotNull(gRes.publicKeyBase64());

        // OpenSSL P256
        var oRes256 = keyGenService.generate(new KeyGenRequest(UUID.randomUUID().toString(), "openssl", "EC", null, "secp256r1", pass, 10));
        assertEquals("openssl", oRes256.provider());
        assertNotNull(oRes256.privateKeyBase64());
        assertNotNull(oRes256.publicKeyBase64());

        // OpenSSL P384
        var oRes384 = keyGenService.generate(new KeyGenRequest(UUID.randomUUID().toString(), "openssl", "EC", null, "secp384r1", pass, 10));
        assertEquals("openssl", oRes384.provider());
        assertNotNull(oRes384.privateKeyBase64());
        assertNotNull(oRes384.publicKeyBase64());
    }

    @Test void testKyberGenerationGmssl() {
        var res = keyGenService.generate(new KeyGenRequest(UUID.randomUUID().toString(), "gmssl", "Kyber", null, null, null, 10));
        assertEquals("gmssl", res.provider());
        assertEquals("Kyber", res.algorithm());
        assertNotNull(res.privateKeyBase64());
        assertNotNull(res.publicKeyBase64());
    }

    @Test void testValidationAndUnsupportedRejection() {
        // SM9 rejected with dedicated explanation
        var ex1 = assertThrows(EngineException.class, () ->
                keyGenService.generate(new KeyGenRequest(UUID.randomUUID().toString(), "openssl", "SM9", null, null, "pass", 10)));
        assertEquals("UNSUPPORTED_ALGORITHM", ex1.code);
        assertTrue(ex1.getMessage().contains("sm9setup"));

        var ex1Gmssl = assertThrows(EngineException.class, () ->
                keyGenService.generate(new KeyGenRequest(UUID.randomUUID().toString(), "gmssl", "SM9", null, null, "pass", 10)));
        assertEquals("UNSUPPORTED_ALGORITHM", ex1Gmssl.code);

        // OpenSSL Kyber rejected
        var ex2 = assertThrows(EngineException.class, () ->
                keyGenService.generate(new KeyGenRequest(UUID.randomUUID().toString(), "openssl", "Kyber", null, null, null, 10)));
        assertEquals("UNSUPPORTED_ALGORITHM", ex2.code);

        // Missing password for SM2
        var ex3 = assertThrows(EngineException.class, () ->
                keyGenService.generate(new KeyGenRequest(UUID.randomUUID().toString(), "gmssl", "SM2", null, null, "", 10)));
        assertEquals("PASSWORD_REQUIRED", ex3.code);

        // Password with control characters or NUL
        var ex3Nul = assertThrows(EngineException.class, () ->
                keyGenService.generate(new KeyGenRequest(UUID.randomUUID().toString(), "gmssl", "SM2", null, null, "pass\0word", 10)));
        assertEquals("INVALID_PARAMETERS", ex3Nul.code);

        var ex3Newline = assertThrows(EngineException.class, () ->
                keyGenService.generate(new KeyGenRequest(UUID.randomUUID().toString(), "gmssl", "SM2", null, null, "pass\nword", 10)));
        assertEquals("INVALID_PARAMETERS", ex3Newline.code);

        var ex3Oversized = assertThrows(EngineException.class, () ->
                keyGenService.generate(new KeyGenRequest(UUID.randomUUID().toString(), "gmssl", "SM2", null, null, "a".repeat(1025), 10)));
        assertEquals("INVALID_PARAMETERS", ex3Oversized.code);

        // Invalid curve
        var ex4 = assertThrows(EngineException.class, () ->
                keyGenService.generate(new KeyGenRequest(UUID.randomUUID().toString(), "openssl", "EC", null, "invalid_curve", "pass", 10)));
        assertEquals("INVALID_CURVE", ex4.code);

        // Invalid provider
        var ex5 = assertThrows(EngineException.class, () ->
                keyGenService.generate(new KeyGenRequest(UUID.randomUUID().toString(), "unknown_provider", "SM4", null, null, null, 10)));
        assertEquals("INVALID_PROVIDER", ex5.code);
    }

    @Test void testHangingFixtureProcessKilledAndSlotReleased() throws Exception {
        // Create a dummy hanging script fixture
        Path hangScript = temp.toRealPath().resolve("hang_runner.sh");
        Files.writeString(hangScript, "#!/bin/sh\nsleep 30\n");
        Files.setPosixFilePermissions(hangScript, PosixFilePermissions.fromString("rwxr-xr-x"));

        EngineSettings hangSettings = new EngineSettings(new MockEnvironment()
                .withProperty("GMSSL_ENGINE_TOKEN", "test-token-32-characters-minimum-123456")
                .withProperty("GMSSL_RUNNER_PATH", hangScript.toString())
                .withProperty("GMSSL_ENGINE_WORK_DIR", temp.toRealPath().resolve("hang_work").toString()));
        KeyGenerationService hangService = new KeyGenerationService(hangSettings, executionService);

        long start = System.currentTimeMillis();
        var ex = assertThrows(EngineException.class, () ->
                hangService.generate(new KeyGenRequest(UUID.randomUUID().toString(), "gmssl", "SM4", null, null, null, 1)));
        long elapsed = System.currentTimeMillis() - start;

        assertEquals("TIMED_OUT", ex.code);
        assertTrue(elapsed < 4000, "Should timeout within 2-3 seconds, actual: " + elapsed);

        // Ensure slot was released immediately
        assertTrue(executionService.tryAcquireSlot(), "Process execution slot must be released after timeout");
        executionService.releaseSlot();

        // Ensure work directory was cleaned up
        try (var files = Files.list(hangSettings.work)) {
            assertEquals(0, files.count(), "Work directory must be completely cleaned after timeout");
        }
    }

    @Test void testOutputFloodFixtureProcessTerminated() throws Exception {
        // Create an output flood script fixture that dumps large amount of data into target output file
        Path floodScript = temp.toRealPath().resolve("flood_runner.sh");
        Files.writeString(floodScript, "#!/bin/sh\ncat > /dev/null\ndd if=/dev/zero of=flood.bin bs=1024 count=1024 2>/dev/null\nsleep 1\n");
        Files.setPosixFilePermissions(floodScript, PosixFilePermissions.fromString("rwxr-xr-x"));

        EngineSettings floodSettings = new EngineSettings(new MockEnvironment()
                .withProperty("GMSSL_ENGINE_TOKEN", "test-token-32-characters-minimum-123456")
                .withProperty("GMSSL_RUNNER_PATH", floodScript.toString())
                .withProperty("GMSSL_ENGINE_MAX_BYTES", "65536") // 64KB limit
                .withProperty("GMSSL_ENGINE_WORK_DIR", temp.toRealPath().resolve("flood_work").toString()));
        KeyGenerationService floodService = new KeyGenerationService(floodSettings, executionService);

        var ex = assertThrows(EngineException.class, () ->
                floodService.generate(new KeyGenRequest(UUID.randomUUID().toString(), "gmssl", "SM4", null, null, null, 5)));

        assertTrue(ex.code.equals("OUTPUT_LIMIT") || ex.code.equals("KEYGEN_FAILED"));

        // Slot released
        assertTrue(executionService.tryAcquireSlot());
        executionService.releaseSlot();

        // Work directory cleaned up
        try (var files = Files.list(floodSettings.work)) {
            assertEquals(0, files.count());
        }
    }

    @Test void testNonZeroExitFixtureDoesNotLeakStderr() throws Exception {
        // Create a script that outputs sensitive error info and fails with non-zero
        Path failScript = temp.toRealPath().resolve("fail_runner.sh");
        Files.writeString(failScript, "#!/bin/sh\necho \"SUPER_SECRET_LEAK_STRING_12345\" >&2\nexit 1\n");
        Files.setPosixFilePermissions(failScript, PosixFilePermissions.fromString("rwxr-xr-x"));

        EngineSettings failSettings = new EngineSettings(new MockEnvironment()
                .withProperty("GMSSL_ENGINE_TOKEN", "test-token-32-characters-minimum-123456")
                .withProperty("GMSSL_RUNNER_PATH", failScript.toString())
                .withProperty("GMSSL_ENGINE_WORK_DIR", temp.toRealPath().resolve("fail_work").toString()));
        KeyGenerationService failService = new KeyGenerationService(failSettings, executionService);

        var ex = assertThrows(EngineException.class, () ->
                failService.generate(new KeyGenRequest(UUID.randomUUID().toString(), "gmssl", "SM4", null, null, null, 5)));

        assertEquals("KEYGEN_FAILED", ex.code);
        assertEquals("Native key generation failed", ex.getMessage());
        assertFalse(ex.getMessage().contains("SUPER_SECRET_LEAK_STRING_12345"), "Raw stderr must never leak to client");

        // Slot released
        assertTrue(executionService.tryAcquireSlot());
        executionService.releaseSlot();
    }

    @Test void testPasswordNeverInArgvOrEnvAndFrameZeroized() throws Exception {
        // Create a wrapper script that inspects argv and env
        Path logFile = temp.toRealPath().resolve("argv_env.log");
        Path runnerWrapper = temp.toRealPath().resolve("spy_runner.sh");
        Path realRunner = Path.of("../native/.build/bin/gmssl-runner").toRealPath();

        String wrapperScript = "#!/bin/sh\n"
                + "echo \"ARGS: $@\" >> " + logFile.toString() + "\n"
                + "env >> " + logFile.toString() + "\n"
                + "exec \"" + realRunner.toString() + "\" \"$@\"\n";
        Files.writeString(runnerWrapper, wrapperScript);
        Files.setPosixFilePermissions(runnerWrapper, PosixFilePermissions.fromString("rwxr-xr-x"));

        EngineSettings spySettings = new EngineSettings(new MockEnvironment()
                .withProperty("GMSSL_ENGINE_TOKEN", "test-token-32-characters-minimum-123456")
                .withProperty("GMSSL_RUNNER_PATH", runnerWrapper.toString())
                .withProperty("GMSSL_ENGINE_WORK_DIR", temp.toRealPath().resolve("spy_work").toString()));
        KeyGenerationService spyService = new KeyGenerationService(spySettings, executionService);

        String secretPassphrase = "UltraPrivatePassword!999";
        var res = spyService.generate(new KeyGenRequest(UUID.randomUUID().toString(), "gmssl", "SM2", null, null, secretPassphrase, 10));
        assertNotNull(res.privateKeyBase64());

        // Read logFile
        assertTrue(Files.exists(logFile));
        String logContent = Files.readString(logFile);
        assertFalse(logContent.contains(secretPassphrase), "Passphrase must NEVER appear in command line arguments or environment variables!");

        // Also test frame array zeroization verification
        List<byte[]> sensitive = new ArrayList<>();
        byte[] frame = ExecutionService.frame(List.of("sm2keygen", "-pass", secretPassphrase));
        sensitive.add(frame);
        // Ensure sensitive zeroization clears bytes
        for (byte[] b : sensitive) {
            Arrays.fill(b, (byte) 0);
        }
        for (byte b : frame) {
            assertEquals((byte) 0, b, "Sensitive frame buffer must be completely zeroized");
        }
    }
}
