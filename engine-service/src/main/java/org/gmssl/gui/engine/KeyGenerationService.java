package org.gmssl.gui.engine;

import static org.gmssl.gui.engine.EngineModels.*;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.springframework.stereotype.Service;

@Service
public class KeyGenerationService {
    private final EngineSettings settings;
    private final ExecutionService executionService;
    private final ExecutorService io = Executors.newVirtualThreadPerTaskExecutor();

    private static final Set<String> SYMMETRIC_ALGORITHMS = Set.of(
            "SM4", "SM4-XTS", "AES", "ZUC", "ZUC256", "HMAC"
    );

    public KeyGenerationService(EngineSettings settings, ExecutionService executionService) {
        this.settings = settings;
        this.executionService = executionService;
    }

    public KeyGenCapabilitiesResponse capabilities() {
        List<String> gmsslAlgs = List.of("SM4", "SM4-XTS", "AES", "ZUC", "ZUC256", "HMAC", "SM2", "EC", "Kyber");
        List<String> opensslAlgs = settings.opensslAvailable
                ? List.of("SM4", "SM4-XTS", "AES", "ZUC", "ZUC256", "HMAC", "SM2", "EC")
                : List.of();

        List<ProviderCapability> providers = List.of(
                new ProviderCapability("gmssl", true, "3.3", null, gmsslAlgs),
                new ProviderCapability(
                        "openssl",
                        settings.opensslAvailable,
                        settings.opensslVersion,
                        settings.opensslAvailable ? null : "OpenSSL is not available in this deployment",
                        opensslAlgs
                )
        );

        List<String> dualProviders = settings.opensslAvailable ? List.of("gmssl", "openssl") : List.of("gmssl");

        List<AlgorithmCapability> algorithms = List.of(
                new AlgorithmCapability("SM4", "SYMMETRIC_KEY", List.of(128), null, dualProviders),
                new AlgorithmCapability("SM4-XTS", "SYMMETRIC_KEY", List.of(256), null, dualProviders),
                new AlgorithmCapability("AES", "SYMMETRIC_KEY", List.of(128, 192, 256), null, dualProviders),
                new AlgorithmCapability("ZUC", "SYMMETRIC_KEY", List.of(128), null, dualProviders),
                new AlgorithmCapability("ZUC256", "SYMMETRIC_KEY", List.of(256), null, dualProviders),
                new AlgorithmCapability("HMAC", "SYMMETRIC_KEY", List.of(128, 256, 512), null, dualProviders),
                new AlgorithmCapability("SM2", "PRIVATE_KEY", null, List.of("sm2p256v1"), dualProviders),
                new AlgorithmCapability("EC", "PRIVATE_KEY", null, List.of("secp256r1", "secp384r1"), dualProviders),
                new AlgorithmCapability("Kyber", "PRIVATE_KEY", null, null, List.of("gmssl"))
        );

        return new KeyGenCapabilitiesResponse(providers, algorithms);
    }

    public KeyGenResponse generate(KeyGenRequest request) {
        if (request == null || request.requestId() == null || request.requestId().isBlank()) {
            throw EngineException.invalid();
        }
        try {
            if (!UUID.fromString(request.requestId()).toString().equals(request.requestId())) {
                throw EngineException.invalid();
            }
        } catch (IllegalArgumentException e) {
            throw EngineException.invalid();
        }

        String provider = request.provider() == null ? "gmssl" : request.provider().toLowerCase();
        if (!provider.equals("gmssl") && !provider.equals("openssl")) {
            throw new EngineException(400, "INVALID_PROVIDER", "Unsupported key generation provider: " + provider);
        }

        if (provider.equals("openssl") && !settings.opensslAvailable) {
            throw new EngineException(503, "PROVIDER_UNAVAILABLE", "OpenSSL provider is not available in this deployment");
        }

        String alg = request.algorithm() == null ? "" : request.algorithm().trim().toUpperCase();
        if (alg.isEmpty()) {
            throw EngineException.invalid();
        }

        if (alg.equals("SM9")) {
            throw new EngineException(400, "UNSUPPORTED_ALGORITHM", "SM9 master and identity key generation is managed via dedicated sm9setup and sm9keygen tools");
        }

        if (provider.equals("openssl") && alg.equals("KYBER")) {
            throw new EngineException(400, "UNSUPPORTED_ALGORITHM", "OpenSSL does not support algorithm: " + alg);
        }

        int timeout = request.timeoutSeconds() == null ? 30 : request.timeoutSeconds();
        if (timeout < 1 || timeout > 300) {
            throw EngineException.invalid();
        }

        if (!executionService.tryAcquireSlot()) {
            throw new EngineException(429, "BUSY", "Execution capacity reached");
        }

        long deadlineNanos = System.nanoTime() + TimeUnit.SECONDS.toNanos(timeout);
        Path directory = null;
        List<byte[]> sensitive = new ArrayList<>();
        try {
            if (!Files.isDirectory(settings.work)) {
                Files.createDirectories(settings.work);
            }
            ExecutionService.rejectSymlinks(settings.work);
            directory = Files.createTempDirectory(settings.work, "keygen-");
            ExecutionService.permissions(directory, "rwx------");

            if (SYMMETRIC_ALGORITHMS.contains(alg)) {
                return generateSymmetric(request, provider, alg, directory, deadlineNanos, sensitive);
            } else if (alg.equals("SM2")) {
                return generateSm2(request, provider, directory, deadlineNanos, sensitive);
            } else if (alg.equals("EC")) {
                return generateEc(request, provider, directory, deadlineNanos, sensitive);
            } else if (alg.equals("KYBER")) {
                return generateKyber(request, directory, deadlineNanos, sensitive);
            } else {
                throw new EngineException(400, "UNSUPPORTED_ALGORITHM", "Unsupported key algorithm: " + alg);
            }
        } catch (EngineException e) {
            throw e;
        } catch (Exception e) {
            throw new EngineException(500, "KEYGEN_ERROR", "Key generation failed");
        } finally {
            executionService.releaseSlot();
            for (byte[] b : sensitive) {
                Arrays.fill(b, (byte) 0);
            }
            if (directory != null) {
                cleanupChecked(directory);
            }
        }
    }

    void cleanupChecked(Path directory) {
        try {
            Path absolute = directory.toAbsolutePath().normalize();
            if (!absolute.startsWith(settings.work) || absolute.equals(settings.work)) {
                throw new IOException("Cleanup boundary");
            }
            try (var files = Files.walk(absolute)) {
                for (Path p : files.sorted(java.util.Comparator.reverseOrder()).toList()) {
                    if (!p.toAbsolutePath().normalize().startsWith(absolute)) {
                        throw new IOException("Cleanup boundary");
                    }
                    Files.deleteIfExists(p);
                }
            }
            if (Files.exists(absolute, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
                throw new IOException("Cleanup incomplete");
            }
        } catch (IOException e) {
            throw new EngineException(503, "CLEANUP_QUARANTINE", "Work storage requires administrator recovery");
        }
    }

    private void validatePassword(String password) {
        if (password == null || password.isEmpty()) {
            throw new EngineException(400, "PASSWORD_REQUIRED", "Password is required for private key encryption");
        }
        if (password.indexOf(0) >= 0 || password.indexOf('\r') >= 0 || password.indexOf('\n') >= 0) {
            throw EngineException.invalid();
        }
        byte[] b = password.getBytes(StandardCharsets.UTF_8);
        if (b.length > 1024) {
            throw EngineException.invalid();
        }
    }

    private KeyGenResponse generateSymmetric(KeyGenRequest request, String provider, String alg,
                                             Path directory, long deadlineNanos, List<byte[]> sensitive) throws Exception {
        int bits;
        if (alg.equals("SM4") || alg.equals("ZUC")) {
            bits = 128;
        } else if (alg.equals("SM4-XTS") || alg.equals("ZUC256")) {
            bits = 256;
        } else if (alg.equals("AES")) {
            bits = request.bits() == null ? 128 : request.bits();
            if (bits != 128 && bits != 192 && bits != 256) {
                throw new EngineException(400, "INVALID_BITS", "AES key length must be 128, 192, or 256 bits");
            }
        } else if (alg.equals("HMAC")) {
            bits = request.bits() == null ? 256 : request.bits();
            if (bits != 128 && bits != 256 && bits != 512) {
                throw new EngineException(400, "INVALID_BITS", "HMAC key length must be 128, 256, or 512 bits");
            }
        } else {
            throw new EngineException(400, "UNSUPPORTED_ALGORITHM", "Unsupported symmetric algorithm: " + alg);
        }

        int byteLen = bits / 8;
        String hex;

        if (provider.equals("gmssl")) {
            Path outPath = directory.resolve("rand.hex");
            runRunner(List.of("rand", "-outlen", String.valueOf(byteLen), "-hex", "-out", outPath.toString()), directory, deadlineNanos, sensitive);
            byte[] fileBytes = ExecutionService.readRegular(outPath, 1024);
            sensitive.add(fileBytes);
            hex = new String(fileBytes, StandardCharsets.UTF_8).trim().toLowerCase();
        } else {
            long remainingNanos = deadlineNanos - System.nanoTime();
            if (remainingNanos <= 0) {
                throw new EngineException(504, "TIMED_OUT", "Key generation timed out");
            }
            ProcessBuilder pb = new ProcessBuilder(settings.openssl.toString(), "rand", "-hex", String.valueOf(byteLen));
            pb.environment().clear();
            pb.environment().put("LANG", "C");
            pb.environment().put("LC_ALL", "C");
            Process p = pb.start();
            ExecutionService.Capture stdout = new ExecutionService.Capture(1024);
            ExecutionService.Capture stderr = new ExecutionService.Capture(1024);
            var outFut = io.submit(() -> stdout.drain(p.getInputStream(), p));
            var errFut = io.submit(() -> stderr.drain(p.getErrorStream(), p));
            boolean finished = false;
            try {
                finished = p.waitFor(remainingNanos, TimeUnit.NANOSECONDS);
                if (!finished) {
                    ExecutionService.stop(p);
                    throw new EngineException(504, "TIMED_OUT", "Key generation timed out");
                }
                outFut.get(1, TimeUnit.SECONDS);
                errFut.get(1, TimeUnit.SECONDS);
            } finally {
                if (p.isAlive()) ExecutionService.stop(p);
                outFut.cancel(true);
                errFut.cancel(true);
                stderr.clear();
            }
            if (p.exitValue() != 0) {
                stdout.clear();
                throw new EngineException(500, "KEYGEN_FAILED", "OpenSSL key generation failed");
            }
            byte[] outBytes = stdout.bytes();
            sensitive.add(outBytes);
            stdout.clear();
            hex = new String(outBytes, StandardCharsets.UTF_8).trim().toLowerCase();
        }

        if (hex.length() != byteLen * 2) {
            throw new EngineException(500, "KEYGEN_FAILED", "Invalid generated key length");
        }

        byte[] hexBytes = hex.getBytes(StandardCharsets.UTF_8);
        sensitive.add(hexBytes);
        String valueBase64 = Base64.getEncoder().encodeToString(hexBytes);

        return new KeyGenResponse(provider, alg, "SYMMETRIC_KEY", "HEX", valueBase64, null, null, List.of());
    }

    private KeyGenResponse generateSm2(KeyGenRequest request, String provider, Path directory,
                                       long deadlineNanos, List<byte[]> sensitive) throws Exception {
        String password = request.password();
        validatePassword(password);

        Path privPem = directory.resolve("sm2_private.pem");
        Path pubPem = directory.resolve("sm2_public.pem");

        if (provider.equals("gmssl")) {
            runRunner(List.of("sm2keygen", "-pass", password, "-out", privPem.toString(), "-pubout", pubPem.toString()), directory, deadlineNanos, sensitive);
        } else {
            Path rawDer = directory.resolve("sm2_raw.der");
            runOpenSslEcDer("ec_paramgen_curve:sm2", rawDer, directory, deadlineNanos, sensitive);
            try {
                runRunner(List.of("__keygen_bridge", "-in", rawDer.toString(), "-out", privPem.toString(), "-pubout", pubPem.toString(), "-pass", password), directory, deadlineNanos, sensitive);
            } finally {
                if (Files.exists(rawDer)) {
                    byte[] zeros = new byte[(int) Files.size(rawDer)];
                    Files.write(rawDer, zeros, StandardOpenOption.TRUNCATE_EXISTING);
                    Files.deleteIfExists(rawDer);
                }
            }
        }

        byte[] privBytes = ExecutionService.readRegular(privPem, settings.maxBytes);
        sensitive.add(privBytes);
        byte[] pubBytes = ExecutionService.readRegular(pubPem, settings.maxBytes);
        sensitive.add(pubBytes);

        String privBase64 = Base64.getEncoder().encodeToString(privBytes);
        String pubBase64 = Base64.getEncoder().encodeToString(pubBytes);

        return new KeyGenResponse(provider, "SM2", "PRIVATE_KEY", "PEM", null, privBase64, pubBase64, List.of());
    }

    private KeyGenResponse generateEc(KeyGenRequest request, String provider, Path directory,
                                      long deadlineNanos, List<byte[]> sensitive) throws Exception {
        String curve = request.curve() == null ? "secp256r1" : request.curve().trim().toLowerCase();
        if (!curve.equals("secp256r1") && !curve.equals("prime256v1") && !curve.equals("secp384r1")) {
            throw new EngineException(400, "INVALID_CURVE", "Unsupported EC curve: " + curve);
        }

        String password = request.password();
        validatePassword(password);

        Path privPem = directory.resolve("ec_private.pem");
        Path pubPem = directory.resolve("ec_public.pem");

        if (provider.equals("gmssl")) {
            runRunner(List.of("eckeygen", "-curve", curve, "-pass", password, "-out", privPem.toString(), "-pubout", pubPem.toString()), directory, deadlineNanos, sensitive);
        } else {
            String opensslCurve = curve.equals("secp384r1") ? "secp384r1" : "prime256v1";
            Path rawDer = directory.resolve("ec_raw.der");
            runOpenSslEcDer("ec_paramgen_curve:" + opensslCurve, rawDer, directory, deadlineNanos, sensitive);
            try {
                runRunner(List.of("__keygen_bridge", "-in", rawDer.toString(), "-out", privPem.toString(), "-pubout", pubPem.toString(), "-pass", password), directory, deadlineNanos, sensitive);
            } finally {
                if (Files.exists(rawDer)) {
                    byte[] zeros = new byte[(int) Files.size(rawDer)];
                    Files.write(rawDer, zeros, StandardOpenOption.TRUNCATE_EXISTING);
                    Files.deleteIfExists(rawDer);
                }
            }
        }

        byte[] privBytes = ExecutionService.readRegular(privPem, settings.maxBytes);
        sensitive.add(privBytes);
        byte[] pubBytes = ExecutionService.readRegular(pubPem, settings.maxBytes);
        sensitive.add(pubBytes);

        String privBase64 = Base64.getEncoder().encodeToString(privBytes);
        String pubBase64 = Base64.getEncoder().encodeToString(pubBytes);

        return new KeyGenResponse(provider, "EC", "PRIVATE_KEY", "PEM", null, privBase64, pubBase64, List.of());
    }

    private KeyGenResponse generateKyber(KeyGenRequest request, Path directory, long deadlineNanos,
                                         List<byte[]> sensitive) throws Exception {
        Path privPem = directory.resolve("kyber_private.pem");
        Path pubPem = directory.resolve("kyber_public.pem");

        runRunner(List.of("kyberkeygen", "-out", privPem.toString(), "-pubout", pubPem.toString()), directory, deadlineNanos, sensitive);

        byte[] privBytes = ExecutionService.readRegular(privPem, settings.maxBytes);
        sensitive.add(privBytes);
        byte[] pubBytes = ExecutionService.readRegular(pubPem, settings.maxBytes);
        sensitive.add(pubBytes);

        String privBase64 = Base64.getEncoder().encodeToString(privBytes);
        String pubBase64 = Base64.getEncoder().encodeToString(pubBytes);

        return new KeyGenResponse("gmssl", "Kyber", "PRIVATE_KEY", "PEM", null, privBase64, pubBase64, List.of());
    }

    void runRunner(List<String> arguments, Path workDir, long deadlineNanos, List<byte[]> sensitive) throws Exception {
        long remainingNanos = deadlineNanos - System.nanoTime();
        if (remainingNanos <= 0) {
            throw new EngineException(504, "TIMED_OUT", "Key generation timed out");
        }

        byte[] frame = ExecutionService.frame(arguments);
        sensitive.add(frame);

        ProcessBuilder pb = new ProcessBuilder(settings.runner.toString());
        pb.directory(workDir.toFile());
        pb.environment().clear();
        pb.environment().put("LANG", "C");
        pb.environment().put("LC_ALL", "C");
        Process p = pb.start();

        ExecutionService.Capture stdout = new ExecutionService.Capture(settings.maxBytes);
        ExecutionService.Capture stderr = new ExecutionService.Capture(Math.min(settings.maxBytes, 1024 * 1024));
        var outFuture = io.submit(() -> stdout.drain(p.getInputStream(), p));
        var errFuture = io.submit(() -> stderr.drain(p.getErrorStream(), p));
        var writeFuture = io.submit(() -> {
            try (var os = p.getOutputStream()) {
                os.write(frame);
            } catch (IOException ignored) {}
        });

        boolean finished = false;
        boolean outputExceeded = false;
        try {
            while (!(finished = p.waitFor(50, TimeUnit.MILLISECONDS)) && System.nanoTime() < deadlineNanos) {
                if (ExecutionService.outputSize(workDir) > settings.maxBytes) {
                    outputExceeded = true;
                    ExecutionService.stop(p);
                    break;
                }
            }
            if (!finished || outputExceeded) {
                ExecutionService.stop(p);
            }
            p.waitFor(1, TimeUnit.SECONDS);
            if (!outputExceeded && ExecutionService.outputSize(workDir) > settings.maxBytes) {
                outputExceeded = true;
            }
            writeFuture.get(1, TimeUnit.SECONDS);
            outFuture.get(1, TimeUnit.SECONDS);
            errFuture.get(1, TimeUnit.SECONDS);
        } finally {
            if (p.isAlive()) {
                ExecutionService.stop(p);
            }
            writeFuture.cancel(true);
            outFuture.cancel(true);
            errFuture.cancel(true);
            stdout.clear();
            stderr.clear();
        }

        if (outputExceeded) {
            throw new EngineException(413, "OUTPUT_LIMIT", "Output limit exceeded");
        }
        if (!finished) {
            throw new EngineException(504, "TIMED_OUT", "Key generation timed out");
        }
        if (p.exitValue() != 0) {
            throw new EngineException(500, "KEYGEN_FAILED", "Native key generation failed");
        }
    }

    private void runOpenSslEcDer(String curveOption, Path outDerFile, Path workDir, long deadlineNanos, List<byte[]> sensitive) throws Exception {
        long rem1 = deadlineNanos - System.nanoTime();
        if (rem1 <= 0) {
            throw new EngineException(504, "TIMED_OUT", "Key generation timed out");
        }

        ProcessBuilder pb1 = new ProcessBuilder(settings.openssl.toString(), "genpkey", "-algorithm", "EC", "-pkeyopt", curveOption);
        pb1.environment().clear();
        pb1.environment().put("LANG", "C");
        pb1.environment().put("LC_ALL", "C");
        Process p1 = pb1.start();

        ExecutionService.Capture p1Out = new ExecutionService.Capture(65536);
        ExecutionService.Capture p1Err = new ExecutionService.Capture(65536);
        var outFut1 = io.submit(() -> p1Out.drain(p1.getInputStream(), p1));
        var errFut1 = io.submit(() -> p1Err.drain(p1.getErrorStream(), p1));

        boolean f1 = false;
        byte[] p1Bytes = null;
        try {
            f1 = p1.waitFor(rem1, TimeUnit.NANOSECONDS);
            if (!f1) {
                ExecutionService.stop(p1);
                throw new EngineException(504, "TIMED_OUT", "Key generation timed out");
            }
            outFut1.get(1, TimeUnit.SECONDS);
            errFut1.get(1, TimeUnit.SECONDS);
            if (p1.exitValue() != 0) {
                throw new EngineException(500, "KEYGEN_FAILED", "OpenSSL key generation failed");
            }
            p1Bytes = p1Out.bytes();
            sensitive.add(p1Bytes);
        } finally {
            if (p1.isAlive()) ExecutionService.stop(p1);
            outFut1.cancel(true);
            errFut1.cancel(true);
            p1Out.clear();
            p1Err.clear();
        }

        long rem2 = deadlineNanos - System.nanoTime();
        if (rem2 <= 0) {
            throw new EngineException(504, "TIMED_OUT", "Key generation timed out");
        }

        ProcessBuilder pb2 = new ProcessBuilder(settings.openssl.toString(), "pkcs8", "-topk8", "-nocrypt", "-outform", "DER", "-out", outDerFile.toString());
        pb2.environment().clear();
        pb2.environment().put("LANG", "C");
        pb2.environment().put("LC_ALL", "C");
        Process p2 = pb2.start();

        ExecutionService.Capture p2Out = new ExecutionService.Capture(65536);
        ExecutionService.Capture p2Err = new ExecutionService.Capture(65536);
        var outFut2 = io.submit(() -> p2Out.drain(p2.getInputStream(), p2));
        var errFut2 = io.submit(() -> p2Err.drain(p2.getErrorStream(), p2));
        final byte[] p1Input = p1Bytes;
        var writeFut2 = io.submit(() -> {
            try (var os = p2.getOutputStream()) {
                os.write(p1Input);
            } catch (IOException ignored) {}
        });

        boolean f2 = false;
        try {
            f2 = p2.waitFor(rem2, TimeUnit.NANOSECONDS);
            if (!f2) {
                ExecutionService.stop(p2);
                throw new EngineException(504, "TIMED_OUT", "Key generation timed out");
            }
            writeFut2.get(1, TimeUnit.SECONDS);
            outFut2.get(1, TimeUnit.SECONDS);
            errFut2.get(1, TimeUnit.SECONDS);
            if (p2.exitValue() != 0) {
                throw new EngineException(500, "KEYGEN_FAILED", "OpenSSL key formatting failed");
            }
        } finally {
            if (p2.isAlive()) ExecutionService.stop(p2);
            writeFut2.cancel(true);
            outFut2.cancel(true);
            errFut2.cancel(true);
            p2Out.clear();
            p2Err.clear();
        }
    }
}
