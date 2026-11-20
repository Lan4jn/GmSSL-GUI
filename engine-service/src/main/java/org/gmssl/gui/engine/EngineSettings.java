package org.gmssl.gui.engine;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

@Component
public class EngineSettings {
    final String token;
    final Path runner;
    final Path work;
    final int maxBytes;
    final int maxProcesses;
    final Set<String> allowedHosts;
    final Set<Integer> allowedPorts;
    final boolean allowLoopback;
    final Path openssl;
    final boolean opensslAvailable;
    final String opensslVersion;

    public EngineSettings(Environment env) {
        token = env.getProperty("GMSSL_ENGINE_TOKEN", "");
        if (token.getBytes(java.nio.charset.StandardCharsets.UTF_8).length < 32) throw new IllegalStateException("Engine token must contain at least 32 bytes");
        runner = Path.of(env.getProperty("GMSSL_RUNNER_PATH", "native/.build/bin/gmssl-runner")).toAbsolutePath().normalize();
        work = Path.of(env.getProperty("GMSSL_ENGINE_WORK_DIR", "engine-service/.work")).toAbsolutePath().normalize();
        maxBytes = bounded(env.getProperty("GMSSL_ENGINE_MAX_BYTES", Integer.class, 16 * 1024 * 1024), 1024, 64 * 1024 * 1024);
        maxProcesses = bounded(env.getProperty("GMSSL_ENGINE_MAX_PROCESSES", Integer.class, 2), 1, 16);
        allowedHosts = split(env.getProperty("GMSSL_ENGINE_ALLOWED_HOSTS", "127.0.0.1,::1"));
        allowedPorts = split(env.getProperty("GMSSL_ENGINE_ALLOWED_PORTS", "14433,14434,14435,14436,14437,14438"))
                .stream().map(Integer::valueOf).collect(Collectors.toUnmodifiableSet());
        allowLoopback = env.getProperty("GMSSL_ENGINE_ALLOW_LOOPBACK", Boolean.class, true);

        String configuredOpenssl = env.getProperty("GMSSL_OPENSSL_PATH");
        Path candidate = null;
        if (configuredOpenssl != null && !configuredOpenssl.isBlank()) {
            Path p = Path.of(configuredOpenssl).toAbsolutePath().normalize();
            try { candidate = p.toRealPath(); } catch (Exception e) { candidate = p; }
        } else {
            for (String fallback : List.of("/opt/homebrew/bin/openssl", "/usr/local/bin/openssl", "/usr/bin/openssl")) {
                Path p = Path.of(fallback);
                try {
                    Path real = p.toRealPath();
                    if (Files.isRegularFile(real) && Files.isExecutable(real)) {
                        candidate = real;
                        break;
                    }
                } catch (Exception ignored) {}
            }
        }

        if (candidate != null && Files.isRegularFile(candidate) && Files.isExecutable(candidate)) {
            String v = probeOpenssl(candidate);
            if (v != null) {
                openssl = candidate;
                opensslAvailable = true;
                opensslVersion = v;
            } else {
                openssl = candidate;
                opensslAvailable = false;
                opensslVersion = null;
            }
        } else {
            openssl = candidate;
            opensslAvailable = false;
            opensslVersion = null;
        }
    }

    private static String probeOpenssl(Path path) {
        try {
            ProcessBuilder pb = new ProcessBuilder(path.toString(), "version");
            pb.environment().clear();
            pb.environment().put("LANG", "C");
            pb.environment().put("LC_ALL", "C");
            Process p = pb.start();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
                String line = reader.readLine();
                boolean finished = p.waitFor(3, TimeUnit.SECONDS);
                if (finished && p.exitValue() == 0 && line != null && !line.isBlank()) {
                    return line.trim();
                }
            }
        } catch (Exception ignored) {}
        return null;
    }

    private static Set<String> split(String s) { return Arrays.stream(s.split(",")).map(String::trim).filter(v -> !v.isEmpty()).collect(Collectors.toUnmodifiableSet()); }
    private static int bounded(int x, int lo, int hi) { if (x < lo || x > hi) throw new IllegalStateException("Engine resource limit outside permitted range"); return x; }
}
