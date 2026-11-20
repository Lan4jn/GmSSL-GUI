package org.gmssl.gui.engine;

import java.util.List;
import java.util.Map;

public final class EngineModels {
    private EngineModels() {}
    public record Input(String name, String contentBase64) {}
    public record ExecutionRequest(String id, String toolId, Map<String,Object> parameters,
            Map<String,Input> inputs, String stdinBase64, Integer timeoutSeconds) {}
    public record Artifact(String name, String mediaType, String contentBase64) {}
    public record UpdatedInput(String token, String contentBase64) {}
    public record ExecutionResponse(String id, String status, Integer exitCode, String stdoutBase64,
            String stderr, long durationMs, boolean truncated, List<Artifact> artifacts,
            List<UpdatedInput> updatedInputs) {}
    public record ApiError(String code, String message, String requestId) {}

    public record ProviderCapability(String id, boolean available, String version, String reason, List<String> algorithms) {}
    public record AlgorithmCapability(String id, String kind, List<Integer> bits, List<String> curves, List<String> providers) {}
    public record KeyGenCapabilitiesResponse(List<ProviderCapability> providers, List<AlgorithmCapability> algorithms) {}

    public record KeyGenRequest(String requestId, String provider, String algorithm, Integer bits, String curve, String password, Integer timeoutSeconds) {}

    public record KeyGenResponse(String provider, String algorithm, String keyKind, String encoding, String valueBase64, String privateKeyBase64, String publicKeyBase64, List<String> warnings) {}
}
