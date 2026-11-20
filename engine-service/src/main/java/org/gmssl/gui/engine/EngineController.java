package org.gmssl.gui.engine;

import static org.gmssl.gui.engine.EngineModels.*;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/internal/v1")
public class EngineController {
    private final CatalogService catalog;
    private final ExecutionService executions;
    private final KeyGenerationService keyGenerations;

    EngineController(CatalogService catalog, ExecutionService executions, KeyGenerationService keyGenerations) {
        this.catalog = catalog;
        this.executions = executions;
        this.keyGenerations = keyGenerations;
    }

    @GetMapping("/capabilities") public JsonNode capabilities() { return catalog.catalog(); }
    @PostMapping("/executions") public ExecutionResponse execute(@RequestBody ExecutionRequest request) { return executions.execute(request); }
    @PostMapping("/executions/{id}/cancel") public Map<String,Boolean> cancel(@PathVariable String id) { return Map.of("cancelled", executions.cancel(id)); }

    @GetMapping("/key-generation-capabilities")
    public KeyGenCapabilitiesResponse keyGenerationCapabilities() {
        return keyGenerations.capabilities();
    }

    @PostMapping("/key-generations")
    public KeyGenResponse generateKey(@RequestBody KeyGenRequest request) {
        return keyGenerations.generate(request);
    }
}

@RestControllerAdvice
class EngineErrors {
    @ExceptionHandler(EngineException.class) ResponseEntity<ApiError> error(EngineException e) { return ResponseEntity.status(e.status).body(new ApiError(e.code, e.getMessage(), UUID.randomUUID().toString())); }
    @ExceptionHandler(Exception.class) ResponseEntity<ApiError> unexpected(Exception e) { return ResponseEntity.badRequest().body(new ApiError("INVALID_REQUEST", "Request could not be processed", UUID.randomUUID().toString())); }
}
