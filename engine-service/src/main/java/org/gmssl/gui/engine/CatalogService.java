package org.gmssl.gui.engine;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;

@Component
public class CatalogService {
    private final ObjectNode catalog;
    private final Map<String,JsonNode> tools = new LinkedHashMap<>();
    public CatalogService(ObjectMapper mapper) throws IOException {
        try (var in = new ClassPathResource("catalog.json").getInputStream()) { catalog = (ObjectNode)mapper.readTree(in); }
        var extension = new ClassPathResource("extensions-catalog.json");
        if (extension.exists()) try (var in = extension.getInputStream()) {
            JsonNode extra = mapper.readTree(in);
            for (JsonNode tool : extra.path("tools")) ((ArrayNode)catalog.get("tools")).add(tool);
        }
        for (JsonNode tool : catalog.path("tools")) {
            String id = tool.path("id").asText();
            if (!id.matches("[a-z][a-z0-9_]{0,63}") || tools.putIfAbsent(id, tool) != null) throw new IOException("Invalid catalog identity");
        }
    }
    public JsonNode catalog() { return catalog.deepCopy(); }
    public JsonNode tool(String id) { JsonNode tool = tools.get(id); if (tool == null) throw new EngineException(400,"UNKNOWN_TOOL","Unknown tool"); return tool; }
}
