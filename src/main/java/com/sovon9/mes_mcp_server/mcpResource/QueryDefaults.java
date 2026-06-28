package com.sovon9.mes_mcp_server.mcpResource;

import org.springframework.ai.mcp.annotation.McpResource;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;

import java.nio.file.Files;
import java.nio.file.Path;

@Component
public class QueryDefaults {

    @McpResource(
            uri = "config://graphql/query-defaults",
            name = "GraphQL Intent and Default Fields Dictionary",
            description = """
                    Contains the system blueprint mapping natural language intents (like downtime or activities)
                    to their recommended default GraphQL fields. ALWAYS reference this resource to pick fields
                    when the user does not specify exact fields in their prompt."""
    )
    public String getIntentDictionary() {
        try {
            ClassPathResource resource = new ClassPathResource("query-defaults.yaml");
            return Files.readString(Path.of(resource.getURI()));
        } catch (Exception e) {
            return "Error loading intent configurations: " + e.getMessage();
        }
    }

}
