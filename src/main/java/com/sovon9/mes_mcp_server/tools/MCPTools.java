package com.sovon9.mes_mcp_server.tools;

import com.sovon9.mes_mcp_server.config.GraphQlDefaultsProperties;
import com.sovon9.mes_mcp_server.sdl.GraphQLSDL;
import graphql.introspection.IntrospectionQuery;
import graphql.introspection.IntrospectionResultToSchema;
import graphql.language.*;
import graphql.schema.idl.SchemaPrinter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ai.mcp.annotation.McpArg;
import org.springframework.ai.mcp.annotation.McpTool;
import org.springframework.ai.mcp.annotation.McpToolParam;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.health.actuate.endpoint.HealthEndpoint;
import org.springframework.boot.health.contributor.Status;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;

import java.util.*;
import java.util.stream.Collectors;

//@Component
@RestController
public class MCPTools {

    private RestClient restClient;
//    private HealthEndpoint healthEndpoint;

    @Value("${graphql-service-url:}")
    private String graphqlService;

    private GraphQlDefaultsProperties defaultsProperties;

    Logger lOGGER = LoggerFactory.getLogger(MCPTools.class);

    public MCPTools(GraphQlDefaultsProperties defaultsProperties) {
        this.restClient = RestClient.builder().build();
        this.defaultsProperties = defaultsProperties;
//        this.healthEndpoint = healthEndpoint;
    }

    @McpTool(name = "graphql-introspect", description = """
            Returns the full GraphQL schema introspection.
            
            ⚠️CRITICAL: When constructing queries, you are strictly forbidden from guessing
            or adding fields outside of the 'preferred_default_fields' list provided in the response
            
            Use this to understand available types, queries, mutations, and their fields before constructing any GraphQL queries.
            """)
    public Map<String, Object> introspect(@McpToolParam(description = "GraphQL type name to introspect (e.g., Downtime, Activity). If empty, returns full schema") String typeName,
                             @McpToolParam(description = "Depth of nested type expansion. default = 1") Integer depth)
    {
        Map<String, Object> response=new HashMap<>();
        response.put("typeName", typeName);
        String introspectionQuery = IntrospectionQuery.INTROSPECTION_QUERY
                .replace("isOneOf", "");
        Map query = restClient.post().uri(graphqlService).header(
                        "Content-Type", "application/json")
                .body(Map.of("query", introspectionQuery))
                .retrieve().body(Map.class);

        Object dataObj = query.get("data");

        Map<String, Object> data =  (Map<String, Object>)dataObj;

//        // Filter out null interface names to prevent NPE in IntrospectionResultToSchema
//        Map<String, Object> schema = (Map<String, Object>) data.get("__schema");
//        List<Map<String, Object>> types = (List<Map<String, Object>>) schema.get("types");
//        for (Map<String, Object> type : types) {
//            List<Map<String, Object>> interfaces = (List<Map<String, Object>>) type.get("interfaces");
//            if (interfaces != null) {
//                interfaces.removeIf(iface -> iface.get("name") == null);
//            }
//        }

        Document schemaDocument=null;
        try {
            IntrospectionResultToSchema converter = new IntrospectionResultToSchema();
            schemaDocument = converter.createSchemaDefinition(data);
        }
        catch (Exception e)
        {
            e.printStackTrace();
            throw e;
        }

        SchemaPrinter.Options options = SchemaPrinter.Options.defaultOptions()
                .includeScalarTypes(false) // Hides built-in Scalars (String, Int, etc.)
                .includeSchemaDefinition(false)
                .includeDirectives(false);

        // 1. Full schema — return everything
        if (typeName == null || typeName.isBlank()) {
            response.put("introspection", schemaDocument);
            return response;
        }

        // Type-specific — build a lookup map by type name

        // 2. Map all definitions by their name for quick O(1) lookup
        Map<String, TypeDefinition<?>> typeIndex = schemaDocument.getDefinitions().stream()
                .filter(def -> def instanceof TypeDefinition<?>)
                .map(def -> (TypeDefinition<?>) def)
                .collect(Collectors.toMap(TypeDefinition::getName, td -> td));

        // 3. Expand root type + related types up to depth
        int finalDepth = (depth == null || depth < 1) ? 1 : depth;
        Set<String> visited = new LinkedHashSet<>(); // preserves insertion order
        collectTypes(typeName, typeIndex, finalDepth, visited, 0);

        if (visited.isEmpty()) {
            response.put("ERROR","Type not found: " + typeName);
            return response;
        }

        // 4. Build SDL from only the collected types
        List<Definition> filteredDefs = visited.stream()
                .map(typeIndex::get)
                .filter(Objects::nonNull)
                .collect(Collectors.toList());

        Document filteredDocument = Document.newDocument().definitions(filteredDefs).build();
        response.put("introspection", filteredDocument);

        // Inject structural directives right alongside the technical metadata
        Map<String, Object> guidelines = new HashMap<>();

        Map<String, List<String>> defaults = defaultsProperties.getDefaults();
        boolean containsDefault = defaults.containsKey(typeName.toLowerCase());
        if("Query".equalsIgnoreCase(typeName))
        {
            guidelines.put("all_query_preferred_defaults", defaults);
            guidelines.put("instruction", "This is the root Query type. When selecting any of these queries, " +
                    "you MUST default to selecting the specific fields outlined in this dictionary.");
            response.put("business_rules", guidelines);
        }
        else if(defaults.containsKey(typeName.toLowerCase()))
        {
            List<String> typeDefaults = defaults.get(typeName.toLowerCase());
            guidelines.put("preferred_default_fields", typeDefaults);
            guidelines.put("instruction", "When constructing a query for '" + typeName +
                    "', select these default fields unless the user explicitly requested alternative columns.");
            response.put("business_rules", guidelines);
        }
        return response;
    }

    /**
     * Recursively collects a type and its field types up to maxDepth.
     */
    private void collectTypes(String currentTypeName, Map<String, TypeDefinition<?>> typeIndex,
                              int maxDepth, Set<String> visited, int currentDepth) {
        // Notice the 5th parameter above ^^^

        // Stop conditions: reached max depth, already visited, is a built-in scalar, or doesn't exist
        if (currentDepth > maxDepth || visited.contains(currentTypeName) ||
                isBuiltIn(currentTypeName) || !typeIndex.containsKey(currentTypeName)) {
            return;
        }

        visited.add(currentTypeName);
        TypeDefinition<?> typeDef = typeIndex.get(currentTypeName);

        // Recursively find types in Object fields
        if (typeDef instanceof ObjectTypeDefinition objDef) {
            for (FieldDefinition field : objDef.getFieldDefinitions()) {
                String fieldTypeName = extractRawTypeName(field.getType());
                // Pass currentDepth + 1 to the next level
                collectTypes(fieldTypeName, typeIndex, maxDepth, visited, currentDepth + 1);
            }
        }
        // Recursively find types in Input Object fields
        else if (typeDef instanceof InputObjectTypeDefinition inputDef) {
            for (InputValueDefinition field : inputDef.getInputValueDefinitions()) {
                String fieldTypeName = extractRawTypeName(field.getType());
                // Pass currentDepth + 1 to the next level
                collectTypes(fieldTypeName, typeIndex, maxDepth, visited, currentDepth + 1);
            }
        }
    }

    /**
     * Recursively unwraps NonNull (!) and List ([]) wrappers to get the base type name.
     */
    private String extractRawTypeName(Type<?> type) {
        if (type instanceof NonNullType nnt) {
            return extractRawTypeName(nnt.getType());
        } else if (type instanceof ListType lt) {
            return extractRawTypeName(lt.getType());
        } else if (type instanceof TypeName tn) {
            return tn.getName();
        }
        return "";
    }

    /**
     * Checks if a type is a GraphQL built-in scalar or introspection type.
     */
    private boolean isBuiltIn(String typeName) {
        return typeName.startsWith("__") ||
                List.of("String", "Boolean", "Int", "Float", "ID").contains(typeName);
    }

    /**
     * Unwraps ListType / NonNullType wrappers to get the base type name.
     * e.g. [User!]! → "User"
     */
    private String unwrapTypeName(Type<?> type) {
        if (type instanceof TypeName tn) return tn.getName();
        if (type instanceof NonNullType nnt) return unwrapTypeName(nnt.getType());
        if (type instanceof ListType lt) return unwrapTypeName(lt.getType());
        return null;
    }


    @McpTool(name = "execute-query",
            description = """
            Executes a graphql query operation against the backend.
            ⚠️ STRICT RULE:: If the user does not specify exact fields, use default field names for the root query.
            ⚠️If you do not know the exact schema, use the 'introspect' tool first to gather the correct fields and types.
            """)
    public Map<String, Object> executeQuery(
            @McpToolParam(description = "The GraphQL query or mutation string. Must be a valid GraphQL payload.") String query,
            @McpToolParam(description = "A JSON object containing the variables for the query.") Map<String, Object> variables)
    {
        Map<String, Object> bodymap =  new HashMap<>();
        bodymap.put("query", query);
        bodymap.put("variables", variables == null ? Map.of() : variables);

        return restClient.post().uri(graphqlService)
                .body(bodymap)
                .retrieve()
                .body(Map.class);
    }

//    @McpTool(name = "check-system-health", description = """
//            Returns the real-time operational status of the MCP gateway and downstream backend GraphQL services.
//            Run this tool if network errors occur, queries time out, or to verify connection stability.
//            """)
//    public Map<String, Object> health()
//    {
//        Map<String, Object> healthStatus = new HashMap<>();
//        String mcpServerStataus = healthEndpoint.health().getStatus().equals(Status.UP)? "HEALTHY":"DEGRADED";
//        healthStatus.put("mcp-server", mcpServerStataus);
//
//        try {
//            Map<?, ?> backendResponse = restClient.get()
//                    .uri("/actuator/health")
//                    .retrieve()
//                    .body(Map.class);
//
//            String statusStr = (backendResponse != null && backendResponse.containsKey("status"))
//                    ? String.valueOf(backendResponse.get("status"))
//                    : "UNKNOWN";
//
//            String backendHealthStatus = statusStr.equals(Status.UP) ? "HEALTHY" : "DEGRADED";
//            healthStatus.put("graphql-server",backendHealthStatus);
//        }
//        catch (Exception e)
//        {
//            healthStatus.put("graphql-server","DEGRADED");
//        }
//
//        boolean overAllStatus = healthStatus.entrySet().stream().allMatch(es -> es.getValue().equals(Status.UP));
//        healthStatus.put("overall_system_status", overAllStatus);
//
//        return healthStatus;
//    }

}
