package com.sovon9.mes_mcp_server.tools;

import com.sovon9.mes_mcp_server.sdl.GraphQLSDL;
import graphql.introspection.IntrospectionResultToSchema;
import graphql.language.*;
import org.springframework.ai.mcp.annotation.McpArg;
import org.springframework.ai.mcp.annotation.McpTool;
import org.springframework.ai.mcp.annotation.McpToolParam;
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

    public MCPTools() {
        this.restClient = RestClient.builder().baseUrl("http://localhost:8080/graphql").build();
    }

    @McpTool(name = "introspect", description = "Returns the full GraphQL schema in SDL format.\n" +
            "            Use this to understand available types, queries, mutations, and their fields\n" +
            "            before constructing any GraphQL queries.")
    public String introspect(@McpToolParam(description = "GraphQL type to inspect. If empty, returns full schema") String typeName, @McpToolParam(description = "Depth of nested type expansion. default = 1") Integer depth)
    {
        Map query = restClient.post().header(
                        "Content-Type", "application/json")
                .body(Map.of("query", GraphQLSDL.INTROSPECTION_SCHEMA))
                .retrieve().body(Map.class);

        Object dataObj = query.get("data");

        Map<String, Object> data =  (Map<String, Object>)dataObj;

        IntrospectionResultToSchema converter = new IntrospectionResultToSchema();
        Document fullDocument = converter.createSchemaDefinition(data);

        // Filter what the LLM doesn't need
        List<String> BUILT_IN_TYPES = List.of(
                "String", "Boolean", "Int", "Float", "ID",  // scalars
                "__Schema", "__Type", "__Field", "__InputValue", // introspection types
                "__EnumValue", "__Directive", "__DirectiveLocation"
        );

        List<Definition> cleanDefinitions = fullDocument.getDefinitions().stream()
                .filter(def -> !(def instanceof DirectiveDefinition))  // remove all directives
                .filter(def -> {
                    if (def instanceof TypeDefinition<?> td) {
                        return !BUILT_IN_TYPES.contains(td.getName()); // remove built-in types
                    }
                    return true;
                })
                .toList();

        // Full schema — return everything
        if (typeName == null || typeName.isBlank()) {
            Document cleanDocument = Document.newDocument().definitions(cleanDefinitions)
                    .build();
            return AstPrinter.printAst(cleanDocument);
        }

        // Type-specific — build a lookup map by type name

        Map<String, TypeDefinition<?>> typeIndex = cleanDefinitions.stream()
                .filter(def -> def instanceof TypeDefinition<?>)
                .map(def -> (TypeDefinition<?>) def)
                .collect(Collectors.toMap(TypeDefinition::getName, td -> td));

        // Expand root type + related types up to depth
        int finalDepth = (depth == null || depth < 1) ? 1 : depth;
        Set<String> visited = new LinkedHashSet<>(); // preserves insertion order
        collectTypes(typeName, typeIndex, finalDepth, visited);

        if (visited.isEmpty()) {
            return "Type not found: " + typeName;
        }

        // Build SDL from only the collected types
        List<Definition> filteredDefs = visited.stream()
                .map(typeIndex::get)
                .filter(Objects::nonNull)
                .map(td -> (Definition) td)
                .toList();

        return AstPrinter.printAst(Document.newDocument().definitions(filteredDefs).build());
    }

    /**
     * Recursively collects a type and its field types up to maxDepth.
     */
    private void collectTypes(String typeName, Map<String, TypeDefinition<?>> typeIndex,
                              int remainingDepth, Set<String> visited) {
        if (typeName == null || visited.contains(typeName)) return;

        TypeDefinition<?> typeDef = typeIndex.get(typeName);
        if (typeDef == null) return; // built-in or unknown, skip

        visited.add(typeName);

        if (remainingDepth == 0) return; // don't expand fields further

        // Collect field types based on the kind of type
        List<String> referencedTypes = new ArrayList<>();

        if (typeDef instanceof ObjectTypeDefinition otd) {
            otd.getFieldDefinitions().forEach(field -> {
                referencedTypes.add(unwrapTypeName(field.getType()));
                field.getInputValueDefinitions().forEach(arg ->
                        referencedTypes.add(unwrapTypeName(arg.getType())));
            });
        } else if (typeDef instanceof InputObjectTypeDefinition iotd) {
            iotd.getInputValueDefinitions().forEach(field ->
                    referencedTypes.add(unwrapTypeName(field.getType())));
        } else if (typeDef instanceof InterfaceTypeDefinition itd) {
            itd.getFieldDefinitions().forEach(field ->
                    referencedTypes.add(unwrapTypeName(field.getType())));
        } else if (typeDef instanceof UnionTypeDefinition utd) {
            utd.getMemberTypes().forEach(member ->
                    referencedTypes.add(unwrapTypeName(member)));
        }

        // Recurse into each referenced type
        referencedTypes.forEach(ref ->
                collectTypes(ref, typeIndex, remainingDepth - 1, visited));
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

//    private Map<String, Object> findTypeByName(List<Map<String, Object>> types, String typeName) {
//        return types.stream().filter(type->typeName.equals(type.get("name")))
//                .findFirst().orElse(null);
//    }


    @McpTool(name = "execute-query", description = "Executes graphql query")
    public Map<String, Object> executeQuery(@RequestBody String query, @RequestParam Map<String, Object> variables)
    {
        Map<String, Object> bodymap =  new HashMap<>();
        bodymap.put("query", query);
        bodymap.put("variables", variables == null ? Map.of() : variables);

        return restClient.post()
                .body(bodymap)
                .retrieve()
                .body(Map.class);
    }

}
