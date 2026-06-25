package com.sovon9.mes_mcp_server.sdl;

public class GraphQLSDL {
    public static final String INTROSPECTION_SCHEMA = """
            {
                __schema {
                    queryType { name }
                    types {
                       kind
                       name
                       description
                       fields(includeDeprecated: true) {
                           name
                           description
                           args {
                                name
                                type {
                                    kind
                                    name
                                    ofType {
                                        kind
                                        name
                                        ofType { kind name }
                                    }
                                }
                           }
                           type {
                               kind
                               name
                               ofType {
                                    kind
                                    name
                                    ofType { kind name }
                               }
                           }
                       }
                       inputFields {
                           name
                           type {
                              kind
                              name
                              ofType { kind name ofType { kind name } }
                           }
                       }
                       interfaces { name }
                       enumValues(includeDeprecated: true) { name }
                       possibleTypes { name }
                    }
                }
            }
            """;
}
