package com.sovon9.mes_mcp_server.sdl;

public class GraphQLSDL {
    public static final String INTROSPECTION_SCHEMA = """
            {
                __schema {
                    queryType { name }
                    mutationType { name }
                    subscriptionType { name }
                    directives {
                        name
                        locations
                        args {
                            name
                            type {
                                kind
                                name
                                ofType { kind name }
                            }
                        }
                    }
                    types {
                       kind
                       name
                       enumValues(includeDeprecated: true) {
                          name
                       }
                       fields(includeDeprecated: true) {
                           name
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
                              ofType { kind name }
                           }
                       }
                    }
                }
            }
            """;
}
