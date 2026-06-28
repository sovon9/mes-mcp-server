package com.sovon9.mes_mcp_server.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;

import java.util.List;
import java.util.Map;

@Configuration
@ConfigurationProperties(prefix = "mcp.graphql")
public class GraphQlDefaultsProperties {

    Map<String, List<String>> defaults;

    public Map<String, List<String>> getDefaults() {
        return defaults;
    }

    public void setDefaults(Map<String, List<String>> defaults) {
        this.defaults = defaults;
    }

}
