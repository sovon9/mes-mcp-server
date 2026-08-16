package com.sovon9.mes_mcp_server.oauth;

import com.sovon9.mes_mcp_server.config.OAuthProperties;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Exposes the OAuth 2.0 Authorization Server Metadata endpoints required by the MCP spec.
 *
 * <p>Claude Code (and any other MCP client) performs discovery by fetching:
 * <pre>
 *   GET /.well-known/oauth-authorization-server
 * </pre>
 * This tells Claude Code where to find /authorize, /token, /register, and which
 * PKCE challenge methods are supported.
 *
 * <p>Also exposes the Protected Resource Metadata (RFC 9728) which links the
 * resource server back to this authorization server:
 * <pre>
 *   GET /.well-known/oauth-protected-resource
 * </pre>
 */
@RestController
public class OAuthMetadataController {

    private final OAuthProperties props;

    public OAuthMetadataController(OAuthProperties props) {
        this.props = props;
    }

    /**
     * RFC 8414 — OAuth 2.0 Authorization Server Metadata.
     * Claude Code reads this to discover all OAuth endpoints on this MCP server.
     */
    @GetMapping("/.well-known/oauth-authorization-server")
    public Map<String, Object> authorizationServerMetadata() {
        String issuer = props.getIssuerUri();

        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("issuer",                              issuer);
        meta.put("authorization_endpoint",              issuer + "/authorize");
        meta.put("token_endpoint",                      issuer + "/token");
        meta.put("registration_endpoint",               issuer + "/register");
        meta.put("response_types_supported",            List.of("code"));
        meta.put("grant_types_supported",               List.of("authorization_code", "refresh_token"));
        meta.put("code_challenge_methods_supported",    List.of("S256"));
        meta.put("token_endpoint_auth_methods_supported", List.of("none", "client_secret_post"));
        return meta;
    }

    /**
     * RFC 9728 — OAuth 2.0 Protected Resource Metadata.
     * Tells clients that this resource is protected by our own authorization server.
     */
    @GetMapping("/.well-known/oauth-protected-resource")
    public Map<String, Object> protectedResourceMetadata() {
        String issuer = props.getIssuerUri();

        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("resource",             issuer);
        meta.put("authorization_servers", List.of(issuer));
        return meta;
    }
}
