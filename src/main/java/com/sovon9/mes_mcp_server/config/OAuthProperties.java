package com.sovon9.mes_mcp_server.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Configuration properties for the OAuth PKCE proxy layer.
 * This MCP server acts as an Authorization Server front-end that proxies
 * the actual authentication to an upstream Authorization Server (e.g., Spring Authorization Server).
 *
 * <p>Flow summary:
 * <ol>
 *   <li>Claude Code discovers {@code /.well-known/oauth-authorization-server}</li>
 *   <li>Claude Code registers itself via {@code POST /register}</li>
 *   <li>Claude Code initiates PKCE flow → {@code GET /authorize}</li>
 *   <li>MCP server redirects browser to upstream AS login page</li>
 *   <li>Upstream AS redirects back to {@code GET /callback} with auth code</li>
 *   <li>MCP server exchanges code with upstream, issues its own short-lived code to Claude</li>
 *   <li>Claude Code exchanges code + code_verifier at {@code POST /token}</li>
 *   <li>MCP server verifies PKCE and returns the upstream JWT</li>
 *   <li>Claude uses JWT as Bearer token on all subsequent MCP calls</li>
 * </ol>
 */
@Component
@ConfigurationProperties(prefix = "mes.oauth")
public class OAuthProperties {

    /**
     * Public base URL of this MCP server. Used to build redirect_uri for upstream AS
     * and for the {@code /.well-known} metadata endpoints.
     */
    private String issuerUri = "http://localhost:8088";

    /**
     * Authorization endpoint of the upstream Authorization Server.
     * Example: http://localhost:9000/oauth2/authorize
     */
    private String upstreamAuthorizationUri = "http://localhost:9000/oauth2/authorize";

    /**
     * Token endpoint of the upstream Authorization Server.
     * Example: http://localhost:9000/oauth2/token
     */
    private String upstreamTokenUri = "http://localhost:9000/oauth2/token";

    /**
     * Client ID that this MCP server is registered as in the upstream AS.
     * The upstream AS must allow {@code <issuerUri>/callback} as a redirect URI for this client.
     */
    private String upstreamClientId;

    /**
     * Client secret for the upstream client registration.
     * Leave blank if the upstream client is configured as a public client.
     */
    private String upstreamClientSecret;

    // ── Getters & Setters ──────────────────────────────────────────────────────

    public String getIssuerUri() { return issuerUri; }
    public void setIssuerUri(String issuerUri) { this.issuerUri = issuerUri; }

    public String getUpstreamAuthorizationUri() { return upstreamAuthorizationUri; }
    public void setUpstreamAuthorizationUri(String upstreamAuthorizationUri) { this.upstreamAuthorizationUri = upstreamAuthorizationUri; }

    public String getUpstreamTokenUri() { return upstreamTokenUri; }
    public void setUpstreamTokenUri(String upstreamTokenUri) { this.upstreamTokenUri = upstreamTokenUri; }

    public String getUpstreamClientId() { return upstreamClientId; }
    public void setUpstreamClientId(String upstreamClientId) { this.upstreamClientId = upstreamClientId; }

    public String getUpstreamClientSecret() { return upstreamClientSecret; }
    public void setUpstreamClientSecret(String upstreamClientSecret) { this.upstreamClientSecret = upstreamClientSecret; }
}
