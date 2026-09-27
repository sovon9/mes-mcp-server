package com.sovon9.mes_mcp_server.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

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

    /**
     * Hosts an https redirect_uri may point to when a client registers via {@code POST /register}
     * (exact, case-insensitive match — no wildcards). Empty means no external host is allowed.
     * Loopback http redirects ({@code localhost}, {@code 127.0.0.1}, {@code [::1]}) are always allowed.
     */
    private List<String> allowedRedirectHosts = new ArrayList<>();

    /**
     * Private-use URI schemes (RFC 8252 §7.1, e.g. {@code cursor}, {@code vscode}) that native
     * clients may register as redirect_uri. Empty means none.
     */
    private List<String> allowedCustomSchemes = new ArrayList<>();

    /** Maximum number of redirect_uris a single client may register. */
    private int maxRedirectUris = 5;

    /** Upper bound on registered clients, to stop unauthenticated /register from filling the table. */
    private long maxRegisteredClients = 10_000;

    // ── Getters & Setters ──────────────────────────────────────────────────────

    public List<String> getAllowedRedirectHosts() { return allowedRedirectHosts; }
    public void setAllowedRedirectHosts(List<String> allowedRedirectHosts) { this.allowedRedirectHosts = allowedRedirectHosts; }

    public List<String> getAllowedCustomSchemes() { return allowedCustomSchemes; }
    public void setAllowedCustomSchemes(List<String> allowedCustomSchemes) { this.allowedCustomSchemes = allowedCustomSchemes; }

    public int getMaxRedirectUris() { return maxRedirectUris; }
    public void setMaxRedirectUris(int maxRedirectUris) { this.maxRedirectUris = maxRedirectUris; }

    public long getMaxRegisteredClients() { return maxRegisteredClients; }
    public void setMaxRegisteredClients(long maxRegisteredClients) { this.maxRegisteredClients = maxRegisteredClients; }

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
