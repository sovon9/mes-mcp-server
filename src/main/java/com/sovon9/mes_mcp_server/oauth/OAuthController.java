package com.sovon9.mes_mcp_server.oauth;

import com.sovon9.mes_mcp_server.config.OAuthProperties;
import com.sovon9.mes_mcp_server.oauth.model.OAuthClient;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestClient;

import java.io.IOException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * OAuth 2.0 PKCE proxy in front of the upstream Authorization Server.
 *
 * <h2>Client trust model</h2>
 * Clients self-register at {@code /register} (RFC 7591) as public clients. Registration is validated
 * ({@link RedirectUriPolicy}) and persisted, and from then on the registered redirect URIs are the
 * only place an authorization code may be sent:
 * <ul>
 *   <li>{@code /authorize} rejects unknown clients and unregistered redirect URIs, and requires S256 PKCE</li>
 *   <li>{@code /callback} re-checks the client and redirect URI carried in {@code state}</li>
 *   <li>{@code /token} requires the same {@code client_id}, {@code redirect_uri} and the PKCE verifier</li>
 * </ul>
 * PKCE alone does not authenticate the client — it only binds the code to whoever started the flow —
 * so the registered-redirect check is what stops a code being delivered to an attacker.
 *
 * <h2>state = Base64(key=value pairs)</h2>
 * Between /authorize and /callback the flow data (client, redirect_uri, code_challenge, original state,
 * our upstream PKCE verifier) travels in the {@code state} parameter, so no pending-flow map is kept.
 * The state is not signed; /callback therefore trusts nothing in it without re-validating against the
 * client registry.
 *
 * <p>The only in-memory store is {@code issuedCodes} between /callback and /token.
 */
@RestController
public class OAuthController {

    private static final Logger log = LoggerFactory.getLogger(OAuthController.class);

    private static final long CODE_TTL_SECONDS = 300;
    private static final int MAX_CLIENT_NAME_LENGTH = 100;

    private final OAuthProperties props;
    private final OAuthClientRepository clients;
    private final RedirectUriPolicy redirectPolicy;
    private final RestClient restClient;

    // Single-use codes issued at /callback, consumed at /token (5-min TTL). Package-private for tests.
    final Map<String, Map<String, String>> issuedCodes = new ConcurrentHashMap<>();

    public OAuthController(OAuthProperties props, OAuthClientRepository clients, RedirectUriPolicy redirectPolicy) {
        this.props          = props;
        this.clients        = clients;
        this.redirectPolicy = redirectPolicy;
        this.restClient     = RestClient.builder().build();
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // POST /register  — RFC 7591 Dynamic Client Registration
    // Validates the redirect URIs, persists the client, returns a public client_id.
    // ═══════════════════════════════════════════════════════════════════════════
    @PostMapping("/register")
    public ResponseEntity<Map<String, Object>> register(@RequestBody Map<String, Object> body) {
        if (clients.count() >= props.getMaxRegisteredClients()) {
            return ResponseEntity.status(503)
                    .body(Map.of("error", "temporarily_unavailable", "error_description", "Client registry is full"));
        }

        if (!(body.get("redirect_uris") instanceof List<?> rawUris)
                || rawUris.isEmpty() || rawUris.size() > props.getMaxRedirectUris()) {
            return registrationError("invalid_redirect_uri",
                    "redirect_uris must be a list of 1 to " + props.getMaxRedirectUris() + " URIs");
        }
        Set<String> redirectUris = new LinkedHashSet<>();
        for (Object raw : rawUris) {
            String problem = raw instanceof String s ? redirectPolicy.validate(s) : "redirect_uris must contain strings";
            if (problem != null) return registrationError("invalid_redirect_uri", problem);
            redirectUris.add((String) raw);
        }

        String clientName = body.get("client_name") instanceof String s ? sanitizeName(s) : null;
        String clientId = UUID.randomUUID().toString();
        clients.save(new OAuthClient(clientId, clientName, List.copyOf(redirectUris), Instant.now()));
        log.info("Client registered: clientId={} name={} redirectUris={}", clientId, clientName, redirectUris);

        // Only public clients / authorization_code + refresh_token are supported; per RFC 7591 §3.2.1
        // the response states what was actually registered, whatever the client asked for.
        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("client_id",                  clientId);
        resp.put("client_id_issued_at",        Instant.now().getEpochSecond());
        if (clientName != null) resp.put("client_name", clientName);
        resp.put("redirect_uris",              List.copyOf(redirectUris));
        resp.put("grant_types",                List.of("authorization_code", "refresh_token"));
        resp.put("response_types",             List.of("code"));
        resp.put("token_endpoint_auth_method", "none");
        return ResponseEntity.status(201).body(resp);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // GET /authorize
    //
    // 1. Validate client_id and redirect_uri against the registry. On failure show an error —
    //    never redirect to an unverified redirect_uri.
    // 2. Require S256 PKCE.
    // 3. Generate our own PKCE pair for the upstream AS, pack the flow data into state,
    //    and redirect the browser to the upstream login page.
    // ═══════════════════════════════════════════════════════════════════════════
    @GetMapping("/authorize")
    public void authorize(
            @RequestParam("client_id")                                 String clientId,
            @RequestParam("redirect_uri")                              String redirectUri,
            @RequestParam(value = "response_type",        required = false) String responseType,
            @RequestParam(value = "state",                required = false) String state,
            @RequestParam(value = "code_challenge",       required = false) String codeChallenge,
            @RequestParam(value = "code_challenge_method",required = false) String codeChallengeMethod,
            HttpServletResponse response) throws IOException {

        OAuthClient client = clients.findById(clientId).orElse(null);
        if (client == null) {
            log.warn("/authorize rejected: unknown client_id");
            response.sendError(400, "Unknown client_id");
            return;
        }
        if (!redirectPolicy.isRegistered(client.getRedirectUris(), redirectUri)) {
            log.warn("/authorize rejected: redirect_uri not registered for clientId={}", clientId);
            response.sendError(400, "redirect_uri is not registered for this client");
            return;
        }

        // From here the redirect_uri is trusted, so errors go back to the client.
        if (!"code".equals(responseType)) {
            redirectError(response, redirectUri, state, "unsupported_response_type", "response_type must be code");
            return;
        }
        if (codeChallenge == null || codeChallenge.isBlank() || !"S256".equals(codeChallengeMethod)) {
            redirectError(response, redirectUri, state, "invalid_request",
                    "PKCE is required: send code_challenge with code_challenge_method=S256");
            return;
        }

        String upstreamVerifier  = generateVerifier();
        String upstreamChallenge = s256(upstreamVerifier);

        String rawState = "clientId="       + encode(clientId)
                + "&redirectUri="           + encode(redirectUri)
                + "&clientState="           + encode(state != null ? state : "")
                + "&codeChallenge="         + encode(codeChallenge)
                + "&upstreamVerifier="      + encode(upstreamVerifier);
        String encodedState = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(rawState.getBytes(StandardCharsets.UTF_8));

        String loginUrl = props.getUpstreamAuthorizationUri()
                + "?response_type=code"
                + "&client_id="             + encode(props.getUpstreamClientId())
                + "&redirect_uri="          + encode(props.getIssuerUri() + "/callback")
                + "&state="                 + encode(encodedState)
                + "&scope=openid"
                + "&code_challenge="        + encode(upstreamChallenge)
                + "&code_challenge_method=S256";

        // state holds the upstream PKCE verifier — do not log the URL
        log.info("Redirecting clientId={} to upstream AS login", clientId);
        response.sendRedirect(loginUrl);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // GET /callback
    //
    // Upstream AS lands here after user login.
    // Decode state → re-validate client + redirect_uri → exchange code with upstream →
    // issue a local single-use code to the client.
    // ═══════════════════════════════════════════════════════════════════════════
    @GetMapping("/callback")
    public void callback(
            @RequestParam(value = "code",              required = false) String code,
            @RequestParam(value = "state",             required = false) String state,
            @RequestParam(value = "error",             required = false) String error,
            @RequestParam(value = "error_description", required = false) String errorDesc,
            HttpServletResponse response) throws IOException {

        if (error != null) {
            log.error("Upstream AS error: {} — {}", error, errorDesc);
            response.sendError(400, "Upstream auth error: " + error + " — " + errorDesc);
            return;
        }
        if (code == null || state == null) {
            response.sendError(400, "Missing code or state");
            return;
        }

        Map<String, String> statePayload;
        try {
            String rawState = new String(Base64.getUrlDecoder().decode(state), StandardCharsets.UTF_8);
            statePayload = new HashMap<>();
            for (String pair : rawState.split("&")) {
                int idx = pair.indexOf('=');
                if (idx > 0) {
                    String k = pair.substring(0, idx);
                    String v = URLDecoder.decode(pair.substring(idx + 1), StandardCharsets.UTF_8);
                    statePayload.put(k, v);
                }
            }
        } catch (Exception e) {
            log.error("Failed to decode state: {}", e.getMessage());
            response.sendError(400, "Invalid state parameter");
            return;
        }

        String clientId          = statePayload.get("clientId");
        String redirectUri       = statePayload.get("redirectUri");
        String clientState       = statePayload.get("clientState");
        String codeChallenge     = statePayload.get("codeChallenge");
        String upstreamVerifier  = statePayload.get("upstreamVerifier");

        // state is not signed, so never trust its redirect_uri without checking the registry again
        OAuthClient client = clientId == null ? null : clients.findById(clientId).orElse(null);
        if (client == null || codeChallenge == null || codeChallenge.isBlank() || upstreamVerifier == null
                || !redirectPolicy.isRegistered(client.getRedirectUris(), redirectUri)) {
            log.warn("/callback rejected: state does not match a registered client");
            response.sendError(400, "Invalid state parameter");
            return;
        }

        // Exchange the upstream auth code using our PKCE verifier
        // demo-app uses CLIENT_SECRET_BASIC → credentials go in the Authorization header, not the body
        MultiValueMap<String, String> tokenReq = new LinkedMultiValueMap<>();
        tokenReq.add("grant_type",    "authorization_code");
        tokenReq.add("code",          code);
        tokenReq.add("redirect_uri",  props.getIssuerUri() + "/callback");
        tokenReq.add("code_verifier", upstreamVerifier);

        Map<String, Object> tokenResp;
        try {
            tokenResp = restClient.post()
                    .uri(props.getUpstreamTokenUri())
                    .header("Authorization", basicAuthHeader())
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(tokenReq)
                    .retrieve()
                    .body(new ParameterizedTypeReference<>() {});
        } catch (Exception e) {
            log.error("Token exchange with upstream failed: {}", e.getMessage());
            response.sendError(502, "Token exchange failed: " + e.getMessage());
            return;
        }

        if (tokenResp == null || tokenResp.containsKey("error")) {
            log.error("Upstream token error: {}", tokenResp != null ? tokenResp.get("error") : "null response");
            response.sendError(502, "Upstream returned error: " +
                    (tokenResp != null ? tokenResp.get("error") : "null response"));
            return;
        }

        purgeExpiredCodes();

        // Store the token under a single-use auth code for the client to pick up at /token
        String authCode = UUID.randomUUID().toString();
        Map<String, String> issued = new HashMap<>();
        issued.put("clientId",        clientId);
        issued.put("accessToken",     String.valueOf(tokenResp.get("access_token")));
        issued.put("refreshToken",    tokenResp.get("refresh_token") != null
                                        ? String.valueOf(tokenResp.get("refresh_token")) : "");
        issued.put("tokenType",       String.valueOf(tokenResp.getOrDefault("token_type", "Bearer")));
        Object exp = tokenResp.get("expires_in");
        issued.put("expiresIn",       exp instanceof Number n ? String.valueOf(n.longValue()) : "3600");
        issued.put("codeChallenge",   codeChallenge);
        issued.put("redirectUri",     redirectUri);
        issued.put("issuedAt",        String.valueOf(Instant.now().getEpochSecond()));
        issuedCodes.put(authCode, issued);

        log.info("Auth code issued for clientId={}", clientId);

        Map<String, String> params = new LinkedHashMap<>();
        params.put("code", authCode);
        params.put("state", blankToNull(clientState));
        response.sendRedirect(withQuery(redirectUri, params));
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // POST /token
    // Client presents authCode + client_id + redirect_uri + its code_verifier.
    // Every one of them must match what was recorded at /authorize; the code is burned on any failure.
    // ═══════════════════════════════════════════════════════════════════════════
    @PostMapping(value = "/token", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<Map<String, Object>> token(@RequestParam Map<String, String> params) {
        String grantType = params.get("grant_type");

        if ("refresh_token".equals(grantType)) {
            return handleRefresh(params.get("client_id"), params.get("refresh_token"));
        }
        if (!"authorization_code".equals(grantType)) {
            return err("unsupported_grant_type", "Supported: authorization_code, refresh_token");
        }

        String code         = params.get("code");
        String clientId     = params.get("client_id");
        String redirectUri  = params.get("redirect_uri");
        String codeVerifier = params.get("code_verifier");

        if (code == null)                                return err("invalid_request", "code is required");
        if (clientId == null || clientId.isBlank())      return err("invalid_request", "client_id is required");
        if (redirectUri == null || redirectUri.isBlank()) return err("invalid_request", "redirect_uri is required");
        // RFC 7636 §4.1: verifier is 43-128 characters
        if (codeVerifier == null || codeVerifier.length() < 43 || codeVerifier.length() > 128) {
            return err("invalid_request", "code_verifier is required (43-128 characters)");
        }

        Map<String, String> issued = issuedCodes.remove(code);
        if (issued == null) return err("invalid_grant", "Code invalid, already used, or expired");

        long age = Instant.now().getEpochSecond() - Long.parseLong(issued.get("issuedAt"));
        if (age > CODE_TTL_SECONDS) return err("invalid_grant", "Authorization code expired");

        if (!clientId.equals(issued.get("clientId"))) {
            return err("invalid_grant", "client_id does not match the authorization request");
        }
        if (!redirectUri.equals(issued.get("redirectUri"))) {
            return err("invalid_grant", "redirect_uri mismatch");
        }
        boolean pkceOk = MessageDigest.isEqual(
                s256(codeVerifier).getBytes(StandardCharsets.US_ASCII),
                issued.get("codeChallenge").getBytes(StandardCharsets.US_ASCII));
        if (!pkceOk) {
            log.warn("PKCE verification failed for clientId={}", clientId);
            return err("invalid_grant", "code_verifier does not match code_challenge");
        }

        log.info("PKCE ok — returning JWT to clientId={}", clientId);
        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("access_token",  issued.get("accessToken"));
        resp.put("token_type",    issued.get("tokenType"));
        resp.put("expires_in",    Long.parseLong(issued.get("expiresIn")));
        if (!issued.get("refreshToken").isBlank()) resp.put("refresh_token", issued.get("refreshToken"));
        return ResponseEntity.ok().header("Cache-Control", "no-store").body(resp);
    }

    // ── Refresh Token ──────────────────────────────────────────────────────────
    // The refresh token belongs to the upstream client (demo-app), so it cannot be bound to the
    // registering client here; at minimum the caller must present a registered client_id.
    private ResponseEntity<Map<String, Object>> handleRefresh(String clientId, String refreshToken) {
        if (clientId == null || !clients.existsById(clientId)) return err("invalid_client", "Unknown client_id");
        if (refreshToken == null) return err("invalid_request", "refresh_token required");
        // demo-app uses CLIENT_SECRET_BASIC → credentials in header
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type",    "refresh_token");
        body.add("refresh_token", refreshToken);
        try {
            Map<String, Object> r = restClient.post().uri(props.getUpstreamTokenUri())
                    .header("Authorization", basicAuthHeader())
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED).body(body)
                    .retrieve().body(new ParameterizedTypeReference<>() {});
            return ResponseEntity.ok().header("Cache-Control", "no-store").body(r);
        } catch (Exception e) {
            return err("invalid_grant", "Refresh token invalid or expired");
        }
    }

    // ── Helpers ────────────────────────────────────────────────────────────────
    private void purgeExpiredCodes() {
        long now = Instant.now().getEpochSecond();
        issuedCodes.values().removeIf(c -> now - Long.parseLong(c.get("issuedAt")) > CODE_TTL_SECONDS);
    }

    private ResponseEntity<Map<String, Object>> registrationError(String error, String desc) {
        log.warn("Registration rejected: {} — {}", error, desc);
        return ResponseEntity.badRequest().body(Map.of("error", error, "error_description", desc));
    }

    /** Client names are shown to users later (consent page) — keep them short and free of control characters. */
    private String sanitizeName(String name) {
        String cleaned = name.replaceAll("\\p{Cntrl}", "").trim();
        if (cleaned.length() > MAX_CLIENT_NAME_LENGTH) cleaned = cleaned.substring(0, MAX_CLIENT_NAME_LENGTH);
        return cleaned.isEmpty() ? null : cleaned;
    }

    private void redirectError(HttpServletResponse response, String redirectUri, String state,
                               String error, String description) throws IOException {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("error", error);
        params.put("error_description", description);
        params.put("state", blankToNull(state));
        response.sendRedirect(withQuery(redirectUri, params));
    }

    private String withQuery(String base, Map<String, String> params) {
        StringBuilder sb = new StringBuilder(base);
        char separator = base.contains("?") ? '&' : '?';
        for (Map.Entry<String, String> e : params.entrySet()) {
            if (e.getValue() == null) continue;
            sb.append(separator).append(encode(e.getKey())).append('=').append(encode(e.getValue()));
            separator = '&';
        }
        return sb.toString();
    }

    private String blankToNull(String v) { return v == null || v.isBlank() ? null : v; }

    private String generateVerifier() {
        byte[] b = new byte[32];
        new SecureRandom().nextBytes(b);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    private String s256(String verifier) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256")
                    .digest(verifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (Exception e) { throw new IllegalStateException(e); }
    }

    private String encode(String v) { return URLEncoder.encode(v, StandardCharsets.UTF_8); }

    /**
     * Builds a Basic Auth header value from the upstream client credentials.
     * Required because demo-app is registered with CLIENT_SECRET_BASIC in the upstream AS.
     */
    private String basicAuthHeader() {
        String credentials = props.getUpstreamClientId() + ":" + props.getUpstreamClientSecret();
        return "Basic " + Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
    }

    private ResponseEntity<Map<String, Object>> err(String error, String desc) {
        log.warn("OAuth error: {} — {}", error, desc);
        return ResponseEntity.badRequest().body(Map.of("error", error, "error_description", desc));
    }
}
