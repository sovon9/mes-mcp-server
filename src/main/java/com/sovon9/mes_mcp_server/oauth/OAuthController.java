package com.sovon9.mes_mcp_server.oauth;

import com.sovon9.mes_mcp_server.config.OAuthProperties;
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
 * Minimal OAuth 2.0 PKCE proxy — no pending-flow map, no model classes.
 *
 * <h2>Trick: state = Base64(JSON payload)</h2>
 * Instead of storing a pending-flow in memory between /authorize and /callback,
 * we encode all required data (Claude's redirect_uri, code_challenge, original state,
 * and our own upstream PKCE verifier) as a Base64-encoded JSON blob in the {@code state}
 * parameter sent to the upstream AS. The upstream AS echoes it back unchanged in /callback,
 * so we decode it there — zero server-side state needed for this leg of the flow.
 *
 * <p>The only in-memory store is a small {@code issuedCodes} map between /callback and /token,
 * holding the upstream JWT until Claude Code presents its code_verifier.
 */
@RestController
public class OAuthController {

    private static final Logger log = LoggerFactory.getLogger(OAuthController.class);

    private final OAuthProperties props;
    private final RestClient restClient;

    // Single-use codes issued at /callback, consumed at /token (5-min TTL enforced inline)
    private final Map<String, Map<String, String>> issuedCodes = new ConcurrentHashMap<>();

    public OAuthController(OAuthProperties props) {
        this.props      = props;
        this.restClient = RestClient.builder().build();
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // POST /register  — RFC 7591 Dynamic Client Registration
    // Claude Code calls this on first connect. Just echo back a client_id.
    // No storage needed — client_id is validated implicitly via PKCE at /token.
    // ═══════════════════════════════════════════════════════════════════════════
    @PostMapping("/register")
    public ResponseEntity<Map<String, Object>> register(@RequestBody Map<String, Object> body) {
        String clientId = UUID.randomUUID().toString();
        log.info("Client registered dynamically: clientId={}", clientId);

        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("client_id",                 clientId);
        resp.put("client_id_issued_at",        Instant.now().getEpochSecond());
        resp.put("redirect_uris",              body.getOrDefault("redirect_uris",  List.of()));
        resp.put("grant_types",                body.getOrDefault("grant_types",    List.of("authorization_code")));
        resp.put("response_types",             body.getOrDefault("response_types", List.of("code")));
        resp.put("token_endpoint_auth_method", "none");
        return ResponseEntity.status(201).body(resp);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // GET /authorize
    //
    // 1. Generate our own PKCE pair for the upstream AS (it requires PKCE).
    // 2. Pack everything we need at /callback into the state param as Base64 JSON.
    //    The upstream AS echoes state back unchanged — no server memory needed.
    // 3. Build login URL using the fixed client_id from application.properties.
    // 4. Redirect browser to upstream AS login page.
    // ═══════════════════════════════════════════════════════════════════════════
    @GetMapping("/authorize")
    public void authorize(
            @RequestParam("redirect_uri")                          String redirectUri,
            @RequestParam(value = "state",                required = false) String state,
            @RequestParam(value = "code_challenge",       required = false) String codeChallenge,
            @RequestParam(value = "code_challenge_method",required = false) String codeChallengeMethod,
            @RequestParam                                          Map<String, String> allParams,
            HttpServletResponse response) throws IOException {

        // Generate this server's own PKCE verifier/challenge for the upstream AS call
        String upstreamVerifier  = generateVerifier();
        String upstreamChallenge = s256(upstreamVerifier);

        // Encode everything into the state so /callback can reconstruct it without any map
        // Format: key=value pairs joined by "&", then Base64-URL encoded
        String rawState = "redirectUri="  + encode(redirectUri)
                + "&clientState="        + encode(state != null ? state : "")
                + "&codeChallenge="      + encode(codeChallenge != null ? codeChallenge : "")
                + "&challengeMethod="    + encode(codeChallengeMethod != null ? codeChallengeMethod : "S256")
                + "&upstreamVerifier="   + encode(upstreamVerifier);
        String encodedState = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(rawState.getBytes(StandardCharsets.UTF_8));

        // Build the upstream AS login URL using the fixed client_id from application.properties
        String loginUrl = props.getUpstreamAuthorizationUri()
                + "?response_type=code"
                + "&client_id="             + encode(props.getUpstreamClientId())
                + "&redirect_uri="          + encode(props.getIssuerUri() + "/callback")
                + "&state="                 + encode(encodedState)
                + "&scope=openid"
                + "&code_challenge="        + encode(upstreamChallenge)
                + "&code_challenge_method=S256";

        log.info("Redirecting to upstream AS login: {}", loginUrl);
        response.sendRedirect(loginUrl);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // GET /callback
    //
    // Upstream AS lands here after user login.
    // Decode the state blob → exchange code for tokens → issue a local code to Claude.
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

        // Decode the state blob we packed in /authorize (key=value pairs, Base64-URL encoded)
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

        String redirectUri       = statePayload.get("redirectUri");
        String clientState       = statePayload.get("clientState");
        String codeChallenge     = statePayload.get("codeChallenge");
        String challengeMethod   = statePayload.get("challengeMethod");
        String upstreamVerifier  = statePayload.get("upstreamVerifier");

        // Exchange the upstream auth code using our PKCE verifier (Pair B)
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
            log.error("Upstream token error response: {}", tokenResp);
            response.sendError(502, "Upstream returned error: " +
                    (tokenResp != null ? tokenResp.get("error") : "null response"));
            return;
        }

        // Store the token under a single-use auth code for Claude to pick up at /token
        String authCode = UUID.randomUUID().toString();
        Map<String, String> issued = new HashMap<>();
        issued.put("accessToken",     String.valueOf(tokenResp.get("access_token")));
        issued.put("refreshToken",    tokenResp.get("refresh_token") != null
                                        ? String.valueOf(tokenResp.get("refresh_token")) : "");
        issued.put("tokenType",       String.valueOf(tokenResp.getOrDefault("token_type", "Bearer")));
        Object exp = tokenResp.get("expires_in");
        issued.put("expiresIn",       exp instanceof Number n ? String.valueOf(n.longValue()) : "3600");
        issued.put("codeChallenge",   codeChallenge != null ? codeChallenge : "");
        issued.put("challengeMethod", challengeMethod != null ? challengeMethod : "S256");
        issued.put("redirectUri",     redirectUri);
        issued.put("issuedAt",        String.valueOf(Instant.now().getEpochSecond()));
        issuedCodes.put(authCode, issued);

        log.info("Auth code issued: {}", authCode);

        // Redirect back to Claude Code with the auth code
        String claudeCallback = redirectUri
                + "?code=" + encode(authCode)
                + (clientState != null ? "&state=" + encode(clientState) : "");

        log.info("Redirecting to Claude: {}", claudeCallback);
        response.sendRedirect(claudeCallback);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // POST /token
    // Claude Code presents authCode + its code_verifier (Pair A).
    // Verify PKCE, return the upstream JWT.
    // ═══════════════════════════════════════════════════════════════════════════
    @PostMapping(value = "/token", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<Map<String, Object>> token(@RequestParam Map<String, String> params) {
        String grantType = params.get("grant_type");

        if ("refresh_token".equals(grantType)) {
            return handleRefresh(params.get("refresh_token"));
        }
        if (!"authorization_code".equals(grantType)) {
            return err("unsupported_grant_type", "Supported: authorization_code, refresh_token");
        }

        String code         = params.get("code");
        String redirectUri  = params.get("redirect_uri");
        String codeVerifier = params.get("code_verifier");

        if (code == null) return err("invalid_request", "code is required");

        Map<String, String> issued = issuedCodes.remove(code);
        if (issued == null) return err("invalid_grant", "Code invalid, already used, or expired");

        // Enforce 5-minute TTL
        long age = Instant.now().getEpochSecond() - Long.parseLong(issued.get("issuedAt"));
        if (age > 300) return err("invalid_grant", "Authorization code expired");

        // Verify redirect_uri
        if (redirectUri != null && !redirectUri.equals(issued.get("redirectUri"))) {
            return err("invalid_grant", "redirect_uri mismatch");
        }

        // Verify Claude's PKCE (Pair A)
        String challenge = issued.get("codeChallenge");
        if (challenge != null && !challenge.isBlank()) {
            if (codeVerifier == null || codeVerifier.isBlank()) {
                return err("invalid_request", "code_verifier required");
            }
            String method = issued.getOrDefault("challengeMethod", "S256");
            boolean valid = "plain".equalsIgnoreCase(method)
                    ? codeVerifier.equals(challenge)
                    : s256(codeVerifier).equals(challenge);
            if (!valid) {
                log.warn("PKCE verification failed");
                return err("invalid_grant", "code_verifier does not match code_challenge");
            }
        }

        log.info("PKCE ok — returning JWT to Claude");
        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("access_token",  issued.get("accessToken"));
        resp.put("token_type",    issued.get("tokenType"));
        resp.put("expires_in",    Long.parseLong(issued.get("expiresIn")));
        if (!issued.get("refreshToken").isBlank()) resp.put("refresh_token", issued.get("refreshToken"));
        return ResponseEntity.ok(resp);
    }

    // ── Refresh Token ──────────────────────────────────────────────────────────
    private ResponseEntity<Map<String, Object>> handleRefresh(String refreshToken) {
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
            return ResponseEntity.ok(r);
        } catch (Exception e) {
            return err("invalid_grant", "Refresh token invalid or expired");
        }
    }

    // ── Helpers ────────────────────────────────────────────────────────────────
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
