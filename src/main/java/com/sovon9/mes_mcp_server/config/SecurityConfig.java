package com.sovon9.mes_mcp_server.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http)
//    {
//        http.authorizeHttpRequests(req->req.anyRequest().permitAll())
//        .csrf(csrf->csrf.disable());
//        return http.build();
//    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception
    {
        http.authorizeHttpRequests(req -> req
                        // ── Public: health check ──────────────────────────────────────────────
                        .requestMatchers(HttpMethod.GET, "/health").permitAll()

                        // ── Public: OAuth discovery (RFC 8414 / RFC 9728) ─────────────────────
                        // Claude Code fetches these to auto-discover /authorize, /token, /register
                        .requestMatchers("/.well-known/oauth-authorization-server").permitAll()
                        .requestMatchers("/.well-known/oauth-protected-resource").permitAll()

                        // ── Public: Dynamic Client Registration (RFC 7591) ────────────────────
                        // Claude Code self-registers here before starting the auth flow
                        .requestMatchers(HttpMethod.POST, "/register").permitAll()

                        // ── Public: PKCE Authorization Flow ──────────────────────────────────
                        // /authorize  — receives PKCE params, redirects browser to upstream AS
                        // /callback   — upstream AS redirects back here with auth code
                        // /token      — Claude Code exchanges code + code_verifier for JWT
                        .requestMatchers(HttpMethod.GET,  "/authorize").permitAll()
                        .requestMatchers(HttpMethod.GET,  "/callback").permitAll()
                        .requestMatchers(HttpMethod.POST, "/token").permitAll()

                        // ── Protected: everything else requires a valid JWT ───────────────────
                        // The JWT is issued by localhost:9000 and validated via the resource server
                        .anyRequest().authenticated())

                .oauth2ResourceServer(oauth -> oauth.jwt(Customizer.withDefaults()))
                .csrf(csrf -> csrf.disable())
                .exceptionHandling(config -> config
                        .authenticationEntryPoint((request, response, authException) ->
                                response.sendError(HttpStatus.UNAUTHORIZED.value(), authException.getMessage())));

        return http.build();
    }


}
