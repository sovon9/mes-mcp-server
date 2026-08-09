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

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http)
    {
        http.authorizeHttpRequests(req->req.anyRequest().permitAll())
        .csrf(csrf->csrf.disable());
        return http.build();
    }

//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception
//    {
//        http.authorizeHttpRequests(req->
//                       req.requestMatchers(HttpMethod.GET, "/health").permitAll()
//                               .anyRequest().authenticated())
//                .oauth2ResourceServer(oauth->oauth.jwt(Customizer.withDefaults()))
//                .csrf(csrf->csrf.disable())
//                .exceptionHandling(config -> config
//                        .authenticationEntryPoint((request, response, authException) ->
//                                response.sendError(HttpStatus.UNAUTHORIZED.value(), authException.getMessage())));
//
//        return http.build();
//    }


}
