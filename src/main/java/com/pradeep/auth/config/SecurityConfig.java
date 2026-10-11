package com.pradeep.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import lombok.extern.slf4j.Slf4j;

@Configuration
@EnableWebSecurity
@Slf4j
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf
                // This is a private service-to-service exchange, authenticated with
                // X-Finance-Handoff-Key rather than a browser cookie/session.
                .ignoringRequestMatchers("/auth/finance/handoff/exchange")
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
            )
            .cors(cors -> {}) // Enable CORS (uses CorsConfig bean)
            .authorizeHttpRequests(auth -> auth
                // Allow CORS preflight requests
                .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                
                // Public endpoints
                .requestMatchers("/actuator/health", "/actuator/info").permitAll()
                
                // Auth login endpoint - permit all
                .requestMatchers("/auth/login", "/auth/finance/handoff/exchange").permitAll()
                
                // Auth success endpoint - requires authentication (OAuth2 user will be available)
                .requestMatchers("/auth/success").authenticated()
                
                // Session-aware endpoints require an authenticated browser session.
                .requestMatchers("/auth/logout", "/auth/user").authenticated()
                
                // OAuth2 callback endpoint (Spring Security default) - permit all
                .requestMatchers("/login/oauth2/code/**").permitAll()
                
                // All other requests require authentication
                .anyRequest().authenticated()
            )
            .oauth2Login(oauth2 -> oauth2
                .loginPage("/auth/login")
                .defaultSuccessUrl("/auth/success", true)
                .failureHandler((request, response, exception) -> {
                    // Safe diagnostics only: never log authorization codes, tokens, or cookies.
                    log.warn("Google OAuth sign-in failed: {}", exception.getMessage());
                    response.sendRedirect("/auth/login?error=true");
                })
            );

        return http.build();
    }
}
