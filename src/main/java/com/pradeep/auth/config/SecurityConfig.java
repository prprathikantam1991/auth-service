package com.pradeep.auth.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable()) // Disable CSRF for API endpoints
            .cors(cors -> {}) // Enable CORS (uses CorsConfig bean)
            .authorizeHttpRequests(auth -> auth
                // Allow CORS preflight requests
                .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                
                // Public endpoints
                .requestMatchers("/actuator/health", "/actuator/info").permitAll()
                
                // Auth login endpoint - permit all
                .requestMatchers("/auth/login").permitAll()
                
                // Auth success endpoint - requires authentication (OAuth2 user will be available)
                .requestMatchers("/auth/success").authenticated()
                
                // Auth logout and user endpoints - permit all (handled by controller)
                .requestMatchers("/auth/logout", "/auth/user").permitAll()
                
                // OAuth2 callback endpoint (Spring Security default) - permit all
                .requestMatchers("/login/oauth2/code/**").permitAll()
                
                // All other requests require authentication
                .anyRequest().authenticated()
            )
            .oauth2Login(oauth2 -> oauth2
                .loginPage("/auth/login")
                .defaultSuccessUrl("/auth/success", true)
                .failureUrl("/auth/login?error=true")
            );

        return http.build();
    }
}

