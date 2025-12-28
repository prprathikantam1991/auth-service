package com.pradeep.auth.controller;

import com.pradeep.auth.client.UserServiceClient;
import com.pradeep.auth.config.CookieConfig;
import com.pradeep.auth.dto.UserInfo;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final CookieConfig cookieConfig;
    private final UserServiceClient userServiceClient;

    @Value("${frontend.url:http://localhost:4200}")
    private String frontendUrl;

    /**
     * Initiates OAuth2 login flow - redirects to Google
     */
    @GetMapping("/login")
    public void login(HttpServletResponse response) throws IOException {
        log.info("Login endpoint called - redirecting to OAuth2 login");
        // Spring Security OAuth2 will handle the redirect
        response.sendRedirect("/oauth2/authorization/google");
    }

    /**
     * Handles successful OAuth2 authentication
     * Spring Security processes the OAuth2 callback at /login/oauth2/code/google first,
     * then redirects here after successful authentication
     * Creates/updates user and sets JWT in HttpOnly cookie
     */
    @GetMapping("/success")
    public ResponseEntity<Void> handleSuccess(
            @AuthenticationPrincipal OidcUser oidcUser,
            HttpServletResponse response) throws IOException {
        
        if (oidcUser == null) {
            log.error("OAuth2 callback received but user is null");
            response.sendRedirect(frontendUrl + "/login?error=authentication_failed");
            return ResponseEntity.status(HttpStatus.FOUND).build();
        }

        try {
            // Extract user information from OIDC user
            String email = oidcUser.getEmail();
            String googleId = oidcUser.getSubject(); // "sub" claim
            String name = oidcUser.getFullName();
            String picture = oidcUser.getPicture();

            log.info("OAuth2 callback successful for user: {}", email);

            // Create or update user via User Service Client
            boolean userCreated = userServiceClient.createOrUpdateUser(email, googleId, name, picture);
            if (!userCreated) {
                log.warn("Failed to create/update user in User Service: {}", email);
                // Continue with authentication even if user creation fails
                // The user can still authenticate, but may need to retry
            }

            // Get ID token (JWT) from OIDC user
            String idToken = oidcUser.getIdToken().getTokenValue();

            // Create HttpOnly cookie with JWT
            Cookie cookie = cookieConfig.createTokenCookie(idToken);

            // Set SameSite attribute via response header
            String sameSite = cookieConfig.getSameSite();
            String cookieHeader = String.format("%s=%s; Path=/; HttpOnly; Max-Age=%d; SameSite=%s",
                    cookieConfig.getCookieName(),
                    idToken,
                    cookie.getMaxAge(),
                    sameSite.substring(0, 1).toUpperCase() + sameSite.substring(1));

            if (cookieConfig.createTokenCookie("").getSecure()) {
                cookieHeader += "; Secure";
            }

            if (cookie.getDomain() != null && !cookie.getDomain().isEmpty()) {
                cookieHeader += "; Domain=" + cookie.getDomain();
            }

            response.setHeader("Set-Cookie", cookieHeader);

            log.info("User authenticated and cookie set for: {}", email);

            // Redirect to frontend
            response.sendRedirect(frontendUrl + "/dashboard");
            return ResponseEntity.status(HttpStatus.FOUND).build();

        } catch (Exception e) {
            log.error("Error processing OAuth2 callback", e);
            response.sendRedirect(frontendUrl + "/login?error=processing_failed");
            return ResponseEntity.status(HttpStatus.FOUND).build();
        }
    }

    /**
     * Logout endpoint - clears the cookie
     */
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletResponse response) {
        log.info("Logout endpoint called");

        // Clear cookie by setting it with max-age=0
        String cookieHeader = String.format("%s=; Path=/; HttpOnly; Max-Age=0; SameSite=%s",
                cookieConfig.getCookieName(),
                cookieConfig.getSameSite().substring(0, 1).toUpperCase() + 
                cookieConfig.getSameSite().substring(1));

        if (cookieConfig.createTokenCookie("").getSecure()) {
            cookieHeader += "; Secure";
        }

        response.setHeader("Set-Cookie", cookieHeader);

        return ResponseEntity.ok().build();
    }

    /**
     * Get current user info (optional endpoint)
     */
    @GetMapping("/user")
    public ResponseEntity<UserInfo> getCurrentUser(@AuthenticationPrincipal OidcUser oidcUser) {
        if (oidcUser == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        String email = oidcUser.getEmail();
        String googleId = oidcUser.getSubject();
        
        // #region agent log
        try {
            java.nio.file.Files.write(java.nio.file.Paths.get("w:\\projects\\angular\\ems-ui\\.cursor\\debug.log"), 
                (String.format("{\"sessionId\":\"debug-session\",\"runId\":\"run1\",\"hypothesisId\":\"A\",\"location\":\"AuthController.java:145\",\"message\":\"Getting user info\",\"data\":{\"email\":\"%s\",\"googleId\":\"%s\"},\"timestamp\":%d}\n", 
                    email != null ? email : "null", googleId != null ? googleId : "null", System.currentTimeMillis())).getBytes(), 
                java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND);
        } catch (Exception e) {}
        // #endregion
        
        // Get user info from User Service via UserServiceClient
        UserInfo userInfo = userServiceClient.getUserByEmail(email);
        
        // #region agent log
        try {
            java.nio.file.Files.write(java.nio.file.Paths.get("w:\\projects\\angular\\ems-ui\\.cursor\\debug.log"), 
                (String.format("{\"sessionId\":\"debug-session\",\"runId\":\"run1\",\"hypothesisId\":\"B\",\"location\":\"AuthController.java:152\",\"message\":\"UserInfo retrieved\",\"data\":{\"userInfo\":%s,\"hasRoles\":%s},\"timestamp\":%d}\n", 
                    userInfo != null ? "not_null" : "null", 
                    userInfo != null && userInfo.getRoles() != null ? String.valueOf(userInfo.getRoles().size()) : "0", 
                    System.currentTimeMillis())).getBytes(), 
                java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND);
        } catch (Exception e) {}
        // #endregion
        
        // Get user roles/authorities from User Service
        List<String> roles = new ArrayList<>();
        if (email != null && !email.isEmpty()) {
            roles = userServiceClient.getUserAuthorities(email);
            
            // #region agent log
            try {
                java.nio.file.Files.write(java.nio.file.Paths.get("w:\\projects\\angular\\ems-ui\\.cursor\\debug.log"), 
                    (String.format("{\"sessionId\":\"debug-session\",\"runId\":\"run1\",\"hypothesisId\":\"C\",\"location\":\"AuthController.java:159\",\"message\":\"Roles from email lookup\",\"data\":{\"rolesCount\":%d,\"roles\":%s},\"timestamp\":%d}\n", 
                        roles.size(), roles.toString(), System.currentTimeMillis())).getBytes(), 
                    java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND);
            } catch (Exception e) {}
            // #endregion
        }
        
        // If no roles found by email, try Google ID as fallback
        if (roles.isEmpty() && googleId != null && !googleId.isEmpty()) {
            roles = userServiceClient.getUserAuthoritiesByGoogleId(googleId);
            
            // #region agent log
            try {
                java.nio.file.Files.write(java.nio.file.Paths.get("w:\\projects\\angular\\ems-ui\\.cursor\\debug.log"), 
                    (String.format("{\"sessionId\":\"debug-session\",\"runId\":\"run1\",\"hypothesisId\":\"D\",\"location\":\"AuthController.java:167\",\"message\":\"Roles from Google ID lookup\",\"data\":{\"rolesCount\":%d,\"roles\":%s},\"timestamp\":%d}\n", 
                        roles.size(), roles.toString(), System.currentTimeMillis())).getBytes(), 
                    java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND);
            } catch (Exception e) {}
            // #endregion
        }
        
        if (userInfo != null) {
            // Update roles in existing userInfo
            userInfo.setRoles(roles);
            
            // #region agent log
            try {
                java.nio.file.Files.write(java.nio.file.Paths.get("w:\\projects\\angular\\ems-ui\\.cursor\\debug.log"), 
                    (String.format("{\"sessionId\":\"debug-session\",\"runId\":\"run1\",\"hypothesisId\":\"E\",\"location\":\"AuthController.java:175\",\"message\":\"Final UserInfo with roles\",\"data\":{\"rolesCount\":%d,\"roles\":%s},\"timestamp\":%d}\n", 
                        roles.size(), roles.toString(), System.currentTimeMillis())).getBytes(), 
                    java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND);
            } catch (Exception e) {}
            // #endregion
            
            return ResponseEntity.ok(userInfo);
        }

        // If user not in User Service, return info from OIDC token with roles
        userInfo = new UserInfo(
                null,
                oidcUser.getEmail(),
                oidcUser.getFullName(),
                oidcUser.getPicture(),
                oidcUser.getSubject(),
                roles
        );
        return ResponseEntity.ok(userInfo);
    }
}

