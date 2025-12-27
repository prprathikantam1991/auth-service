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
        
        // Get user info from User Service via UserServiceClient
        UserInfo userInfo = userServiceClient.getUserByEmail(email);
        
        if (userInfo != null) {
            return ResponseEntity.ok(userInfo);
        }

        // If user not in User Service, return info from OIDC token
        userInfo = new UserInfo(
                null,
                oidcUser.getEmail(),
                oidcUser.getFullName(),
                oidcUser.getPicture(),
                oidcUser.getSubject()
        );
        return ResponseEntity.ok(userInfo);
    }
}

