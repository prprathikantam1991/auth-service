package com.pradeep.auth.controller;

import com.pradeep.auth.client.UserServiceClient;
import com.pradeep.auth.config.CookieConfig;
import com.pradeep.auth.dto.UserInfo;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
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

    @Value("${auth.allowed-return-urls:http://localhost:4200}")
    private String allowedReturnUrls;

    /**
     * Initiates OAuth2 login flow - redirects to Google
     * Accepts returnUrl parameter to redirect back to originating app after login
     */
    @GetMapping("/login")
    public void login(
            @RequestParam(value = "returnUrl", required = false) String returnUrl,
            HttpServletRequest request,
            HttpServletResponse response) throws IOException {
        log.info("Login endpoint called - returnUrl: {}", returnUrl);
        
        // Store returnUrl in session if provided and valid
        if (returnUrl != null && !returnUrl.isEmpty()) {
            if (isValidReturnUrl(returnUrl)) {
                HttpSession session = request.getSession();
                session.setAttribute("returnUrl", returnUrl);
                log.info("Stored returnUrl in session: {}", returnUrl);
            } else {
                log.warn("Invalid returnUrl provided, ignoring: {}", returnUrl);
            }
        }
        
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
            HttpServletRequest request,
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

            // Get returnUrl from session and redirect to it, or use default frontend URL
            String redirectUrl = getReturnUrl(request);
            log.info("Redirecting to: {}", redirectUrl);
            response.sendRedirect(redirectUrl);
            return ResponseEntity.status(HttpStatus.FOUND).build();

        } catch (Exception e) {
            log.error("Error processing OAuth2 callback", e);
            response.sendRedirect(frontendUrl + "/login?error=processing_failed");
            return ResponseEntity.status(HttpStatus.FOUND).build();
        }
    }

    /**
     * Retrieves returnUrl from session and validates it
     * Returns validated returnUrl or default frontend URL
     */
    private String getReturnUrl(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            String returnUrl = (String) session.getAttribute("returnUrl");
            if (returnUrl != null && !returnUrl.isEmpty()) {
                // Remove from session after use
                session.removeAttribute("returnUrl");
                
                // Validate returnUrl before using it
                if (isValidReturnUrl(returnUrl)) {
                    log.info("Using returnUrl from session: {}", returnUrl);
                    return returnUrl;
                } else {
                    log.warn("Invalid returnUrl in session, using default: {}", returnUrl);
                }
            }
        }
        
        // Default to frontend URL with /dashboard
        return frontendUrl + "/dashboard";
    }

    /**
     * Validates returnUrl against whitelist to prevent open redirect attacks
     * Only allows localhost URLs matching pattern: http://localhost:PORT or http://127.0.0.1:PORT
     */
    private boolean isValidReturnUrl(String returnUrl) {
        if (returnUrl == null || returnUrl.isEmpty()) {
            return false;
        }

        try {
            // Decode URL-encoded returnUrl
            String decodedUrl = URLDecoder.decode(returnUrl, StandardCharsets.UTF_8);
            
            // Check if URL matches localhost pattern
            if (!decodedUrl.startsWith("http://localhost:") && 
                !decodedUrl.startsWith("http://127.0.0.1:")) {
                log.warn("ReturnUrl does not match localhost pattern: {}", decodedUrl);
                return false;
            }

            // Check against whitelist
            List<String> allowedUrls = Arrays.asList(allowedReturnUrls.split(","));
            for (String allowedUrl : allowedUrls) {
                String trimmedAllowed = allowedUrl.trim();
                // Check if returnUrl starts with any allowed URL
                if (decodedUrl.startsWith(trimmedAllowed)) {
                    log.debug("ReturnUrl validated against whitelist: {}", decodedUrl);
                    return true;
                }
            }

            log.warn("ReturnUrl not in whitelist: {}", decodedUrl);
            return false;

        } catch (Exception e) {
            log.error("Error validating returnUrl: {}", returnUrl, e);
            return false;
        }
    }

    /**
     * Logout endpoint - invalidates session and clears the cookie
     */
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletRequest request, HttpServletResponse response) {
        log.info("Logout endpoint called");
        
        // Invalidate session to remove from Redis
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
            log.info("Session invalidated and removed from Redis");
        }

        // Clear cookie by setting it with max-age=0
        // Must match the same attributes (domain, path, secure) used when setting it
        String cookieHeader = String.format("%s=; Path=/; HttpOnly; Max-Age=0; SameSite=%s",
                cookieConfig.getCookieName(),
                cookieConfig.getSameSite().substring(0, 1).toUpperCase() + 
                cookieConfig.getSameSite().substring(1));

        if (cookieConfig.createTokenCookie("").getSecure()) {
            cookieHeader += "; Secure";
        }

        // If domain was set when creating the cookie, it must be set when clearing it
        Cookie tempCookie = cookieConfig.createTokenCookie("");
        if (tempCookie.getDomain() != null && !tempCookie.getDomain().isEmpty()) {
            cookieHeader += "; Domain=" + tempCookie.getDomain();
        }

        response.setHeader("Set-Cookie", cookieHeader);
        log.info("Cookie cleared: {}", cookieConfig.getCookieName());

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

