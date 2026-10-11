package com.pradeep.auth.controller;

import com.pradeep.auth.client.UserServiceClient;
import com.pradeep.auth.dto.UserInfo;
import com.pradeep.auth.service.FinanceHandoffCodeService;
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
import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final UserServiceClient userServiceClient;
    private final FinanceHandoffCodeService financeHandoffCodeService;

    @Value("${frontend.url:http://localhost:4200}")
    private String frontendUrl;

    @Value("${auth.allowed-return-urls:http://localhost:4200}")
    private String allowedReturnUrls;

    @Value("${finance.handoff.callback-url:http://localhost:8080/api/auth/handoff/callback}")
    private String financeCallbackUrl;

    @Value("${finance.handoff.service-key:${FINANCE_HANDOFF_SERVICE_KEY:}}")
    private String financeHandoffServiceKey;

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
     * Creates/updates the internal user before completing the authenticated session.
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

            log.info("OAuth2 callback received");

            // Create or update user via User Service Client
            boolean userCreated = userServiceClient.createOrUpdateUser(email, googleId, name, picture);
            if (!userCreated) {
                log.warn("User provisioning failed during OAuth2 callback");
                invalidateSession(request);
                response.sendRedirect(frontendUrl + "/login?error=user_provisioning_failed");
                return ResponseEntity.status(HttpStatus.FOUND).build();
            }

            log.info("User provisioning completed");

            UserInfo internalUser = userServiceClient.getUserByGoogleId(googleId);
            if (internalUser == null || internalUser.getId() == null) {
                invalidateSession(request);
                response.sendRedirect(frontendUrl + "/login?error=user_lookup_failed");
                return ResponseEntity.status(HttpStatus.FOUND).build();
            }

            // Get returnUrl from session and redirect to it, or use default frontend URL
            String redirectUrl = getReturnUrl(request);
            String handoffCode = financeHandoffCodeService.issue("user:" + internalUser.getId());
            response.sendRedirect(financeCallbackUrl + "?code=" + java.net.URLEncoder.encode(handoffCode, StandardCharsets.UTF_8)
                    + "&returnUrl=" + java.net.URLEncoder.encode(redirectUrl, StandardCharsets.UTF_8));
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
     * Logout endpoint - invalidates the server-side Redis session.
     */
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletRequest request, HttpServletResponse response) {
        log.info("Logout endpoint called");
        
        invalidateSession(request);
        response.setHeader("Clear-Site-Data", "\"cookies\"");
        log.info("Authenticated session invalidated");

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
        UserInfo userInfo = userServiceClient.getUserByEmail(email);
        if (userInfo == null) {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).build();
        }

        userInfo.setRoles(userServiceClient.getUserAuthorities(email));
        return ResponseEntity.ok(userInfo);
    }

    /** Private backend exchange; the browser never receives the internal owner identity. */
    @PostMapping("/finance/handoff/exchange")
    public ResponseEntity<java.util.Map<String, String>> exchangeFinanceHandoff(
            @RequestHeader(value = "X-Finance-Handoff-Key", required = false) String serviceKey,
            @RequestParam String code) {
        if (serviceKey == null || !java.security.MessageDigest.isEqual(serviceKey.getBytes(StandardCharsets.UTF_8), financeHandoffServiceKey.getBytes(StandardCharsets.UTF_8))) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        String ownerUserId = financeHandoffCodeService.consume(code);
        return ownerUserId == null ? ResponseEntity.status(HttpStatus.UNAUTHORIZED).build()
                : ResponseEntity.ok(java.util.Map.of("ownerUserId", ownerUserId));
    }

    private void invalidateSession(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }
    }
}
