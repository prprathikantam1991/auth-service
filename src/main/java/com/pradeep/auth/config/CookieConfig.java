package com.pradeep.auth.config;

import jakarta.servlet.http.Cookie;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

@Configuration
public class CookieConfig {

    @Value("${auth.cookie.name:id_token}")
    private String cookieName;

    @Value("${auth.cookie.domain:}")
    private String cookieDomain;

    @Value("${auth.cookie.secure:false}")
    private boolean secure;

    @Value("${auth.cookie.same-site:strict}")
    private String sameSite;

    @Value("${auth.cookie.max-age:3600}")
    private int maxAge;

    public Cookie createTokenCookie(String token) {
        Cookie cookie = new Cookie(cookieName, token);
        cookie.setHttpOnly(true); // JavaScript cannot access
        cookie.setSecure(secure); // Only HTTPS in production
        cookie.setPath("/");
        cookie.setMaxAge(maxAge); // 1 hour default
        
        // Set domain if configured (for cross-subdomain cookies)
        if (cookieDomain != null && !cookieDomain.isEmpty()) {
            cookie.setDomain(cookieDomain);
        }
        
        // Note: SameSite is set via response header, not cookie attribute
        // This will be handled in the controller
        
        return cookie;
    }

    public String getCookieName() {
        return cookieName;
    }

    public String getSameSite() {
        return sameSite;
    }
}

