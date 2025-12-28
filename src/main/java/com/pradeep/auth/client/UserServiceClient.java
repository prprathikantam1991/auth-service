package com.pradeep.auth.client;

import com.pradeep.auth.dto.UserInfo;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Client service for interacting with User Service REST API
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class UserServiceClient {

    private final RestTemplate restTemplate;

    @Value("${user.service.url:http://localhost:8082}")
    private String userServiceUrl;

    /**
     * Create or update user in User Service (idempotent operation)
     * @param email User email
     * @param googleId User Google ID
     * @param name User name
     * @param picture User picture URL
     * @return true if successful, false otherwise
     */
    public boolean createOrUpdateUser(String email, String googleId, String name, String picture) {
        if (email == null || email.isEmpty() || googleId == null || googleId.isEmpty()) {
            log.warn("Email or Google ID is null or empty, cannot create/update user");
            return false;
        }

        try {
            Map<String, String> userRequest = new HashMap<>();
            userRequest.put("email", email);
            userRequest.put("googleId", googleId);
            userRequest.put("name", name);
            userRequest.put("picture", picture);

            String url = userServiceUrl + "/api/users/create-or-update";
            ResponseEntity<Map<String, Object>> response = restTemplate.exchange(
                    url,
                    HttpMethod.POST,
                    new org.springframework.http.HttpEntity<>(userRequest),
                    new ParameterizedTypeReference<Map<String, Object>>() {}
            );

            if (response.getStatusCode().is2xxSuccessful()) {
                log.info("User created/updated in User Service: {}", email);
                return true;
            } else {
                log.warn("Failed to create/update user in User Service: {} - Status: {}", email, response.getStatusCode());
                return false;
            }
        } catch (RestClientException e) {
            log.error("Error calling User Service to create/update user: {}", email, e);
            return false;
        } catch (Exception e) {
            log.error("Unexpected error creating/updating user in User Service: {}", email, e);
            return false;
        }
    }

    /**
     * Get user by email from User Service
     * @param email User email
     * @return UserInfo if found, null otherwise
     */
    public UserInfo getUserByEmail(String email) {
        if (email == null || email.isEmpty()) {
            log.warn("Email is null or empty, cannot fetch user");
            return null;
        }

        try {
            String url = userServiceUrl + "/api/users/{email}";
            ResponseEntity<Map<String, Object>> response = restTemplate.exchange(
                    url,
                    HttpMethod.GET,
                    null,
                    new ParameterizedTypeReference<Map<String, Object>>() {},
                    email
            );

            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                Map<String, Object> userData = response.getBody();
                return mapToUserInfo(userData);
            } else if (response.getStatusCode() == HttpStatus.NOT_FOUND) {
                log.debug("User not found in User Service: {}", email);
                return null;
            }
        } catch (RestClientException e) {
            log.warn("Failed to get user from User Service: {}", email, e);
        } catch (Exception e) {
            log.error("Unexpected error getting user from User Service: {}", email, e);
        }

        return null;
    }

    /**
     * Get user by Google ID from User Service
     * @param googleId User Google ID
     * @return UserInfo if found, null otherwise
     */
    public UserInfo getUserByGoogleId(String googleId) {
        if (googleId == null || googleId.isEmpty()) {
            log.warn("Google ID is null or empty, cannot fetch user");
            return null;
        }

        try {
            String url = userServiceUrl + "/api/users/google/{googleId}";
            ResponseEntity<Map<String, Object>> response = restTemplate.exchange(
                    url,
                    HttpMethod.GET,
                    null,
                    new ParameterizedTypeReference<Map<String, Object>>() {},
                    googleId
            );

            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                Map<String, Object> userData = response.getBody();
                return mapToUserInfo(userData);
            } else if (response.getStatusCode() == HttpStatus.NOT_FOUND) {
                log.debug("User not found in User Service by Google ID: {}", googleId);
                return null;
            }
        } catch (RestClientException e) {
            log.warn("Failed to get user from User Service by Google ID: {}", googleId, e);
        } catch (Exception e) {
            log.error("Unexpected error getting user from User Service by Google ID: {}", googleId, e);
        }

        return null;
    }

    /**
     * Get user authorities (roles) by email from User Service
     * @param email User email
     * @return List of role strings (e.g., ["ROLE_HR", "ROLE_ADMIN"]), empty list if not found or error
     */
    public List<String> getUserAuthorities(String email) {
        if (email == null || email.isEmpty()) {
            log.warn("Email is null or empty, cannot fetch authorities");
            return new ArrayList<>();
        }

        try {
            String url = userServiceUrl + "/api/users/{email}/authorities";
            
            // #region agent log
            try {
                java.nio.file.Files.write(java.nio.file.Paths.get("w:\\projects\\angular\\ems-ui\\.cursor\\debug.log"), 
                    (String.format("{\"sessionId\":\"debug-session\",\"runId\":\"run1\",\"hypothesisId\":\"F\",\"location\":\"UserServiceClient.java:167\",\"message\":\"Calling User Service authorities endpoint\",\"data\":{\"url\":\"%s\",\"email\":\"%s\"},\"timestamp\":%d}\n", 
                        url, email, System.currentTimeMillis())).getBytes(), 
                    java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND);
            } catch (Exception e) {}
            // #endregion
            
            // User Service returns AuthoritiesResponse wrapper: { "authorities": ["ROLE_HR", ...] }
            ResponseEntity<Map<String, Object>> response = restTemplate.exchange(
                    url,
                    HttpMethod.GET,
                    null,
                    new ParameterizedTypeReference<Map<String, Object>>() {},
                    email
            );

            // #region agent log
            try {
                java.nio.file.Files.write(java.nio.file.Paths.get("w:\\projects\\angular\\ems-ui\\.cursor\\debug.log"), 
                    (String.format("{\"sessionId\":\"debug-session\",\"runId\":\"run1\",\"hypothesisId\":\"G\",\"location\":\"UserServiceClient.java:178\",\"message\":\"User Service response\",\"data\":{\"status\":\"%s\",\"hasBody\":%s,\"body\":%s},\"timestamp\":%d}\n", 
                        response.getStatusCode().toString(), 
                        response.getBody() != null ? "true" : "false",
                        response.getBody() != null ? response.getBody().toString() : "null",
                        System.currentTimeMillis())).getBytes(), 
                    java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND);
            } catch (Exception e) {}
            // #endregion

            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                Map<String, Object> responseBody = response.getBody();
                // Extract authorities from the response wrapper
                Object authoritiesObj = responseBody.get("authorities");
                List<String> authorities = new ArrayList<>();
                
                if (authoritiesObj instanceof List) {
                    @SuppressWarnings("unchecked")
                    List<Object> authoritiesList = (List<Object>) authoritiesObj;
                    authorities = authoritiesList.stream()
                            .map(auth -> auth.toString())
                            .collect(Collectors.toList());
                }
                
                // #region agent log
                try {
                    java.nio.file.Files.write(java.nio.file.Paths.get("w:\\projects\\angular\\ems-ui\\.cursor\\debug.log"), 
                        (String.format("{\"sessionId\":\"debug-session\",\"runId\":\"run1\",\"hypothesisId\":\"J\",\"location\":\"UserServiceClient.java:195\",\"message\":\"Extracted authorities\",\"data\":{\"authoritiesCount\":%d,\"authorities\":%s},\"timestamp\":%d}\n", 
                            authorities.size(), authorities.toString(), System.currentTimeMillis())).getBytes(), 
                        java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND);
                } catch (Exception e) {}
                // #endregion
                
                log.debug("Retrieved {} authorities for user: {}", authorities.size(), email);
                return authorities;
            } else if (response.getStatusCode() == HttpStatus.NOT_FOUND) {
                log.debug("User not found in User Service: {}", email);
                return new ArrayList<>();
            }
        } catch (RestClientException e) {
            log.warn("Failed to get authorities by email for user: {}", email, e);
            
            // #region agent log
            try {
                java.nio.file.Files.write(java.nio.file.Paths.get("w:\\projects\\angular\\ems-ui\\.cursor\\debug.log"), 
                    (String.format("{\"sessionId\":\"debug-session\",\"runId\":\"run1\",\"hypothesisId\":\"H\",\"location\":\"UserServiceClient.java:194\",\"message\":\"RestClientException\",\"data\":{\"error\":\"%s\"},\"timestamp\":%d}\n", 
                        e.getMessage(), System.currentTimeMillis())).getBytes(), 
                    java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND);
            } catch (Exception ex) {}
            // #endregion
        } catch (Exception e) {
            log.error("Unexpected error getting authorities by email for user: {}", email, e);
            
            // #region agent log
            try {
                java.nio.file.Files.write(java.nio.file.Paths.get("w:\\projects\\angular\\ems-ui\\.cursor\\debug.log"), 
                    (String.format("{\"sessionId\":\"debug-session\",\"runId\":\"run1\",\"hypothesisId\":\"I\",\"location\":\"UserServiceClient.java:200\",\"message\":\"Exception getting authorities\",\"data\":{\"error\":\"%s\"},\"timestamp\":%d}\n", 
                        e.getMessage(), System.currentTimeMillis())).getBytes(), 
                    java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND);
            } catch (Exception ex) {}
            // #endregion
        }

        return new ArrayList<>();
    }

    /**
     * Get user authorities (roles) by Google ID from User Service
     * @param googleId User Google ID
     * @return List of role strings (e.g., ["ROLE_HR", "ROLE_ADMIN"]), empty list if not found or error
     */
    public List<String> getUserAuthoritiesByGoogleId(String googleId) {
        if (googleId == null || googleId.isEmpty()) {
            log.warn("Google ID is null or empty, cannot fetch authorities");
            return new ArrayList<>();
        }

        try {
            String url = userServiceUrl + "/api/users/google/{googleId}/authorities";
            
            // User Service returns AuthoritiesResponse wrapper: { "authorities": ["ROLE_HR", ...] }
            ResponseEntity<Map<String, Object>> response = restTemplate.exchange(
                    url,
                    HttpMethod.GET,
                    null,
                    new ParameterizedTypeReference<Map<String, Object>>() {},
                    googleId
            );

            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                Map<String, Object> responseBody = response.getBody();
                // Extract authorities from the response wrapper
                Object authoritiesObj = responseBody.get("authorities");
                List<String> authorities = new ArrayList<>();
                
                if (authoritiesObj instanceof List) {
                    @SuppressWarnings("unchecked")
                    List<Object> authoritiesList = (List<Object>) authoritiesObj;
                    authorities = authoritiesList.stream()
                            .map(auth -> auth.toString())
                            .collect(Collectors.toList());
                }
                
                log.debug("Retrieved {} authorities for user by Google ID: {}", authorities.size(), googleId);
                return authorities;
            } else if (response.getStatusCode() == HttpStatus.NOT_FOUND) {
                log.debug("User not found in User Service by Google ID: {}", googleId);
                return new ArrayList<>();
            }
        } catch (RestClientException e) {
            log.warn("Failed to get authorities by Google ID for user: {}", googleId, e);
        } catch (Exception e) {
            log.error("Unexpected error getting authorities by Google ID for user: {}", googleId, e);
        }

        return new ArrayList<>();
    }

    /**
     * Map User Service response Map to UserInfo DTO
     */
    private UserInfo mapToUserInfo(Map<String, Object> userData) {
        try {
            Long id = userData.get("id") != null ? ((Number) userData.get("id")).longValue() : null;
            String email = (String) userData.get("email");
            String name = (String) userData.get("name");
            String picture = (String) userData.get("picture");
            String googleId = (String) userData.get("googleId");
            
            // Extract roles from userData if available
            List<String> roles = new ArrayList<>();
            if (userData.get("roles") != null) {
                Object rolesObj = userData.get("roles");
                if (rolesObj instanceof List) {
                    @SuppressWarnings("unchecked")
                    List<Object> rolesList = (List<Object>) rolesObj;
                    roles = rolesList.stream()
                            .map(role -> role.toString())
                            .collect(Collectors.toList());
                }
            }

            return new UserInfo(id, email, name, picture, googleId, roles);
        } catch (Exception e) {
            log.error("Error mapping user data to UserInfo", e);
            return null;
        }
    }
}

