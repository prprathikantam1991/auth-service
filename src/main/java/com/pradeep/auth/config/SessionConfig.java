package com.pradeep.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.serializer.JdkSerializationRedisSerializer;
import org.springframework.data.redis.serializer.RedisSerializer;
import org.springframework.session.data.redis.config.annotation.web.http.EnableRedisHttpSession;

/**
 * Configuration for Spring Session with Redis using Java serialization.
 * 
 * NOTE: JSON serialization with Spring Security OAuth2 is problematic because:
 * - Spring Security OAuth2 objects contain complex types (enums, nested objects)
 * - Jackson cannot reliably deserialize OAuth2AuthorizationRequest and related types
 * - Type information (@class) requirements cause compatibility issues
 * 
 * Java serialization is the recommended approach for Spring Security sessions.
 * While it's not human-readable, it's reliable and works out-of-the-box.
 * 
 * To view session data, you can:
 * - Use Redis CLI to check session keys: KEYS spring:session:*
 * - Check session expiration: TTL spring:session:sessions:SESSION_ID
 * - Use Redis GUI tools that can display binary data
 * - Monitor session count: DBSIZE or KEYS spring:session:sessions:* | wc -l
 */
@Configuration
@EnableRedisHttpSession(maxInactiveIntervalInSeconds = 1800) // 30 minutes
public class SessionConfig {

    /**
     * Configure Spring Session to use Java serialization.
     * 
     * This bean name is important - Spring Session looks for this specific bean
     * to determine how to serialize session data.
     * 
     * Java serialization is used because:
     * - Spring Security OAuth2 objects are complex and difficult to serialize with JSON
     * - Jackson cannot reliably handle OAuth2AuthorizationRequest and related types
     * - This is the recommended approach for Spring Security sessions
     * 
     * @return JdkSerializationRedisSerializer that stores data as binary (reliable for Spring Security)
     */
    @Bean("springSessionDefaultRedisSerializer")
    public RedisSerializer<Object> springSessionDefaultRedisSerializer() {
        // Use Java serialization - reliable for Spring Security OAuth2
        return new JdkSerializationRedisSerializer();
    }
}

