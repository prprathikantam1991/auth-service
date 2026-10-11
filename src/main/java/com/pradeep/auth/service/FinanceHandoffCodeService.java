package com.pradeep.auth.service;

import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

/** Stores a short-lived, single-use Finance Tracker handoff code in Redis. */
@Service
public class FinanceHandoffCodeService {
    private static final Duration TTL = Duration.ofMinutes(2);
    private static final String PREFIX = "finance:handoff:";
    private final StringRedisTemplate redis;
    private final SecureRandom random = new SecureRandom();

    public FinanceHandoffCodeService(StringRedisTemplate redis) {
        this.redis = redis;
    }

    public String issue(String internalUserId) {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        String code = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        redis.opsForValue().set(PREFIX + code, internalUserId, TTL);
        return code;
    }

    /** Atomic Redis delete makes the code unusable after this call. */
    public String consume(String code) {
        if (code == null || code.isBlank()) return null;
        return redis.opsForValue().getAndDelete(PREFIX + code);
    }
}
