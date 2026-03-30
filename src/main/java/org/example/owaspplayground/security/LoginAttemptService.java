package org.example.owaspplayground.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.concurrent.TimeUnit;

/**
 * Tracks failed login attempts per username in Redis.
 *
 * Threat: A07 — brute-force and credential stuffing via unlimited login attempts.
 * Implementation: Redis INCR counter with TTL-based auto-expiry. After {@code maxAttempts}
 *     failures the account is locked for {@code lockoutDuration}; the counter resets
 *     automatically when the TTL expires or on a successful login.
 * Limitation: username-based only — distributed attacks from many IPs are not blocked.
 *     A known username can be deliberately locked out by an attacker (DoS), mitigated by
 *     the short default lockout window.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class LoginAttemptService {

    private static final String KEY_PREFIX = "brute:login:";

    private final StringRedisTemplate redis;

    @Value("${security.brute-force.max-attempts:5}")
    private int maxAttempts;

    @Value("${security.brute-force.lockout-duration:PT15M}")
    private Duration lockoutDuration;

    public boolean isBlocked(String username) {
        String val = redis.opsForValue().get(KEY_PREFIX + username);
        return val != null && Integer.parseInt(val) >= maxAttempts;
    }

    public void recordFailure(String username) {
        String key = KEY_PREFIX + username;
        Long count = redis.opsForValue().increment(key);
        if (count != null && count == 1) {
            // Set TTL only on the first failure — the window starts from the first attempt.
            redis.expire(key, lockoutDuration);
        }
        log.warn("Failed login attempt for '{}': count={}/{}", LogSanitizer.s(username), count, maxAttempts);
    }

    public void clearAttempts(String username) {
        redis.delete(KEY_PREFIX + username);
    }

    /** Remaining lockout time — used to populate the {@code Retry-After} response header. */
    public Duration remainingLockout(String username) {
        Long ttl = redis.getExpire(KEY_PREFIX + username, TimeUnit.SECONDS);
        return (ttl != null && ttl > 0) ? Duration.ofSeconds(ttl) : Duration.ZERO;
    }
}
