package org.example.owaspplayground.security;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

/**
 * Redis-backed denylist for invalidated access tokens.
 *
 * Threat: A07 — stolen or leaked tokens remain valid until expiry.
 * Implementation: on logout the token's jti is stored in Redis with a TTL equal to the
 *     token's remaining lifetime. The filter checks the denylist before accepting a token.
 *     After the token would have expired anyway the Redis key auto-deletes — no cleanup needed.
 * Limitation: the denylist only covers tokens whose jti is present (tokens issued before this
 *     feature was deployed have no jti and are always accepted).
 */
@Service
@RequiredArgsConstructor
public class TokenDenylistService {

    private static final String KEY_PREFIX = "denylist:";

    private final StringRedisTemplate redis;

    public void denylist(String jti, Duration remainingTtl) {
        if (!remainingTtl.isNegative() && !remainingTtl.isZero()) {
            redis.opsForValue().set(KEY_PREFIX + jti, "1", remainingTtl);
        }
    }

    public boolean isDenylisted(String jti) {
        return Boolean.TRUE.equals(redis.hasKey(KEY_PREFIX + jti));
    }
}
