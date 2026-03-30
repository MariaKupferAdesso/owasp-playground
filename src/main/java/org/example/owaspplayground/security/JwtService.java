package org.example.owaspplayground.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.example.owaspplayground.domain.Role;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

/**
 * Threat: forged or replayed tokens granting unauthorized access (A01, A07).
 * Implementation: HMAC-SHA-256 signed JWT with short expiry; claims carry userId + role
 *   for stateless authorization without DB lookups.
 * Limitations: tokens can be invalidated via the denylist (see {@link TokenDenylistService});
 *   without that, a leaked token remains valid until expiry.
 */
@Service
public class JwtService {

    private final SecretKey secretKey;
    private final JwtProperties props;

    public JwtService(JwtProperties props) {
        this.props = props;
        this.secretKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(props.secret()));
    }

    public String generateToken(UUID userId, String username, Role role) {
        Instant now = Instant.now();
        return Jwts.builder()
                .id(UUID.randomUUID().toString())   // jti — unique token ID for denylist
                .subject(username)
                .claim("userId", userId.toString())
                .claim("role", role.name())
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plus(props.expiry())))
                .signWith(secretKey)
                .compact();
    }

    /**
     * Parses and validates a JWT. Throws {@link JwtException} on any validation failure
     * (bad signature, expired, malformed). Callers must not trust the result if an exception
     * is thrown.
     */
    public Claims parseToken(String token) {
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}
