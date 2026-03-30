package org.example.owaspplayground.security;

import java.util.UUID;

/**
 * Immutable principal extracted from a verified JWT.
 * Stored in the SecurityContext — no DB round-trip per request (stateless).
 */
public record JwtPrincipal(UUID userId, String username, String role) {

    public boolean isAdmin() {
        return "ADMIN".equals(role);
    }
}
