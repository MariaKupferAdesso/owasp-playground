package org.example.owaspplayground.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.UUID;

/**
 * Threat: unauthorized API access via missing or tampered tokens (A01).
 * Implementation: extracts Bearer token from Authorization header, verifies signature and
 *   expiry, then populates SecurityContext with a {@link JwtPrincipal} — no DB call needed.
 * Limitations: revoked-before-expiry tokens are accepted (mitigated by short TTL).
 */
@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final TokenDenylistService tokenDenylistService;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {

        String header = request.getHeader("Authorization");

        if (header == null || !header.startsWith("Bearer ")) {
            chain.doFilter(request, response);
            return;
        }

        String token = header.substring(7);
        try {
            Claims claims = jwtService.parseToken(token);

            String jti = claims.getId();
            if (jti != null && tokenDenylistService.isDenylisted(jti)) {
                log.warn("Denylisted token from {}", request.getRemoteAddr());
                chain.doFilter(request, response);
                return;
            }

            String username = claims.getSubject();
            String role = claims.get("role", String.class);
            UUID userId = UUID.fromString(claims.get("userId", String.class));

            var principal = new JwtPrincipal(userId, username, role);
            var auth = new UsernamePasswordAuthenticationToken(
                    principal, null, List.of(new SimpleGrantedAuthority("ROLE_" + role)));

            SecurityContextHolder.getContext().setAuthentication(auth);

        } catch (JwtException e) {
            // Log but do not short-circuit — security rules will reject the unauthenticated request
            log.warn("Invalid JWT from {}: {}", request.getRemoteAddr(), LogSanitizer.s(e.getMessage()));
        }

        chain.doFilter(request, response);
    }
}
