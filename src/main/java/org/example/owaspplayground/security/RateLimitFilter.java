package org.example.owaspplayground.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;

import org.springframework.data.redis.core.StringRedisTemplate;

/**
 * General-purpose rate limiting filter.
 *
 * Threat: A07 — API abuse, scraping, and DoS via unbounded request rates.
 * Implementation: Fixed-window Redis counter per identity (authenticated userId or client IP).
 *     Runs after {@link JwtAuthenticationFilter} so the SecurityContext is already populated.
 * Limitations:
 *     - Fixed window (not sliding) — a burst at the window boundary can double the effective rate.
 *     - IP-based limiting is trivially bypassed with IP rotation; use only as a first layer.
 *     - Does not replace DDoS mitigation at the network or CDN layer.
 */
@Slf4j
public class RateLimitFilter extends OncePerRequestFilter {

    private static final String KEY_PREFIX = "rate:";

    private final StringRedisTemplate redis;
    private final int requestsPerWindow;
    private final Duration windowDuration;
    /**
     * When true, the first value of X-Forwarded-For is trusted as the real client IP.
     * Enable ONLY when this application runs behind a trusted reverse proxy that sets
     * the header reliably (e.g. nginx, AWS ALB). When false (default), the socket-level
     * remote address is always used — not spoofable by the client.
     */
    private final boolean trustForwardedFor;

    public RateLimitFilter(StringRedisTemplate redis, int requestsPerWindow,
                           Duration windowDuration, boolean trustForwardedFor) {
        this.redis = redis;
        this.requestsPerWindow = requestsPerWindow;
        this.windowDuration = windowDuration;
        this.trustForwardedFor = trustForwardedFor;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        String identifier = resolveIdentifier(request);
        String key = KEY_PREFIX + identifier;

        Long count = redis.opsForValue().increment(key);
        if (count != null && count == 1) {
            // Set TTL on the first request in the window — window starts here.
            redis.expire(key, windowDuration);
        }

        if (count != null && count > requestsPerWindow) {
            log.warn("Rate limit exceeded: identifier={} count={}/{}", LogSanitizer.s(identifier), count, requestsPerWindow);
            writeTooManyRequests(response);
            return;
        }

        chain.doFilter(request, response);
    }

    /**
     * Authenticated requests are keyed by userId; anonymous requests by client IP.
     * Using userId (not username) avoids collisions and is stable across password changes.
     */
    private String resolveIdentifier(HttpServletRequest request) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.isAuthenticated() && auth.getPrincipal() instanceof JwtPrincipal principal) {
            return "user:" + principal.userId();
        }
        return "ip:" + extractClientIp(request);
    }

    private String extractClientIp(HttpServletRequest request) {
        if (trustForwardedFor) {
            String forwarded = request.getHeader("X-Forwarded-For");
            if (forwarded != null && !forwarded.isBlank()) {
                return forwarded.split(",")[0].trim();
            }
        }
        return request.getRemoteAddr();
    }

    private void writeTooManyRequests(HttpServletResponse response) throws IOException {
        response.setStatus(429);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        String body = """
                {"status":429,"error":"Too Many Requests","message":"Rate limit exceeded","timestamp":"%s"}
                """.formatted(Instant.now()).strip();
        response.getWriter().write(body);
    }
}
