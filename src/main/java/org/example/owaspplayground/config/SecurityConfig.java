package org.example.owaspplayground.config;

import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.example.owaspplayground.security.JwtAuthenticationFilter;
import org.example.owaspplayground.security.JwtProperties;
import org.example.owaspplayground.security.JwtService;
import org.example.owaspplayground.security.LogSanitizer;
import org.example.owaspplayground.security.RateLimitFilter;
import org.example.owaspplayground.security.TokenDenylistService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.time.Instant;
import java.util.List;

import static org.springframework.security.config.Customizer.withDefaults;

@Slf4j
@Configuration
@EnableWebSecurity
// @PreAuthorize / @PostAuthorize for RBAC and ownership enforcement at method level (A01)
@EnableMethodSecurity(prePostEnabled = true)
@EnableConfigurationProperties(JwtProperties.class)
public class SecurityConfig {

    @Value("${security.cors.allowed-origins}")
    private List<String> allowedOrigins;

    @Value("${security.rate-limit.requests-per-window:100}")
    private int rateLimitRequestsPerWindow;

    @Value("${security.rate-limit.window-duration:PT1M}")
    private java.time.Duration rateLimitWindowDuration;

    @Value("${security.rate-limit.trust-forwarded-for:false}")
    private boolean rateLimitTrustForwardedFor;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   JwtService jwtService,
                                                   TokenDenylistService tokenDenylistService,
                                                   StringRedisTemplate redis) throws Exception {
        http
            // CSRF: disabled — stateless REST API; JWT in Authorization header cannot be
            // auto-attached by the browser, so CSRF does not apply.
            // Limitation: must be re-enabled if session cookies are ever introduced.
            .csrf(csrf -> csrf.disable())

            // CORS: allowlist-based, delegates to corsConfigurationSource bean.
            .cors(withDefaults())

            // Security Headers
            .headers(headers -> headers
                // Clickjacking (A05) — deny framing entirely.
                .frameOptions(frame -> frame.deny())
                // MIME sniffing (A03) — browser must honour declared content-type.
                .contentTypeOptions(withDefaults())
                // HSTS — SSL stripping / downgrade attacks (A02).
                // Limitation: first-visit unprotected without preload list submission.
                .httpStrictTransportSecurity(hsts -> hsts
                    .includeSubDomains(true)
                    .maxAgeInSeconds(31_536_000))
                // CSP — belt-and-suspenders for JSON APIs; restricts resource loading (A03).
                // Limitation: primarily useful when the API ever serves HTML error pages.
                .contentSecurityPolicy(csp -> csp
                    .policyDirectives("default-src 'none'; frame-ancestors 'none'"))
                // Information leakage via Referer header (A09).
                .referrerPolicy(ref -> ref
                    .policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.NO_REFERRER))
                // Cache control (A04) — prevents browsers and proxies from caching sensitive
                // API responses (tokens, user data, orders). Adds:
                //   Cache-Control: no-cache, no-store, max-age=0, must-revalidate
                //   Pragma: no-cache
                //   Expires: 0
                // Limitation: does not control server-side or CDN caches — those require
                // separate configuration outside the application.
                .cacheControl(withDefaults())
            )

            // STATELESS — no HttpSession; eliminates session fixation/hijacking.
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))

            // JWT filter runs before Spring's UsernamePasswordAuthenticationFilter.
            // Populates SecurityContext from a verified Bearer token — no DB round-trip.
            .addFilterBefore(new JwtAuthenticationFilter(jwtService, tokenDenylistService),
                    UsernamePasswordAuthenticationFilter.class)

            // Rate limiting runs after JWT filter so SecurityContext is already set.
            // Authenticated requests are keyed by userId; anonymous requests by client IP.
            .addFilterAfter(new RateLimitFilter(redis, rateLimitRequestsPerWindow, rateLimitWindowDuration,
                    rateLimitTrustForwardedFor), JwtAuthenticationFilter.class)

            // DENY BY DEFAULT (A01) — every path requires authentication unless explicitly
            // permitted below. Force-browsing: unknown paths return 401/403, not 404.
            // Note: /api/auth/logout is intentionally NOT listed here — it requires a valid token.
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/actuator/health", "/actuator/info").permitAll()
                .requestMatchers("/api/auth/register", "/api/auth/login").permitAll()
                .requestMatchers("/api/public/**").permitAll()
                .anyRequest().authenticated())

            // Structured JSON error responses; logs every denial for audit trail.
            .exceptionHandling(ex -> ex
                .authenticationEntryPoint((request, response, e) -> {
                    log.warn("Authentication failure: {} {} from {}",
                            request.getMethod(), LogSanitizer.s(request.getRequestURI()), request.getRemoteAddr());
                    writeError(response, 401, "Unauthorized", "Authentication required");
                })
                .accessDeniedHandler((request, response, e) -> {
                    var auth = SecurityContextHolder.getContext().getAuthentication();
                    String user = (auth != null) ? auth.getName() : "anonymous";
                    log.warn("Access denied: {} {} for user '{}'",
                            request.getMethod(), LogSanitizer.s(request.getRequestURI()), LogSanitizer.s(user));
                    writeError(response, 403, "Forbidden", "Access denied");
                }));

        return http.build();
    }

    // CORS — explicit origin allowlist (A01/A05).
    // allowCredentials=false: consistent with JWT-in-header; no cookies.
    // Limitation: does not protect against SSRF.
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        var config = new CorsConfiguration();
        config.setAllowedOrigins(allowedOrigins);
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("Authorization", "Content-Type", "Accept"));
        config.setExposedHeaders(List.of("Authorization"));
        config.setAllowCredentials(false);
        config.setMaxAge(3600L);
        var source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    // BCrypt cost=10 — intentionally slow to resist brute force (A07).
    // Limitation: cost factor should be tuned upward as hardware improves.
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    private void writeError(HttpServletResponse response,
                            int status, String error, String message) throws java.io.IOException {
        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        // Inline JSON — avoids pulling Jackson into SecurityConfig.
        // Structure mirrors ErrorResponse record; no sensitive data emitted.
        String body = """
                {"status":%d,"error":"%s","message":"%s","timestamp":"%s"}
                """.formatted(status, error, message, Instant.now()).strip();
        response.getWriter().write(body);
    }
}
