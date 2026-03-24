package org.example.owaspplayground.config;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.time.Instant;
import java.util.List;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Value("${security.cors.allowed-origins}")
    private List<String> allowedOrigins;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // CSRF: disabled — stateless REST API using JWT in Authorization header.
            // Browsers cannot auto-attach JWT, so CSRF attacks do not apply.
            // Limitation: must re-enable if session cookies are ever introduced.
            .csrf(csrf -> csrf.disable())

            // CORS: delegates to corsConfigurationSource bean.
            .cors(withDefaults())

            // Security Headers
            .headers(headers -> headers
                // Clickjacking (OWASP A05) — deny framing entirely.
                // Limitation: does not protect against CSS-based UI redressing.
                .frameOptions(frame -> frame.deny())

                // MIME sniffing (OWASP A03) — browser must honour declared content-type.
                .contentTypeOptions(withDefaults())

                // SSL stripping / downgrade attacks (OWASP A02).
                // Limitation: first-visit is unprotected without HSTS preload list submission.
                .httpStrictTransportSecurity(hsts -> hsts
                    .includeSubDomains(true)
                    .maxAgeInSeconds(31_536_000))

                // XSS (OWASP A03) — restricts resource loading; belt-and-suspenders for JSON APIs.
                // Limitation: primarily useful when the API ever serves HTML error pages.
                .contentSecurityPolicy(csp -> csp
                    .policyDirectives("default-src 'none'; frame-ancestors 'none'"))

                // Information leakage via Referer header (OWASP A09).
                .referrerPolicy(ref -> ref
                    .policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.NO_REFERRER))
            )

            // STATELESS: no HttpSession created or used. Eliminates session fixation/hijacking.
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))

            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/actuator/health", "/actuator/info").permitAll()
                .anyRequest().authenticated())

            // Return JSON 401/403 instead of Spring's default HTML redirect to /login.
            .exceptionHandling(ex -> ex
                .authenticationEntryPoint((request, response, e) ->
                    writeError(response, 401, "Unauthorized", "Authentication required"))
                .accessDeniedHandler((request, response, e) ->
                    writeError(response, 403, "Forbidden", "Access denied")));

        return http.build();
    }

    // CORS — explicit origin whitelist (OWASP A01/A05).
    // allowCredentials=false: consistent with JWT-in-header; cookies are not used.
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

    // BCrypt cost=10 (default) — intentionally slow to resist brute force (OWASP A07).
    // Limitation: cost factor should be tuned upward as hardware improves over time.
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    private void writeError(HttpServletResponse response,
                            int status, String error, String message) throws java.io.IOException {
        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        // Simple inline JSON — avoids pulling Jackson into SecurityConfig.
        // Structure mirrors ErrorResponse record; no sensitive data is emitted.
        String body = """
                {"status":%d,"error":"%s","message":"%s","timestamp":"%s"}
                """.formatted(status, error, message, Instant.now()).strip();
        response.getWriter().write(body);
    }
}
