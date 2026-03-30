package org.example.owaspplayground;

import org.example.owaspplayground.domain.AppUser;
import org.example.owaspplayground.domain.Role;
import org.example.owaspplayground.repository.OrderRepository;
import org.example.owaspplayground.repository.UserRepository;
import org.example.owaspplayground.security.LoginAttemptService;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Integration tests for brute-force protection on POST /api/auth/login.
 *
 * Test YAML uses max-attempts=3 and lockout-duration=PT1M to keep test execution fast.
 *
 * Covers (A07 — Identification and Authentication Failures):
 * - Account locked after N consecutive failures → 429 + Retry-After header
 * - Successful login before threshold → 200 (not blocked)
 * - Successful login resets the counter
 * - Locked account stays locked even with correct password
 */
@SpringBootTest
@Import(TestcontainersConfiguration.class)
class BruteForceProtectionTest {

    @Autowired WebApplicationContext wac;
    @Autowired UserRepository userRepository;
    @Autowired OrderRepository orderRepository;
    @Autowired PasswordEncoder passwordEncoder;
    @Autowired LoginAttemptService loginAttemptService;
    @Autowired StringRedisTemplate redis;

    MockMvc mockMvc;

    static final String LOGIN_URL = "/api/auth/login";
    static final String CORRECT_PASSWORD = "password123";
    static final String WRONG_PASSWORD = "wrongPassword";

    AppUser testUser;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders
                .webAppContextSetup(wac)
                .apply(SecurityMockMvcConfigurers.springSecurity())
                .build();

        orderRepository.deleteAll();
        userRepository.deleteAll();

        testUser = userRepository.save(AppUser.builder()
                .username("alice")
                .passwordHash(passwordEncoder.encode(CORRECT_PASSWORD))
                .role(Role.USER)
                .build());

        // Clear any leftover Redis state from previous test runs.
        loginAttemptService.clearAttempts(testUser.getUsername());
    }

    @AfterEach
    void tearDown() {
        // Clear all brute-force counters so test state does not leak into other test classes
        // (e.g. AccessControlTest also creates an "alice" user and must not see a locked account).
        var keys = redis.keys("brute:*");
        if (keys != null && !keys.isEmpty()) {
            redis.delete(keys);
        }
    }

    private void performFailedLogin(String username) throws Exception {
        mockMvc.perform(post(LOGIN_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"%s","password":"%s"}
                                """.formatted(username, WRONG_PASSWORD)));
    }

    private void performSuccessfulLogin() throws Exception {
        mockMvc.perform(post(LOGIN_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"%s","password":"%s"}
                                """.formatted(testUser.getUsername(), CORRECT_PASSWORD)))
                .andExpect(status().isOk());
    }

    // ── Lockout after threshold ───────────────────────────────────────────────

    @Nested
    @DisplayName("Account lockout after threshold (max-attempts=3 in tests)")
    class AccountLockout {

        @Test
        @DisplayName("3 failed logins → 4th attempt returns 429 with Retry-After header")
        void lockedAfterMaxAttempts() throws Exception {
            performFailedLogin(testUser.getUsername());
            performFailedLogin(testUser.getUsername());
            performFailedLogin(testUser.getUsername());

            mockMvc.perform(post(LOGIN_URL)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    {"username":"alice","password":"anything"}
                                    """))
                    .andExpect(status().isTooManyRequests())
                    .andExpect(header().exists("Retry-After"))
                    .andExpect(jsonPath("$.status").value(429))
                    .andExpect(jsonPath("$.error").value("Too Many Requests"));
        }

        @Test
        @DisplayName("Locked account rejected even with correct password → 429")
        void lockedAccountRejectedWithCorrectPassword() throws Exception {
            performFailedLogin(testUser.getUsername());
            performFailedLogin(testUser.getUsername());
            performFailedLogin(testUser.getUsername());

            mockMvc.perform(post(LOGIN_URL)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    {"username":"alice","password":"%s"}
                                    """.formatted(CORRECT_PASSWORD)))
                    .andExpect(status().isTooManyRequests());
        }
    }

    // ── Below threshold ───────────────────────────────────────────────────────

    @Nested
    @DisplayName("Login succeeds when below threshold")
    class BelowThreshold {

        @Test
        @DisplayName("2 failed logins (below max=3) → correct password succeeds → 200")
        void loginSucceedsBeforeThreshold() throws Exception {
            performFailedLogin(testUser.getUsername());
            performFailedLogin(testUser.getUsername());

            performSuccessfulLogin();
        }

        @Test
        @DisplayName("Successful login resets counter — can fail again without early lockout")
        void successfulLoginResetsCounter() throws Exception {
            performFailedLogin(testUser.getUsername());
            performFailedLogin(testUser.getUsername());

            // Login succeeds and resets the counter.
            performSuccessfulLogin();

            // Two more failures should not trigger lockout (counter was reset to 0).
            performFailedLogin(testUser.getUsername());
            performFailedLogin(testUser.getUsername());

            mockMvc.perform(post(LOGIN_URL)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    {"username":"alice","password":"%s"}
                                    """.formatted(CORRECT_PASSWORD)))
                    .andExpect(status().isOk());
        }
    }

    // ── Unknown usernames ─────────────────────────────────────────────────────

    @Nested
    @DisplayName("Unknown username — counted to prevent enumeration via timing")
    class UnknownUsername {

        @Test
        @DisplayName("3 attempts on unknown username → 4th returns 429")
        void unknownUsernameIsAlsoThrottled() throws Exception {
            performFailedLogin("nonexistent");
            performFailedLogin("nonexistent");
            performFailedLogin("nonexistent");

            mockMvc.perform(post(LOGIN_URL)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    {"username":"nonexistent","password":"any"}
                                    """))
                    .andExpect(status().isTooManyRequests());
        }
    }
}
