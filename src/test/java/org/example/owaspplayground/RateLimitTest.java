package org.example.owaspplayground;

import org.example.owaspplayground.domain.AppUser;
import org.example.owaspplayground.domain.Role;
import org.example.owaspplayground.repository.OrderRepository;
import org.example.owaspplayground.repository.UserRepository;
import org.example.owaspplayground.security.JwtService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Integration tests for general rate limiting (A07).
 *
 * Overrides requests-per-window to 3 so tests stay fast.
 * Redis keys are cleared in @BeforeEach to isolate each test.
 *
 * Covers:
 * - Anonymous request keyed by IP → 429 after limit
 * - Authenticated request keyed by userId → 429 after limit
 * - Different users do not affect each other's counters
 */
@SpringBootTest(properties = {
        "security.rate-limit.requests-per-window=3",
        "security.rate-limit.window-duration=PT1M"
})
@Import(TestcontainersConfiguration.class)
class RateLimitTest {

    @Autowired WebApplicationContext wac;
    @Autowired UserRepository userRepository;
    @Autowired OrderRepository orderRepository;
    @Autowired JwtService jwtService;
    @Autowired PasswordEncoder passwordEncoder;
    @Autowired StringRedisTemplate redis;

    MockMvc mockMvc;

    AppUser alice;
    AppUser bob;
    String aliceToken;
    String bobToken;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders
                .webAppContextSetup(wac)
                .apply(SecurityMockMvcConfigurers.springSecurity())
                .build();

        orderRepository.deleteAll();
        userRepository.deleteAll();

        alice = userRepository.save(AppUser.builder()
                .username("alice").passwordHash(passwordEncoder.encode("pw")).role(Role.USER).build());
        bob = userRepository.save(AppUser.builder()
                .username("bob").passwordHash(passwordEncoder.encode("pw")).role(Role.USER).build());

        aliceToken = jwtService.generateToken(alice.getId(), alice.getUsername(), Role.USER);
        bobToken   = jwtService.generateToken(bob.getId(), bob.getUsername(), Role.USER);

        // Clear all rate limit counters so tests are isolated.
        var keys = redis.keys("rate:*");
        if (keys != null && !keys.isEmpty()) {
            redis.delete(keys);
        }
    }

    @Test
    @DisplayName("Anonymous: 3 requests succeed, 4th returns 429")
    void anonymousRequestIsRateLimitedByIp() throws Exception {
        for (int i = 0; i < 3; i++) {
            mockMvc.perform(get("/api/public/status"))
                    .andExpect(status().isOk());
        }
        mockMvc.perform(get("/api/public/status"))
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.status").value(429))
                .andExpect(jsonPath("$.error").value("Too Many Requests"));
    }

    @Test
    @DisplayName("Authenticated: 3 requests succeed, 4th returns 429")
    void authenticatedRequestIsRateLimitedByUserId() throws Exception {
        for (int i = 0; i < 3; i++) {
            mockMvc.perform(get("/api/orders")
                            .header("Authorization", "Bearer " + aliceToken))
                    .andExpect(status().isOk());
        }
        mockMvc.perform(get("/api/orders")
                        .header("Authorization", "Bearer " + aliceToken))
                .andExpect(status().isTooManyRequests());
    }

    @Test
    @DisplayName("Different users have independent counters")
    void differentUsersHaveIndependentCounters() throws Exception {
        // Exhaust Alice's limit.
        for (int i = 0; i < 3; i++) {
            mockMvc.perform(get("/api/orders")
                            .header("Authorization", "Bearer " + aliceToken))
                    .andExpect(status().isOk());
        }
        mockMvc.perform(get("/api/orders")
                        .header("Authorization", "Bearer " + aliceToken))
                .andExpect(status().isTooManyRequests());

        // Bob is not affected.
        mockMvc.perform(get("/api/orders")
                        .header("Authorization", "Bearer " + bobToken))
                .andExpect(status().isOk());
    }
}
