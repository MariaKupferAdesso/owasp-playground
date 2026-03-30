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
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Integration tests for access token invalidation via logout (A07).
 *
 * Covers:
 * - Token is accepted before logout
 * - Token is rejected (401) immediately after logout
 * - Logout without a token returns 401
 * - A different user's token is unaffected by another user's logout
 */
@SpringBootTest
@Import(TestcontainersConfiguration.class)
class TokenInvalidationTest {

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

        // Clear denylist and rate-limit state.
        var keys = redis.keys("denylist:*");
        if (keys != null && !keys.isEmpty()) redis.delete(keys);
        keys = redis.keys("rate:*");
        if (keys != null && !keys.isEmpty()) redis.delete(keys);
    }

    @Test
    @DisplayName("Token works before logout, is rejected immediately after")
    void tokenIsInvalidatedAfterLogout() throws Exception {
        // Token is valid before logout.
        mockMvc.perform(get("/api/orders")
                        .header("Authorization", "Bearer " + aliceToken))
                .andExpect(status().isOk());

        // Logout.
        mockMvc.perform(post("/api/auth/logout")
                        .header("Authorization", "Bearer " + aliceToken))
                .andExpect(status().isNoContent());

        // Same token is now rejected.
        mockMvc.perform(get("/api/orders")
                        .header("Authorization", "Bearer " + aliceToken))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Logout without token returns 401")
    void logoutWithoutTokenReturns401() throws Exception {
        mockMvc.perform(post("/api/auth/logout"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Logging out one user does not affect another user's token")
    void otherUserTokenUnaffectedByLogout() throws Exception {
        // Alice logs out.
        mockMvc.perform(post("/api/auth/logout")
                        .header("Authorization", "Bearer " + aliceToken))
                .andExpect(status().isNoContent());

        // Bob's token still works.
        mockMvc.perform(get("/api/orders")
                        .header("Authorization", "Bearer " + bobToken))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("Login endpoint still accessible after another user logs out")
    void loginStillAccessibleAfterLogout() throws Exception {
        mockMvc.perform(post("/api/auth/logout")
                        .header("Authorization", "Bearer " + aliceToken))
                .andExpect(status().isNoContent());

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"bob","password":"pw"}
                                """))
                .andExpect(status().isOk());
    }
}
