package org.example.owaspplayground;

import org.example.owaspplayground.domain.AppUser;
import org.example.owaspplayground.domain.Order;
import org.example.owaspplayground.domain.Role;
import org.example.owaspplayground.repository.OrderRepository;
import org.example.owaspplayground.repository.UserRepository;
import org.example.owaspplayground.security.JwtService;
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

import java.util.UUID;

import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Integration tests for OWASP A01 Broken Access Control controls.
 *
 * Covers:
 * - Public endpoint access without authentication
 * - Deny by default (unauthenticated access to protected paths)
 * - RBAC: USER cannot reach ADMIN endpoints
 * - Ownership: USER can only access their own orders
 * - IDOR prevention: accessing another user's order by UUID returns 403
 * - Force browsing: unknown paths return 401/403
 * - ADMIN can access all endpoints
 */
@SpringBootTest
@Import(TestcontainersConfiguration.class)
class AccessControlTest {

    @Autowired WebApplicationContext wac;
    @Autowired UserRepository userRepository;
    @Autowired OrderRepository orderRepository;
    @Autowired JwtService jwtService;
    @Autowired PasswordEncoder passwordEncoder;

    MockMvc mockMvc;

    // Test fixtures
    AppUser userAlice;
    AppUser userBob;
    AppUser adminUser;
    Order aliceOrder;
    Order bobOrder;

    String aliceToken;
    String bobToken;
    String adminToken;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders
                .webAppContextSetup(wac)
                .apply(SecurityMockMvcConfigurers.springSecurity())
                .build();

        orderRepository.deleteAll();
        userRepository.deleteAll();

        userAlice = userRepository.save(AppUser.builder()
                .username("alice")
                .passwordHash(passwordEncoder.encode("password123"))
                .role(Role.USER).build());

        userBob = userRepository.save(AppUser.builder()
                .username("bob")
                .passwordHash(passwordEncoder.encode("password456"))
                .role(Role.USER).build());

        adminUser = userRepository.save(AppUser.builder()
                .username("admin")
                .passwordHash(passwordEncoder.encode("adminPass1"))
                .role(Role.ADMIN).build());

        aliceOrder = orderRepository.save(Order.builder()
                .ownerId(userAlice.getId())
                .title("Alice's order").build());

        bobOrder = orderRepository.save(Order.builder()
                .ownerId(userBob.getId())
                .title("Bob's order").build());

        aliceToken = jwtService.generateToken(userAlice.getId(), userAlice.getUsername(), Role.USER);
        bobToken   = jwtService.generateToken(userBob.getId(), userBob.getUsername(), Role.USER);
        adminToken = jwtService.generateToken(adminUser.getId(), adminUser.getUsername(), Role.ADMIN);
    }

    // ── Public endpoints ──────────────────────────────────────────────────────

    @Nested
    @DisplayName("Public endpoints — no authentication required")
    class PublicEndpoints {

        @Test
        @DisplayName("GET /api/public/status → 200 without token")
        void publicStatusIsAccessibleWithoutAuth() throws Exception {
            mockMvc.perform(get("/api/public/status"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.status").value("UP"));
        }

        @Test
        @DisplayName("GET /actuator/health → 200 without token")
        void actuatorHealthIsPublic() throws Exception {
            mockMvc.perform(get("/actuator/health"))
                    .andExpect(status().isOk());
        }

        @Test
        @DisplayName("POST /api/auth/register → 201 with valid body")
        void registerIsPublic() throws Exception {
            mockMvc.perform(post("/api/auth/register")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    {"username":"newuser","password":"securePass1"}
                                    """))
                    .andExpect(status().isCreated());
        }

        @Test
        @DisplayName("POST /api/auth/login → 200 and returns JWT")
        void loginIsPublicAndReturnsToken() throws Exception {
            mockMvc.perform(post("/api/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    {"username":"alice","password":"password123"}
                                    """))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.token").isNotEmpty())
                    .andExpect(jsonPath("$.expiresInSeconds").value(greaterThan(0)));
        }
    }

    // ── Deny by default ───────────────────────────────────────────────────────

    @Nested
    @DisplayName("Deny by default — unauthenticated requests rejected")
    class DenyByDefault {

        @Test
        @DisplayName("GET /api/orders → 401 without token")
        void ordersRequiresAuth() throws Exception {
            mockMvc.perform(get("/api/orders"))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.status").value(401));
        }

        @Test
        @DisplayName("GET /api/admin/orders → 401 without token")
        void adminOrdersRequiresAuth() throws Exception {
            mockMvc.perform(get("/api/admin/orders"))
                    .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("GET /api/unknown → 401 without token (force browsing blocked)")
        void unknownPathReturns401WithoutAuth() throws Exception {
            mockMvc.perform(get("/api/unknown/path"))
                    .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("Invalid JWT token → 401")
        void invalidJwtReturns401() throws Exception {
            mockMvc.perform(get("/api/orders")
                            .header("Authorization", "Bearer invalid.token.here"))
                    .andExpect(status().isUnauthorized());
        }
    }

    // ── USER role access ──────────────────────────────────────────────────────

    @Nested
    @DisplayName("USER role — can access own data only")
    class UserRoleAccess {

        @Test
        @DisplayName("GET /api/orders → 200, returns only caller's orders")
        void userSeesOnlyOwnOrders() throws Exception {
            mockMvc.perform(get("/api/orders")
                            .header("Authorization", "Bearer " + aliceToken))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$", hasSize(1)))
                    .andExpect(jsonPath("$[0].title").value("Alice's order"));
        }

        @Test
        @DisplayName("GET /api/orders/{ownOrderId} → 200 for own order")
        void userCanFetchOwnOrder() throws Exception {
            mockMvc.perform(get("/api/orders/" + aliceOrder.getId())
                            .header("Authorization", "Bearer " + aliceToken))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.id").value(aliceOrder.getId().toString()));
        }

        @Test
        @DisplayName("POST /api/orders → 201, ownerId set from JWT not body")
        void userCanCreateOrder() throws Exception {
            mockMvc.perform(post("/api/orders")
                            .header("Authorization", "Bearer " + aliceToken)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    {"title":"My new order"}
                                    """))
                    .andExpect(status().isCreated())
                    .andExpect(jsonPath("$.title").value("My new order"))
                    // ownerId must not appear in the response (information hiding)
                    .andExpect(jsonPath("$.ownerId").doesNotExist());
        }
    }

    // ── IDOR prevention ───────────────────────────────────────────────────────

    @Nested
    @DisplayName("IDOR prevention — USER cannot access another user's order")
    class IdorPrevention {

        @Test
        @DisplayName("Alice cannot read Bob's order by UUID → 403")
        void userCannotReadAnotherUsersOrder() throws Exception {
            // Alice attempts to access Bob's order by its UUID — must be denied
            mockMvc.perform(get("/api/orders/" + bobOrder.getId())
                            .header("Authorization", "Bearer " + aliceToken))
                    .andExpect(status().isForbidden())
                    .andExpect(jsonPath("$.status").value(403));
        }

        @Test
        @DisplayName("Bob cannot read Alice's order by UUID → 403")
        void idorPreventionIsSymmetric() throws Exception {
            mockMvc.perform(get("/api/orders/" + aliceOrder.getId())
                            .header("Authorization", "Bearer " + bobToken))
                    .andExpect(status().isForbidden());
        }

        @Test
        @DisplayName("Non-existent order UUID → 404 (no information leakage)")
        void nonExistentOrderReturns404() throws Exception {
            mockMvc.perform(get("/api/orders/" + UUID.randomUUID())
                            .header("Authorization", "Bearer " + aliceToken))
                    .andExpect(status().isNotFound());
        }
    }

    // ── RBAC — USER cannot reach ADMIN endpoints ──────────────────────────────

    @Nested
    @DisplayName("RBAC — USER role cannot access ADMIN endpoints")
    class RbacEnforcement {

        @Test
        @DisplayName("GET /api/admin/orders → 403 for USER role")
        void userCannotListAllOrders() throws Exception {
            mockMvc.perform(get("/api/admin/orders")
                            .header("Authorization", "Bearer " + aliceToken))
                    .andExpect(status().isForbidden());
        }

        @Test
        @DisplayName("GET /api/admin/users → 403 for USER role")
        void userCannotListUsers() throws Exception {
            mockMvc.perform(get("/api/admin/users")
                            .header("Authorization", "Bearer " + aliceToken))
                    .andExpect(status().isForbidden());
        }
    }

    // ── ADMIN role access ─────────────────────────────────────────────────────

    @Nested
    @DisplayName("ADMIN role — can access all data")
    class AdminRoleAccess {

        @Test
        @DisplayName("GET /api/admin/orders → 200 for ADMIN, returns all orders")
        void adminCanListAllOrders() throws Exception {
            mockMvc.perform(get("/api/admin/orders")
                            .header("Authorization", "Bearer " + adminToken))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$", hasSize(greaterThanOrEqualTo(2))));
        }

        @Test
        @DisplayName("GET /api/admin/users → 200 for ADMIN, no password hashes exposed")
        void adminCanListUsersWithoutPasswords() throws Exception {
            mockMvc.perform(get("/api/admin/users")
                            .header("Authorization", "Bearer " + adminToken))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$[*].passwordHash").doesNotExist())
                    .andExpect(jsonPath("$[*].username", hasItems("alice", "bob", "admin")));
        }

        @Test
        @DisplayName("GET /api/orders/{id} → 200 for ADMIN on any order")
        void adminCanReadAnyOrder() throws Exception {
            mockMvc.perform(get("/api/orders/" + bobOrder.getId())
                            .header("Authorization", "Bearer " + adminToken))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.id").value(bobOrder.getId().toString()));
        }
    }

    // ── Input validation ──────────────────────────────────────────────────────

    @Nested
    @DisplayName("Input validation")
    class InputValidation {

        @Test
        @DisplayName("Register with blank username → 400")
        void registerWithBlankUsername() throws Exception {
            mockMvc.perform(post("/api/auth/register")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    {"username":"","password":"securePass1"}
                                    """))
                    .andExpect(status().isBadRequest());
        }

        @Test
        @DisplayName("Register with short password → 400")
        void registerWithShortPassword() throws Exception {
            mockMvc.perform(post("/api/auth/register")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    {"username":"validuser","password":"short"}
                                    """))
                    .andExpect(status().isBadRequest());
        }

        @Test
        @DisplayName("Login with wrong password → 401 (no user enumeration)")
        void loginWithWrongPasswordReturns401() throws Exception {
            mockMvc.perform(post("/api/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    {"username":"alice","password":"wrongpassword"}
                                    """))
                    .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("Login with unknown username → 401 (same response as wrong password)")
        void loginWithUnknownUsernameReturns401() throws Exception {
            mockMvc.perform(post("/api/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    {"username":"doesnotexist","password":"anypassword"}
                                    """))
                    .andExpect(status().isUnauthorized());
        }
    }
}
