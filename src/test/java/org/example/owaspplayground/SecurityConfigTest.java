package org.example.owaspplayground;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@Import(TestcontainersConfiguration.class)
class SecurityConfigTest {

    @Autowired
    WebApplicationContext wac;

    MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders
                .webAppContextSetup(wac)
                .apply(SecurityMockMvcConfigurers.springSecurity())
                .build();
    }

    @Nested
    @DisplayName("Public endpoints")
    class PublicEndpoints {

        @Test
        @DisplayName("/actuator/health is accessible without authentication")
        void actuatorHealthIsPublic() throws Exception {
            mockMvc.perform(get("/actuator/health"))
                    .andExpect(status().isOk());
        }

        @Test
        @DisplayName("/actuator/info is accessible without authentication")
        void actuatorInfoIsPublic() throws Exception {
            mockMvc.perform(get("/actuator/info"))
                    .andExpect(status().isOk());
        }
    }

    @Nested
    @DisplayName("Authentication enforcement")
    class AuthEnforcement {

        @Test
        @DisplayName("Unauthenticated request to protected path returns 401 JSON")
        void unauthenticatedRequestReturns401Json() throws Exception {
            mockMvc.perform(get("/api/anything"))
                    .andExpect(status().isUnauthorized())
                    .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                    .andExpect(jsonPath("$.status").value(401))
                    .andExpect(jsonPath("$.error").value("Unauthorized"))
                    .andExpect(jsonPath("$.timestamp").exists());
        }
    }

    @Nested
    @DisplayName("Security headers")
    class SecurityHeaders {

        @Test
        @DisplayName("X-Content-Type-Options: nosniff")
        void contentTypeOptions() throws Exception {
            mockMvc.perform(get("/actuator/health"))
                    .andExpect(header().string("X-Content-Type-Options", "nosniff"));
        }

        @Test
        @DisplayName("X-Frame-Options: DENY")
        void frameOptions() throws Exception {
            mockMvc.perform(get("/actuator/health"))
                    .andExpect(header().string("X-Frame-Options", "DENY"));
        }

        @Test
        @DisplayName("Strict-Transport-Security with max-age and includeSubDomains (HTTPS only)")
        void hsts() throws Exception {
            // HSTS is only sent over HTTPS; mark the mock request as secure
            mockMvc.perform(get("/actuator/health").secure(true))
                    .andExpect(header().string("Strict-Transport-Security",
                            containsString("max-age=31536000")))
                    .andExpect(header().string("Strict-Transport-Security",
                            containsString("includeSubDomains")));
        }

        @Test
        @DisplayName("Content-Security-Policy header is present")
        void csp() throws Exception {
            mockMvc.perform(get("/actuator/health"))
                    .andExpect(header().exists("Content-Security-Policy"));
        }
    }

    @Nested
    @DisplayName("CORS")
    class CorsTests {

        @Test
        @DisplayName("Preflight from allowed origin returns CORS headers")
        void preflightAllowedOrigin() throws Exception {
            mockMvc.perform(options("/actuator/health")
                            .header("Origin", "http://localhost:3000")
                            .header("Access-Control-Request-Method", "GET"))
                    .andExpect(status().isOk())
                    .andExpect(header().string("Access-Control-Allow-Origin", "http://localhost:3000"))
                    .andExpect(header().exists("Access-Control-Allow-Methods"));
        }

        @Test
        @DisplayName("Preflight from disallowed origin has no Allow-Origin header")
        void preflightDisallowedOrigin() throws Exception {
            mockMvc.perform(options("/actuator/health")
                            .header("Origin", "http://evil.example.com")
                            .header("Access-Control-Request-Method", "GET"))
                    .andExpect(header().doesNotExist("Access-Control-Allow-Origin"));
        }
    }
}
