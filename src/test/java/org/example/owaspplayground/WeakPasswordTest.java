package org.example.owaspplayground;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Integration tests for weak password rejection at POST /api/auth/register.
 *
 * Covers (A07 — Authentication Failures / NIST 800-63b §5.1.1.2):
 * - Commonly-used passwords are rejected with 400
 * - Strong passwords are accepted
 * - Case-insensitive matching (e.g. "PASSWORD" == "password")
 */
@SpringBootTest
@Import(TestcontainersConfiguration.class)
class WeakPasswordTest {

    @Autowired WebApplicationContext wac;

    MockMvc mockMvc;

    static final String REGISTER_URL = "/api/auth/register";

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders
                .webAppContextSetup(wac)
                .apply(SecurityMockMvcConfigurers.springSecurity())
                .build();
    }

    @Test
    @DisplayName("Common password 'password1' is rejected with 400")
    void commonPasswordRejected() throws Exception {
        mockMvc.perform(post(REGISTER_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"newuser1","password":"password1"}
                                """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.message").value(org.hamcrest.Matchers.containsString("password")));
    }

    @Test
    @DisplayName("Common password check is case-insensitive — 'PASSWORD1' is rejected")
    void commonPasswordRejectedCaseInsensitive() throws Exception {
        mockMvc.perform(post(REGISTER_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"newuser2","password":"PASSWORD1"}
                                """))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("Strong password is accepted — registration returns 201")
    void strongPasswordAccepted() throws Exception {
        mockMvc.perform(post(REGISTER_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"newuser3","password":"xK9#mP2$vL7q"}
                                """))
                .andExpect(status().isCreated());
    }

    @Test
    @DisplayName("Password shorter than 8 characters is rejected (existing @Size constraint)")
    void tooShortPasswordRejected() throws Exception {
        mockMvc.perform(post(REGISTER_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"newuser4","password":"abc"}
                                """))
                .andExpect(status().isBadRequest());
    }
}
