package org.example.owaspplayground.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.example.owaspplayground.dto.LoginRequest;
import org.example.owaspplayground.dto.LoginResponse;
import org.example.owaspplayground.dto.RegisterRequest;
import org.example.owaspplayground.service.AuthService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    /** Public — registers a new USER-role account. */
    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public void register(@Valid @RequestBody RegisterRequest request) {
        authService.register(request);
    }

    /** Public — authenticates and returns a short-lived JWT. */
    @PostMapping("/login")
    public LoginResponse login(@Valid @RequestBody LoginRequest request) {
        return authService.login(request.username(), request.password());
    }

    /**
     * Authenticated — invalidates the current access token immediately.
     * Requires a valid Bearer token; the token is added to the Redis denylist for its remaining TTL.
     */
    @PostMapping("/logout")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void logout(@RequestHeader(HttpHeaders.AUTHORIZATION) String authHeader) {
        authService.logout(authHeader.substring(7));
    }
}
