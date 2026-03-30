package org.example.owaspplayground.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.owaspplayground.domain.AppUser;
import org.example.owaspplayground.domain.Role;
import org.example.owaspplayground.dto.LoginResponse;
import org.example.owaspplayground.dto.RegisterRequest;
import org.example.owaspplayground.exception.LoginLockedException;
import org.example.owaspplayground.repository.UserRepository;
import org.example.owaspplayground.security.JwtProperties;
import org.example.owaspplayground.security.JwtService;
import org.example.owaspplayground.security.LogSanitizer;
import org.example.owaspplayground.security.LoginAttemptService;
import org.example.owaspplayground.security.TokenDenylistService;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final JwtProperties jwtProperties;
    private final LoginAttemptService loginAttemptService;
    private final TokenDenylistService tokenDenylistService;

    @Transactional
    public void register(RegisterRequest request) {
        if (userRepository.existsByUsername(request.username())) {
            // Generic message — does not confirm whether username exists (user enumeration A01).
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Registration failed");
        }
        AppUser user = AppUser.builder()
                .username(request.username())
                .passwordHash(passwordEncoder.encode(request.password()))
                .role(Role.USER)
                .build();
        userRepository.save(user);
    }

    @Transactional(readOnly = true)
    public LoginResponse login(String username, String password) {
        // Check lockout before any DB access — fast-fail for blocked accounts (A07).
        if (loginAttemptService.isBlocked(username)) {
            log.warn("Login blocked for '{}': too many failed attempts", LogSanitizer.s(username));
            throw new LoginLockedException(loginAttemptService.remainingLockout(username));
        }

        AppUser user = userRepository.findByUsername(username)
                .orElseThrow(() -> {
                    // Count unknown usernames too — prevents targeted enumeration via timing.
                    loginAttemptService.recordFailure(username);
                    // Generic message — does not distinguish bad username from bad password (A01).
                    return new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials");
                });

        if (!passwordEncoder.matches(password, user.getPasswordHash())) {
            loginAttemptService.recordFailure(username);
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials");
        }

        // Successful login — reset the brute-force counter.
        loginAttemptService.clearAttempts(username);
        String token = jwtService.generateToken(user.getId(), user.getUsername(), user.getRole());
        long expiresInSeconds = jwtProperties.expiry().toSeconds();
        return new LoginResponse(token, expiresInSeconds);
    }

    /**
     * Invalidates the supplied access token by adding its jti to the Redis denylist.
     * The denylist entry TTL matches the token's remaining lifetime so Redis auto-cleans it.
     */
    public void logout(String token) {
        try {
            var claims = jwtService.parseToken(token);
            String jti = claims.getId();
            if (jti == null) return; // tokens issued before jti was added — nothing to denylist
            var remaining = java.time.Duration.between(
                    java.time.Instant.now(), claims.getExpiration().toInstant());
            tokenDenylistService.denylist(jti, remaining);
            log.info("Token invalidated for user '{}'", LogSanitizer.s(claims.getSubject()));
        } catch (io.jsonwebtoken.JwtException e) {
            // Already invalid — nothing to denylist.
            log.debug("Logout called with invalid token: {}", e.getMessage());
        }
    }
}
