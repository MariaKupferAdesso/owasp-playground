package org.example.owaspplayground.security;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/**
 * JWT configuration.
 * - secret: Base64-encoded HMAC-SHA-256 key (≥256 bits). MUST be rotated per environment.
 * - expiry: Short-lived token window (default 15 min) limits the blast radius of a leaked token.
 */
@ConfigurationProperties(prefix = "security.jwt")
public record JwtProperties(String secret, Duration expiry) {}
