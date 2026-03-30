package org.example.owaspplayground.exception;

import java.time.Duration;

/** Thrown when a username is temporarily locked due to too many failed login attempts. */
public class LoginLockedException extends RuntimeException {

    private final Duration retryAfter;

    public LoginLockedException(Duration retryAfter) {
        super("Too many failed login attempts");
        this.retryAfter = retryAfter;
    }

    public Duration getRetryAfter() {
        return retryAfter;
    }
}
