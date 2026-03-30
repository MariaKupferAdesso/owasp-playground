package org.example.owaspplayground.dto;

import org.example.owaspplayground.domain.AppUser;
import org.example.owaspplayground.domain.Role;

import java.util.UUID;

// password_hash intentionally excluded — never expose credentials, even hashed (A02).
public record UserSummary(UUID id, String username, Role role) {

    public static UserSummary from(AppUser user) {
        return new UserSummary(user.getId(), user.getUsername(), user.getRole());
    }
}
