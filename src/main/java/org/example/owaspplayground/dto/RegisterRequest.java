package org.example.owaspplayground.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.example.owaspplayground.security.NotWeakPassword;

public record RegisterRequest(
        @NotBlank @Size(min = 3, max = 100) String username,
        @NotBlank @Size(min = 8, max = 72) @NotWeakPassword String password
) {}
