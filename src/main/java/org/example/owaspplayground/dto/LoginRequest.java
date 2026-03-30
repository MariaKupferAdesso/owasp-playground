package org.example.owaspplayground.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record LoginRequest(
        // Max matches RegisterRequest — prevents oversized Redis keys and SQL parameters.
        @NotBlank @Size(max = 100) String username,
        // BCrypt silently truncates at 72 bytes; reject longer inputs explicitly (A07).
        @NotBlank @Size(max = 72) String password
) {}
