package org.example.owaspplayground.security;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

import java.util.Set;

public class WeakPasswordValidator implements ConstraintValidator<NotWeakPassword, String> {

    // Top 25 most common passwords — NCSC / NordPass annual research.
    // NIST 800-63b §5.1.1.2 requires checking new passwords against a list of known-bad values.
    private static final Set<String> COMMON_PASSWORDS = Set.of(
            "password", "123456", "12345678", "qwerty", "abc123",
            "monkey", "1234567", "letmein", "trustno1", "dragon",
            "baseball", "iloveyou", "master", "sunshine", "ashley",
            "bailey", "passw0rd", "shadow", "123123", "654321",
            "superman", "qazwsx", "michael", "football", "password1"
    );

    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        if (value == null) return true; // @NotBlank handles null separately
        return !COMMON_PASSWORDS.contains(value.toLowerCase());
    }
}
