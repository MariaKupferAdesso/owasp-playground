package org.example.owaspplayground.security;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Threat: A07 — weak or commonly-used passwords trivially broken by dictionary attacks.
 * Implementation: case-insensitive check against the 25 most common passwords (NCSC / NordPass research).
 * Limitation: does not check against breach databases (e.g. HaveIBeenPwned) — that requires a
 * network call and is out of scope for this educational project.
 */
@Documented
@Constraint(validatedBy = WeakPasswordValidator.class)
@Target({ElementType.FIELD, ElementType.PARAMETER})
@Retention(RetentionPolicy.RUNTIME)
public @interface NotWeakPassword {
    String message() default "Password is too common or easily guessable";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}
