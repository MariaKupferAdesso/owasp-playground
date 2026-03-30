package org.example.owaspplayground.exception;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.server.ResponseStatusException;

import java.util.stream.Collectors;

import static org.springframework.http.HttpHeaders.RETRY_AFTER;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(LoginLockedException.class)
    public ResponseEntity<ErrorResponse> handleLoginLocked(LoginLockedException ex) {
        return ResponseEntity.status(429)
                .header(RETRY_AFTER, String.valueOf(ex.getRetryAfter().toSeconds()))
                .body(ErrorResponse.of(429, "Too Many Requests", "Account temporarily locked due to too many failed login attempts"));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleValidation(MethodArgumentNotValidException ex) {
        var fieldErrors = ex.getBindingResult().getFieldErrors().stream()
                .map(fe -> fe.getField() + ": " + fe.getDefaultMessage())
                .sorted()
                .collect(Collectors.joining(", "));
        return ResponseEntity.badRequest()
                .body(ErrorResponse.of(400, "Validation Failed", fieldErrors));
    }

    // Propagates the HTTP status from ResponseStatusException — used by services for 401/403/404.
    // Must be declared before the generic handler to take precedence.
    @ExceptionHandler(ResponseStatusException.class)
    public ResponseEntity<ErrorResponse> handleResponseStatus(ResponseStatusException ex) {
        int status = ex.getStatusCode().value();
        // Reason phrase is safe to forward; it is set explicitly in service code.
        return ResponseEntity.status(status)
                .body(ErrorResponse.of(status, ex.getStatusCode().toString(), ex.getReason()));
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ErrorResponse> handleAccessDenied(AccessDeniedException ex) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(ErrorResponse.of(403, "Forbidden", "Access denied"));
    }

    // Malformed request body (invalid JSON, wrong type, missing quotes, etc.) → 400.
    // Without this handler Spring returns its own error structure, breaking the consistent ErrorResponse contract.
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ErrorResponse> handleNotReadable(HttpMessageNotReadableException ex) {
        // ex.getMessage() can expose internal parser details — log it, never forward it.
        log.debug("Malformed request body: {}", ex.getMessage());
        return ResponseEntity.badRequest()
                .body(ErrorResponse.of(400, "Bad Request", "Malformed or unreadable request body"));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleGeneric(Exception ex) {
        // Log with stack trace so unexpected failures leave an audit trail (A09).
        // ex.getMessage() is intentionally not forwarded to the caller — avoids leaking
        // internal details such as SQL state, class names, or file paths (A05/A09).
        log.error("Unhandled exception: {}", ex.getMessage(), ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ErrorResponse.of(500, "Internal Server Error", "An unexpected error occurred"));
    }
}
