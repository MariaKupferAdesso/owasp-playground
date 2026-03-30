package org.example.owaspplayground.security;

/**
 * Threat: A09 — log injection via newline/carriage-return characters in user-controlled values.
 *   An attacker who registers as "admin\nINFO: Login successful for admin" can forge log entries,
 *   obscure audit trails, or exploit log-parsing pipelines.
 * Implementation: strips CR, LF, tab, and other ASCII control characters (0x00–0x1F, 0x7F)
 *   before the value reaches the log statement. Each offending character is replaced with '_'
 *   to preserve length and avoid masking the original value entirely.
 * Limitation: does not strip ANSI escape sequences — if the log viewer renders ANSI codes
 *   a separate stripping step would be needed.
 */
public final class LogSanitizer {

    private LogSanitizer() {}

    /**
     * Sanitizes a user-controlled string for safe inclusion in log statements.
     * Returns {@code "(null)"} for null input so callers can always log the result directly.
     */
    public static String s(String value) {
        if (value == null) return "(null)";
        return value.replaceAll("[\\r\\n\\t\\x00-\\x1F\\x7F]", "_");
    }
}
