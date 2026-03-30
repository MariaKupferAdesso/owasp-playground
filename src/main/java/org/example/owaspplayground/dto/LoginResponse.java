package org.example.owaspplayground.dto;

public record LoginResponse(String token, long expiresInSeconds) {}
