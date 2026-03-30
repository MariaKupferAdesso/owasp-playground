package org.example.owaspplayground.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/** Demonstrates publicly accessible endpoints (no authentication required). */
@RestController
@RequestMapping("/api/public")
public class PublicController {

    @GetMapping("/status")
    public Map<String, String> status() {
        return Map.of("status", "UP", "service", "owasp-playground");
    }
}
