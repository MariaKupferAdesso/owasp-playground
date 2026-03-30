package org.example.owaspplayground.controller;

import lombok.RequiredArgsConstructor;
import org.example.owaspplayground.dto.OrderResponse;
import org.example.owaspplayground.dto.UserSummary;
import org.example.owaspplayground.service.OrderService;
import org.example.owaspplayground.service.UserService;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Admin-only endpoints.
 *
 * Threat: A01 — privilege escalation; a USER accessing admin data.
 * Implementation: @PreAuthorize("hasRole('ADMIN')") enforced server-side at method level.
 *   The role is verified from the JWT claim, not from a client-supplied parameter.
 * Limitation: role changes in DB are not reflected until the JWT expires (TTL-bounded).
 */
@RestController
@RequestMapping("/api/admin")
@PreAuthorize("hasRole('ADMIN')")
@RequiredArgsConstructor
public class AdminController {

    private final OrderService orderService;
    private final UserService userService;

    /** Returns all orders across all users. ADMIN only. */
    @GetMapping("/orders")
    public List<OrderResponse> getAllOrders() {
        return orderService.getAllOrders();
    }

    /** Returns all users (password hashes excluded). ADMIN only. */
    @GetMapping("/users")
    public List<UserSummary> getAllUsers() {
        return userService.getAllUsers();
    }
}
