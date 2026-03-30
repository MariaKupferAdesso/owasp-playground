package org.example.owaspplayground.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.example.owaspplayground.dto.CreateOrderRequest;
import org.example.owaspplayground.dto.OrderResponse;
import org.example.owaspplayground.security.JwtPrincipal;
import org.example.owaspplayground.service.OrderService;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

/**
 * Order endpoints for authenticated users.
 *
 * Access control:
 * - GET /api/orders       → USER or ADMIN, but each sees only their own orders
 * - GET /api/orders/{id}  → ownership check in service (IDOR prevention)
 * - POST /api/orders      → USER or ADMIN; ownerId derived from JWT (not from request body)
 */
@RestController
@RequestMapping("/api/orders")
@PreAuthorize("isAuthenticated()")
@RequiredArgsConstructor
public class OrderController {

    private final OrderService orderService;

    @GetMapping
    public List<OrderResponse> getMyOrders(@AuthenticationPrincipal JwtPrincipal principal) {
        return orderService.getMyOrders(principal.userId());
    }

    @GetMapping("/{id}")
    public OrderResponse getOrder(@PathVariable UUID id,
                                  @AuthenticationPrincipal JwtPrincipal principal) {
        // Ownership check (+ IDOR protection) is delegated to the service layer.
        return orderService.getOrderById(id, principal);
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public OrderResponse createOrder(@Valid @RequestBody CreateOrderRequest request,
                                     @AuthenticationPrincipal JwtPrincipal principal) {
        // ownerId is always derived from the JWT — clients cannot assign a different owner.
        return orderService.createOrder(request, principal.userId());
    }
}
