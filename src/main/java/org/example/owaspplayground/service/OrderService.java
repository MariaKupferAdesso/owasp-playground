package org.example.owaspplayground.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.owaspplayground.domain.Order;
import org.example.owaspplayground.dto.CreateOrderRequest;
import org.example.owaspplayground.dto.OrderResponse;
import org.example.owaspplayground.repository.OrderRepository;
import org.example.owaspplayground.security.JwtPrincipal;
import org.example.owaspplayground.security.LogSanitizer;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class OrderService {

    private final OrderRepository orderRepository;

    /**
     * Returns only the caller's own orders — prevents horizontal privilege escalation (A01).
     * Server-side filter: the userId comes from the verified JWT, not from request parameters.
     */
    @Transactional(readOnly = true)
    public List<OrderResponse> getMyOrders(UUID ownerId) {
        return orderRepository.findByOwnerId(ownerId).stream()
                .map(OrderResponse::from)
                .toList();
    }

    /**
     * IDOR prevention: the repository query includes ownerId so a USER cannot fetch another
     * user's order by guessing its UUID. ADMIN bypass is handled explicitly.
     *
     * Threat: A01 — insecure direct object reference via predictable or guessable order IDs.
     * Implementation: combined id+ownerId lookup for USER; full lookup for ADMIN only.
     * Limitation: relies on caller supplying the correct principal from SecurityContext.
     */
    @Transactional(readOnly = true)
    public OrderResponse getOrderById(UUID orderId, JwtPrincipal principal) {
        if (principal.isAdmin()) {
            return orderRepository.findById(orderId)
                    .map(OrderResponse::from)
                    .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Order not found"));
        }

        // For non-ADMIN: only succeed if the order belongs to the caller.
        // If the order exists but belongs to someone else, we return 403 and log the attempt.
        boolean orderExists = orderRepository.existsById(orderId);
        if (!orderExists) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Order not found");
        }

        return orderRepository.findByIdAndOwnerId(orderId, principal.userId())
                .map(OrderResponse::from)
                .orElseThrow(() -> {
                    log.warn("IDOR attempt: user '{}' ({}) tried to access order {} owned by another user",
                            LogSanitizer.s(principal.username()), principal.userId(), orderId);
                    return new ResponseStatusException(HttpStatus.FORBIDDEN, "Access denied");
                });
    }

    @Transactional
    public OrderResponse createOrder(CreateOrderRequest request, UUID ownerId) {
        // ownerId is taken from the JWT principal — clients cannot self-assign a different owner.
        Order order = Order.builder()
                .ownerId(ownerId)
                .title(request.title())
                .build();
        return OrderResponse.from(orderRepository.save(order));
    }

    /** Admin-only: returns all orders across all users. */
    @Transactional(readOnly = true)
    public List<OrderResponse> getAllOrders() {
        return orderRepository.findAll().stream()
                .map(OrderResponse::from)
                .toList();
    }
}
