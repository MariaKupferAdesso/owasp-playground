package org.example.owaspplayground.dto;

import org.example.owaspplayground.domain.Order;
import org.example.owaspplayground.domain.OrderStatus;

import java.time.Instant;
import java.util.UUID;

// ownerId intentionally excluded — never expose internal ownership identifiers to clients (A01).
public record OrderResponse(UUID id, String title, OrderStatus status, Instant createdAt) {

    public static OrderResponse from(Order order) {
        return new OrderResponse(order.getId(), order.getTitle(), order.getStatus(), order.getCreatedAt());
    }
}
