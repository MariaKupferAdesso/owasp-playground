package org.example.owaspplayground.domain;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

// Ownership stored as ownerId (UUID) to avoid lazy-loading issues in stateless service layer.
// The DB FK constraint on user_id still enforces referential integrity.
@Entity
@Table(name = "orders")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Order {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    // FK reference stored as plain UUID — avoids @ManyToOne lazy-load issues in stateless context
    @Column(name = "user_id", nullable = false, updatable = false)
    private UUID ownerId;

    @Column(nullable = false)
    private String title;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private OrderStatus status;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @PrePersist
    void prePersist() {
        if (createdAt == null) {
            createdAt = Instant.now();
        }
        if (status == null) {
            status = OrderStatus.PENDING;
        }
    }
}
