package org.example.owaspplayground.repository;

import org.example.owaspplayground.domain.Order;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface OrderRepository extends JpaRepository<Order, UUID> {

    // Used to retrieve only the authenticated user's orders (prevents data leakage)
    List<Order> findByOwnerId(UUID ownerId);

    // Combined lookup: only succeeds when both ID and owner match — prevents IDOR
    Optional<Order> findByIdAndOwnerId(UUID id, UUID ownerId);
}
