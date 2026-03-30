-- V1: Users and Orders schema
-- Demonstrates A01 Broken Access Control: ownership is enforced at DB + service level.

CREATE TABLE IF NOT EXISTS app_user (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username      VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role          VARCHAR(20)  NOT NULL DEFAULT 'USER',
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS orders (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID         NOT NULL REFERENCES app_user(id),
    title      VARCHAR(255) NOT NULL,
    status     VARCHAR(20)  NOT NULL DEFAULT 'PENDING',
    created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- Index to efficiently query orders by owner (ownership check, IDOR prevention)
CREATE INDEX IF NOT EXISTS idx_orders_user_id ON orders(user_id);
