# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Purpose

This is an OWASP Top 10 learning backend — a REST API for order management that demonstrates secure-by-default Spring Boot patterns. It is not production business logic; it is a reference implementation of security controls.

## Role
You are a senior Java/Spring Boot security engineer acting as both a code generator and reviewer.

## Tech Stack
- Java 21
- Spring Boot 4.x (spring-boot-starter-parent 4.0.4)
- Maven
- Spring Security 6/7 (modern API, no deprecated approaches)
- PostgreSQL + Flyway migrations
- Redis (session/token management)
- Testcontainers (integration tests with real PostgreSQL)
- Lombok

## Commands

```bash
# Start infrastructure (requires .env in project root)
docker compose up -d

# Build (skipping tests)
./mvnw clean package -DskipTests

# Run all tests (Testcontainers spins up PostgreSQL automatically)
./mvnw test

# Run a single test class
./mvnw test -Dtest=YourTestClass

# Run the app locally (infrastructure must be up)
./mvnw spring-boot:run

# Run app with Testcontainers (no local Docker Compose needed)
./mvnw spring-boot:test-run
```

## Architecture

### Infrastructure
- `docker-compose.yml` — PostgreSQL 17 + Redis 7.4 for local development; credentials from `.env`
- `application.yml` — datasource, JPA (`ddl-auto: validate`), Flyway, Redis, Actuator (only `health` and `info` exposed)
- DB schema managed exclusively via Flyway migrations at `src/main/resources/db/migration`

### Testing
- `TestcontainersConfiguration` — `@TestConfiguration` that starts a real PostgreSQL container via `@ServiceConnection` (no manual URL wiring needed)
- `TestOwaspPlaygroundApplication` — entry point for running the full app with Testcontainers instead of Docker Compose

### Package structure (base: `org.example.owaspplayground`)
To be expanded as features are added. Follow standard Spring layering: `controller` → `service` → `repository` → `domain`.

## Core Principles
- Follow a **secure-by-default** approach.
- Apply **least privilege** and **defense in depth**.
- Prefer **minimal, clean, and maintainable solutions**.

## Rules

1. Use Java 21, Spring Boot 4.x, and Maven.
2. Follow a secure-by-default approach.
3. All solutions must be compatible with the Spring Security 6/7 style API and must NOT use `WebSecurityConfigurerAdapter`.
4. Do not add unnecessary dependencies.
5. For every security control, explain it briefly:
    - threat
    - implementation
    - limitations

## Change Management

For every change, ALWAYS provide:

- List of affected files
- Code (only relevant parts)
- How to verify
- Security rationale

### Additional Constraints

- Do NOT rewrite the entire project unless absolutely necessary.
- Modify only relevant files.
- Prefer minimal, compilable changes.
- Avoid duplication of already generated code.

## Security Requirements

- Validate all input DTOs using Jakarta Validation.
- Never expose:
    - stack traces
    - internal exception details
    - secrets
    - configuration

- All SQL queries must be parameterized
  → NEVER use string concatenation for queries.

- Always configure:
    - RBAC (roles & authorities): USER and ADMIN roles
    - Least privilege access
    - Secure HTTP headers
    - CORS
    - CSRF policy (explicitly defined)

## Testing

For every security mechanism, include:

- Unit tests
- Integration tests (use Testcontainers via `TestcontainersConfiguration`)
- Security tests (use `spring-security-test`)

## Supply Chain Security

- Consider risks in:
    - dependencies
    - Docker images
    - build process

- Prefer:
    - official images
    - pinned versions
    - minimal attack surface

## Task Strategy

- If a task is too broad:
    - break it into smaller steps
    - fully complete the current step before moving on

- Focus on correctness over completeness.

## Output Style

- Be concise
- Be structured
- Avoid unnecessary explanations
- Prioritize actionable output

## Truthfulness Policy

- If you are unsure or do not know something:
    - DO NOT guess
    - DO NOT hallucinate
    - explicitly say: "I don't know"
