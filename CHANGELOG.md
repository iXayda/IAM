# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added

- Spring Boot 4.1 application baseline with Java 21 and GraalVM Native Image support.
- Health endpoints, Prometheus metrics, OpenTelemetry tracing, and an optional local LGTM stack.
- PostgreSQL service connections and Flyway-managed schema lifecycle.
- Tenant-scoped organization schema and database isolation constraints.
- Tenant-scoped organization membership schema with database-enforced parent ownership.
- Validated organization membership lifecycle model with soft removal and reactivation.
- Validated organization domain model and tenant-scoped lifecycle contract.
- Transactional organization lifecycle operations with active-tenant enforcement and optimistic concurrency.
- Tenant-scoped user directory schema with unified login identifier uniqueness.
- Validated username, email, and phone login identifier rules.
- Type-independent canonical login keys for tenant-scoped lookup.
- Immutable user creation requests with unambiguous login identifiers.
- UUID-backed user identities.
- User lifecycle model with explicit state transitions and monotonic timestamps.
- Tenant-scoped user operations contract and application module boundary.
- Tenant-scoped JDBC user lookup by ID and canonical login key.
- Transactional JDBC user creation with PII-safe login conflict handling.
- Tenant-scoped JDBC user status updates with optimistic concurrency.
- Transactional user lifecycle operations with active-tenant enforcement.
- Tenant-scoped current password credential schema for local users.
- Tenant-scoped local password setting and verification with adaptive hash upgrades.
- Atomic local password login with generic failures and fixed-lifetime session issuance.
- Non-bearer user session metadata with tenant and user lifecycle-version snapshots.
- Transactional tenant lifecycle operations with optimistic concurrency and a protected built-in default tenant.
- Validated tenant domain model and lifecycle contract.

### Fixed

- GraalVM native application startup.
- Concurrent user status commands now converge without an unexpected transaction rollback.
- Login identifier normalization and database validation for phone formatting and login timestamps.
- Deterministic login keys for phone-like usernames and printable email identifiers.

### Security

- Suppressed PostgreSQL server error details that may contain bound login identifiers.
