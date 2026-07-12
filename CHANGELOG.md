# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added

- Spring Boot 4.1 application baseline with Java 21 and GraalVM Native Image support.
- Health endpoints, Prometheus metrics, OpenTelemetry tracing, and an optional local LGTM stack.
- PostgreSQL service connections and Flyway-managed schema lifecycle.
- Tenant-scoped organization schema and database isolation constraints.
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
- Transactional tenant lifecycle operations with optimistic concurrency and a protected built-in default tenant.
- Validated tenant domain model and lifecycle contract.

### Fixed

- GraalVM native application startup.
- Login identifier normalization and database validation for phone formatting and login timestamps.
- Deterministic login keys for phone-like usernames and printable email identifiers.
