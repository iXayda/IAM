# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added

- Tenant-owned web OAuth client constraints for identifiers, HTTPS callbacks, scopes, secrets, and token lifetimes.
- GitHub Actions release verification and Linux Native artifacts.
- Production configuration, backup, rollback, and pilot acceptance guidance.
- Automated release verification for tests, Native Image, schema state, probes, dependency recovery, and graceful shutdown.
- Spring Boot 4.1 application baseline with Java 21 and GraalVM Native Image support.
- Health and root probe endpoints, tagged HTTP latency histograms, trace-correlated logs, sampled exemplars, and an optional local LGTM stack.
- Prometheus alerts for availability, HTTP errors and latency, Redis-backed security dependencies, and login throttling surges.
- PostgreSQL service connections and Flyway-managed schema lifecycle.
- Redis service connections for local development and integration testing.
- Tenant-scoped organization schema and database isolation constraints.
- Tenant-scoped organization membership schema with database-enforced parent ownership.
- Validated organization membership lifecycle model with soft removal and reactivation.
- Transactional membership addition and checks with active-parent guards, plus soft removal after parent deactivation.
- Validated organization domain model and tenant-scoped lifecycle contract.
- Transactional organization lifecycle operations with active-tenant enforcement and optimistic concurrency.
- Tenant-scoped user directory schema with unified login identifier uniqueness.
- Tenant-scoped external identity mapping schema with explicit provider and subject ownership.
- Validated external identity mapping model with redacted subject diagnostics.
- Transactional external identity linking and tenant-scoped mapping lookup with active tenant and user guards.
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
- Provider-neutral external credential verification contract with opaque subject identifiers and redacted diagnostics.
- Disabled-by-default LDAP credential provider configuration with secure transport validation and explicit tenant allowlisting.
- LDAP external credential verification with unique directory lookup, user bind authentication, and outcome metrics.
- Redis-backed atomic login-attempt limits with privacy-preserving keys and bounded failure handling.
- Redis login-attempt enforcement for local password authentication with explicit throttled and unavailable outcomes.
- Redis-backed one-time security state with tenant binding, atomic consumption, and bounded expiry.
- Non-bearer user session metadata with tenant and user lifecycle-version snapshots.
- Transactional tenant lifecycle operations with optimistic concurrency and a protected built-in default tenant.
- Validated tenant domain model and lifecycle contract.

### Fixed

- Database health checks now use bounded connection, validation, and socket waits.
- GraalVM native application startup.
- GraalVM native images now retain runtime LDAP configuration when the provider is disabled during the build.
- Concurrent user status commands now converge without an unexpected transaction rollback.
- Login identifier normalization and database validation for phone formatting and login timestamps.
- Deterministic login keys for phone-like usernames and printable email identifiers.

### Security

- Bound local observability, PostgreSQL, and Redis ports to the loopback interface.
- Suppressed PostgreSQL server error details that may contain bound login identifiers.
