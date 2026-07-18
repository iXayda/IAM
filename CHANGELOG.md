# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added

- SCIM 2.0 service provider, schema, and resource type discovery with protocol errors and Native Image verification.
- Atomic tenant-scoped direct-user group memberships with lifecycle cleanup and directory revision tracking.
- Tenant-scoped directory groups with non-unique display names, optimistic updates, and soft deletion.
- Structured user profiles with independent directory and security revisions.
- Tenant-bound local password login for authorization requests with CSRF protection and issuer-bound redirects.
- Encrypted current refresh-token persistence with atomic access, refresh, and ID token rotation.
- Explicit confidential-client Refresh Token grants with PKCE, scope reduction, forced rotation, and owner lifecycle enforcement.
- Explicit OAuth 2.0 and OpenID Connect endpoint security with public provider metadata and JWK discovery.
- Tenant-owned web OAuth client constraints for identifiers, HTTPS callbacks, scopes, secrets, and token lifetimes.
- Tenant-scoped OAuth client persistence with global client identifiers, one-time secret issuance, encoded secret storage, and optimistic lifecycle updates.
- Spring Security Authorization Server client mapping with active-tenant filtering and safe secret-hash upgrades.
- Tenant-bound OAuth authorization, protected token, and consent persistence schema.
- JDBC-backed OAuth authorization and consent services with encrypted tokens, tenant-aware owner checks, and optimistic state transitions.
- Fixed authorization-server issuer and persistent RSA-3072 signing keys with encrypted private material and restart-stable key IDs.
- GitHub Actions release verification and Linux Native artifacts.
- Production configuration, backup, rollback, and pilot acceptance guidance.
- Automated release verification for tests, Native Image, schema state, OAuth/OIDC flows, probes, dependency recovery, and graceful shutdown.
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
- OAuth consent approval and denial now update consent and pending authorization state atomically.
- Database health checks now use bounded connection, validation, and socket waits.
- GraalVM native application startup.
- GraalVM native images now retain runtime LDAP configuration when the provider is disabled during the build.
- Concurrent user status commands now converge without an unexpected transaction rollback.
- Login identifier normalization and database validation for phone formatting and login timestamps.
- Deterministic login keys for phone-like usernames and printable email identifiers.

### Security

- Render authorization consent through a state-validated, context-escaped page with CSRF-protected, concurrency-safe denial.
- Reject unsupported, repeated, or empty authorization request parameters before client and redirect processing.
- Deny unmatched application requests while keeping health probes and Prometheus metrics explicitly accessible.
- Bound local observability, PostgreSQL, and Redis ports to the loopback interface.
- Suppressed PostgreSQL server error details that may contain bound login identifiers.
