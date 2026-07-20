# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added

- Source-bound MFA login challenges with atomic TOTP or recovery-code completion before session creation.
- One-time recovery code generation with adaptive hashes, atomic consumption, and transaction-bound verification.
- Two-phase TOTP enrollment and verification with encrypted secrets, atomic replay prevention, key rotation, and fail-closed readiness.
- Permission-protected Admin role catalog endpoint with live RBAC authorization.
- Stateless Admin resource-server boundary with live session checks, dynamic RBAC authorities, and deny-by-default routing.
- Session-bound Admin access-token profile with an explicit scope, dedicated audience, and Refresh Token continuity.
- Transactional administrator role bootstrap, hierarchical permanent or bounded JIT grants, fail-closed effective permission resolution, and retained revocation history.
- Tenant-safe administrator RBAC schema with built-in least-privilege roles, stable permissions, and permanent or expiring user bindings.
- Tenant-scoped SCIM Group deletion with strict empty responses, atomic membership cleanup, directory revision updates, and confidential failures.
- Atomic, ordered SCIM Group PATCH operations with SDK-backed paths, bounded direct User membership changes, and confidential failures.
- Tenant-scoped SCIM Group replacement with atomic profile and direct User membership updates, canonical responses, and confidential failures.
- Tenant-scoped SCIM Group creation with atomic, bounded direct User members, canonical references, and confidential member validation.
- Tenant-scoped SCIM Group retrieval and bounded collection paging with capped direct User members, projected attributes, and exact `id` or `displayName` queries.
- Tenant-scoped SCIM User deletion with strict empty responses, lifecycle cleanup, reserved login identifiers, and tenant-safe not-found errors.
- Atomic, bounded, tenant-scoped SCIM User PATCH operations with SDK-backed paths, filtered values, and confidential protocol errors.
- Tenant-scoped SCIM User replacement with atomic identifier, profile, and active-state updates, invalidating existing sessions after identity or lifecycle changes.
- Tenant-scoped SCIM User creation with bounded writable attributes, atomic inactive provisioning, and confidential uniqueness errors.
- Tenant-scoped SCIM User collection paging with bounded, non-advertised `id` and `userName` equality queries.
- Tenant-scoped SCIM User retrieval with attribute projection, canonical metadata, and tenant-safe not-found responses.
- Dedicated SCIM service-token validation with strict tenant/client claims, bounded lifetimes, and read/write scope authorization.
- Confidential Client Credentials issuance with tenant-bound JWT claims, fixed SCIM audience, short lifetimes, and Native Image verification.
- Tenant-bound OAuth client-credentials authorization persistence with grant-specific owner, request, and token invariants.
- SCIM 2.0 service provider, User and Group schema, and resource type discovery with protocol errors and Native Image verification.
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
- Preserved the requested login identifier when applying filtered SCIM User adds instead of substituting the filter literal.
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
