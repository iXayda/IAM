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
- Transactional tenant lifecycle operations with optimistic concurrency and a protected built-in default tenant.
- Validated tenant domain model and lifecycle contract.

### Fixed

- GraalVM native application startup.
- Login identifier normalization and database validation for phone formatting and login timestamps.
