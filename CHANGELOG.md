# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added

- Spring Boot 4.1 application baseline with Java 21 and GraalVM Native Image support.
- Health endpoints, Prometheus metrics, OpenTelemetry tracing, and an optional local LGTM stack.
- PostgreSQL service connections and Flyway-managed schema lifecycle.
- Transactional tenant lifecycle operations with optimistic concurrency and a protected built-in default tenant.
- Validated tenant domain model and lifecycle contract.

### Fixed

- GraalVM native application startup.
