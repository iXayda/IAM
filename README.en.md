# IAM

[简体中文](README.md) | English

IAM is an identity and access management project for a single organization and its applications. It lets applications share accounts and sign-in, with centralized management of users, application roles, sessions, and security audits.

The project provides the IAM backend. A separate identity frontend implements login and administration interactions. Business applications connect through OIDC and manage their own pages and application sessions.

## Use cases

- Share accounts and single sign-on across applications operated by your organization.
- Centrally manage user activation, account disabling, password recovery, and application access.
- View and revoke sessions, and trace security-sensitive operations.

IAM manages accounts, authentication, and application-level authorization. Each application enforces permissions for its own business objects and operations.

## Development and runtime

The project uses Spring Boot 4.1.1, Java 21, and PostgreSQL 18. Builds require JDK 21 and use the included Maven Wrapper. Integration tests start isolated PostgreSQL containers through Docker and require a working Docker installation.

Run the tests and build an executable JAR:

```bash
./mvnw clean verify
```

Before starting the application, configure a dedicated PostgreSQL database and HTTPS:

| Environment variable | Purpose |
| --- | --- |
| `SPRING_DATASOURCE_URL` | PostgreSQL JDBC connection URL |
| `SPRING_DATASOURCE_USERNAME` | Database username |
| `SPRING_DATASOURCE_PASSWORD` | Database password, supplied by the runtime environment |
| `SERVER_SSL_ENABLED` | `true` for IAM TLS; `false` for HTTP upstream connections from a trusted TLS proxy |
| `SERVER_SSL_KEY_STORE` | Required for IAM TLS; keystore location, such as `file:/run/secrets/iam.p12` |
| `SERVER_SSL_KEY_STORE_PASSWORD` | Required for IAM TLS; keystore password, supplied by the runtime environment |
| `SERVER_FORWARD_HEADERS_STRATEGY` | Defaults to `NONE`; use `NATIVE` for trusted proxies |
| `SERVER_TOMCAT_REMOTEIP_INTERNAL_PROXIES` | Required with `NATIVE`; a regular expression matching actual proxy source IPs |
| `IAM_TOTP_KEY_FILE` | Required when TOTP is enabled; path to an external protection key file containing 32 raw binary bytes |
| `IAM_SIGNING_KEY_FILE` | Protection key file for the signing private key, containing 32 raw binary bytes; use a different key from the TOTP protection key |
| `IAM_PROTOCOL_ISSUER` | Required when protocol endpoints are enabled; an explicit HTTPS root URL (port and trailing `/` allowed), never inferred from the request Host or proxy headers |
| `IAM_PROTOCOL_IDENTITY_FRONTEND_URI` | Required for browser authorization navigation; a fixed HTTPS identity frontend URL on the same origin as the issuer, without a query string or fragment |
| `IAM_AUTHORIZATION_KEY_FILE` | Required when protocol endpoints are enabled; path to a separate authorization state protection file containing 64 raw binary bytes, kept separately from the signing and TOTP protection keys |

Use a dedicated IAM database with separate owner and restricted runtime accounts. Migrations, administrator initialization, and deployment maintenance use the owner connection; the web service uses the runtime account. Supply each set of credentials separately so that the running service does not hold the maintenance password. Keep protection keys persistent and restrict read access. Do not commit them to the repository or regenerate them on every startup.

As a database administrator, create the roles and database in a controlled `psql` session. Set passwords interactively with `\password`:

```sql
CREATE ROLE iam_owner LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
\password iam_owner
CREATE ROLE iam_runtime LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
\password iam_runtime
CREATE DATABASE iam OWNER iam_owner;
```

In the maintenance environment, supply the JDBC connection for `iam_owner` and the persistent signing and TOTP protection files. Run migrations, initialize the signing identity, and bootstrap the administrator in order. These commands run independently without an HTTP listener:

```bash
java -jar target/iam.jar migrate
java -jar target/iam.jar initialize-signing-key
java -jar target/iam.jar bootstrap-admin
```

Before administrator initialization, an organization-authorized operator verifies the account holder's identity and arranges for them to use a controlled, real interactive terminal. Follow the prompts to create an account or select an existing active account, verify the password, and enroll and verify TOTP. Passwords and codes are entered without echo; additional arguments and piped input are not accepted. Do not record the screen or collect terminal output. Securely save the recovery codes when they are shown once. Initialization can complete only once and can resume after interruption. Repeating it after completion cannot restore privileges or retrieve recovery codes.

Apply the runtime privilege script through the owner's `psql` connection. Provide credentials through a protected password file or deployment secret management. The following command uses the configured `PGHOST`, `PGPORT`, `PGDATABASE`, and `PGUSER`:

```bash
psql -X --set=runtime_role=iam_runtime --set=iam_schema=public --file=deploy/postgresql/grant-runtime.sql
```

The script explicitly grants the permissions needed by the application; new tables receive no automatic grants. The runtime account cannot create tables, run migrations, modify or delete audit records, change administrator privileges or signing keys, own database objects, or escalate privileges. The default schema is `public`. See [database installation and upgrades](docs/operations.md#数据库安装与升级) for custom schema configuration and upgrades.

The public entry point uses HTTPS, terminated by IAM or a trusted proxy. Forwarded headers are ignored by default; HTTP upstream connections require explicit proxy trust and network access restricted to those proxies. Switch to a runtime environment containing only the `iam_runtime` credentials. The `runtime` profile disables startup migrations and checks the database identity before opening the listener. Startup is rejected if the owner account is used or the runtime account has excessive privileges on protected tables:

```bash
java -jar target/iam.jar --spring.profiles.active=runtime
```

### Container runtime

Configure the JVM image through `.env`:

```bash
# Copy the configuration example
cp .env.example .env
# Configure .env using its comments, then start the service
docker compose up -d
```

## Application integration

There are no default accounts or public registration endpoints. Users are created through an authorized process. The organization verifies each person's identity and delivers a one-time setup credential; the user sets a password before signing in.

The identity frontend calls IAM over same-origin HTTPS, using session cookies and CSRF protection. Frontend and backend may be deployed separately, but browsers must use one fixed origin. Proxies may use verified HTTPS upstream connections, or explicitly trusted HTTP connections over a protected internal network. Cross-origin credentialed access is not enabled.

IAM and application sessions are managed separately. An IAM session cannot serve as an access token for business APIs. OpenAPI describes API fields, request examples, responses, and errors; see the [integration guide](docs/integration.md) for flows across requests.

The [application examples](examples/oidc/README.md) provide two standalone Node.js 22 confidential web/BFF clients and resource services, demonstrating authorization code flow with S256 PKCE, SSO, and online authorization validation. Each application must enforce its own operation-level and object ownership checks. The [browser verification guide](tests/browser/README.md) explains how to run scenarios in an isolated environment.

## API documentation tools

springdoc generates the API specification from controllers and DTOs, with additional descriptions for login, logout, and protocol endpoints handled by Spring Security filters. Documentation endpoints are disabled by default. After configuring the database and HTTPS, enable the `documentation` profile to export the specification:

```bash
java -jar target/iam.jar --spring.profiles.active=runtime,documentation
```

Use a valid session to read `/v3/api-docs` (JSON) or `/v3/api-docs.yaml` (YAML). Export the specification locally, then validate and view it with the [standalone preview tool](tools/swagger/README.md).

## Operations

The main HTTPS port exposes unauthenticated `GET /livez` and `GET /readyz` endpoints that return only the overall status. Liveness checks the process; readiness checks the database, required auditing, authorization protection configuration, and signing material. Unavailable checks return 503. See the [operations guide](docs/operations.md) for troubleshooting, administrator recovery, and key maintenance.

Back up the database together with its matching signing, TOTP, and authorization protection files. To recover, stop the service and restore into a new, empty database. Quarantine security state, verify the administrator again, and complete controlled release before reopening access. Do not reconnect an old snapshot directly to the web service. See the [backup and recovery guide](docs/backup-recovery.md).

## Support and maintenance

Report usage issues and improvement suggestions through [GitHub Issues](https://github.com/iXayda/IAM/issues). The project is maintained by ka1i. Contact: <iXayda@outlook.com>.

For vulnerabilities, follow the [security policy](SECURITY.md). Read the [contribution guide](CONTRIBUTING.md) before contributing.

## License

Unless otherwise stated, this project is licensed under the [Apache License 2.0](LICENSE). The [Code of Conduct](CODE_OF_CONDUCT.md) is licensed under CC BY-SA 4.0.
