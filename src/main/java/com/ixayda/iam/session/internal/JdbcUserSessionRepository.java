package com.ixayda.iam.session.internal;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

import com.ixayda.iam.session.SessionAuthenticationMethod;
import com.ixayda.iam.session.SessionId;
import com.ixayda.iam.session.SessionStatus;
import com.ixayda.iam.session.UserSession;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.IllegalTransactionStateException;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronizationManager;

@Repository
class JdbcUserSessionRepository {

	private static final String COLUMNS = "session_id, tenant_id, user_id, authentication_method, status, "
			+ "issued_tenant_version, issued_user_version, version, authenticated_at, updated_at, expires_at, revoked_at";

	private static final RowMapper<UserSession> ROW_MAPPER = JdbcUserSessionRepository::mapSession;

	private final JdbcClient jdbcClient;

	JdbcUserSessionRepository(JdbcClient jdbcClient) {
		this.jdbcClient = jdbcClient;
	}

	@Transactional(propagation = Propagation.MANDATORY, noRollbackFor = UserSessionAlreadyExistsException.class)
	UserSession insert(UserSession session) {
		Objects.requireNonNull(session, "User session must not be null");
		requireWriteTransaction();
		if (session.status() != SessionStatus.ACTIVE || session.version() != 0
				|| !session.authenticatedAt().equals(session.updatedAt()) || session.revokedAt() != null) {
			throw new IllegalArgumentException(
					"New user session must be active at version zero and start at its authentication time");
		}

		int affected = this.jdbcClient.sql("""
				INSERT INTO user_sessions
				    (session_id, tenant_id, user_id, authentication_method, status,
				     issued_tenant_version, issued_user_version, version,
				     authenticated_at, updated_at, expires_at, revoked_at)
				VALUES
				    (:sessionId, :tenantId, :userId, :authenticationMethod, :status,
				     :issuedTenantVersion, :issuedUserVersion, :version,
				     :authenticatedAt, :updatedAt, :expiresAt, CAST(:revokedAt AS timestamptz))
				ON CONFLICT (session_id) DO NOTHING
				""")
			.param("sessionId", session.id().value())
			.param("tenantId", session.tenantId().value())
			.param("userId", session.userId().value())
			.param("authenticationMethod", databaseValue(session.authenticationMethod()))
			.param("status", databaseValue(session.status()))
			.param("issuedTenantVersion", session.issuedTenantVersion())
			.param("issuedUserVersion", session.issuedUserVersion())
			.param("version", session.version())
			.param("authenticatedAt", databaseValue(session.authenticatedAt()))
			.param("updatedAt", databaseValue(session.updatedAt()))
			.param("expiresAt", databaseValue(session.expiresAt()))
			.param("revokedAt", databaseValue(session.revokedAt()))
			.update();
		if (affected == 0) {
			throw new UserSessionAlreadyExistsException(session.tenantId(), session.id());
		}
		if (affected != 1) {
			throw new IllegalStateException("Creating a user session affected an unexpected number of rows: " + affected);
		}
		return session;
	}

	Optional<UserSession> findById(TenantId tenantId, SessionId sessionId) {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		Objects.requireNonNull(sessionId, "Session ID must not be null");
		return this.jdbcClient.sql("SELECT " + COLUMNS
				+ " FROM user_sessions WHERE tenant_id = :tenantId AND session_id = :sessionId")
			.param("tenantId", tenantId.value())
			.param("sessionId", sessionId.value())
			.query(ROW_MAPPER)
			.optional();
	}

	@Transactional(propagation = Propagation.MANDATORY,
			noRollbackFor = UserSessionConcurrentUpdateException.class)
	UserSession update(UserSession current, UserSession changed) {
		Objects.requireNonNull(current, "Current user session must not be null");
		Objects.requireNonNull(changed, "Changed user session must not be null");
		requireWriteTransaction();
		if (!current.id().equals(changed.id()) || !current.tenantId().equals(changed.tenantId())
				|| !current.userId().equals(changed.userId())
				|| current.authenticationMethod() != changed.authenticationMethod()
				|| current.issuedTenantVersion() != changed.issuedTenantVersion()
				|| current.issuedUserVersion() != changed.issuedUserVersion()
				|| !current.authenticatedAt().equals(changed.authenticatedAt())
				|| !current.expiresAt().equals(changed.expiresAt()) || current.status() != SessionStatus.ACTIVE
				|| changed.status() != SessionStatus.REVOKED || current.version() == Long.MAX_VALUE
				|| changed.version() != current.version() + 1 || changed.updatedAt().isBefore(current.updatedAt())
				|| !changed.updatedAt().equals(changed.revokedAt())) {
			throw new IllegalArgumentException(
					"User session update must preserve identity and issuance state, and revoke exactly one version");
		}

		int affected = this.jdbcClient.sql("""
				UPDATE user_sessions
				SET status = :newStatus,
				    version = :newVersion,
				    updated_at = :updatedAt,
				    revoked_at = :revokedAt
				WHERE tenant_id = :tenantId
				  AND session_id = :sessionId
				  AND user_id = :expectedUserId
				  AND authentication_method = :expectedAuthenticationMethod
				  AND issued_tenant_version = :expectedTenantVersion
				  AND issued_user_version = :expectedUserVersion
				  AND authenticated_at = :expectedAuthenticatedAt
				  AND updated_at = :expectedUpdatedAt
				  AND expires_at = :expectedExpiresAt
				  AND version = :expectedVersion
				  AND status = :expectedStatus
				  AND revoked_at IS NULL
				""")
			.param("newStatus", databaseValue(changed.status()))
			.param("newVersion", changed.version())
			.param("updatedAt", databaseValue(changed.updatedAt()))
			.param("revokedAt", databaseValue(changed.revokedAt()))
			.param("tenantId", current.tenantId().value())
			.param("sessionId", current.id().value())
			.param("expectedUserId", current.userId().value())
			.param("expectedAuthenticationMethod", databaseValue(current.authenticationMethod()))
			.param("expectedTenantVersion", current.issuedTenantVersion())
			.param("expectedUserVersion", current.issuedUserVersion())
			.param("expectedAuthenticatedAt", databaseValue(current.authenticatedAt()))
			.param("expectedUpdatedAt", databaseValue(current.updatedAt()))
			.param("expectedExpiresAt", databaseValue(current.expiresAt()))
			.param("expectedVersion", current.version())
			.param("expectedStatus", databaseValue(current.status()))
			.update();
		if (affected == 0) {
			throw new UserSessionConcurrentUpdateException(current.tenantId(), current.id(), current.version());
		}
		if (affected != 1) {
			throw new IllegalStateException("Updating a user session affected an unexpected number of rows: " + affected);
		}
		return changed;
	}

	private static UserSession mapSession(ResultSet resultSet, int rowNumber) throws SQLException {
		OffsetDateTime revokedAt = resultSet.getObject("revoked_at", OffsetDateTime.class);
		return new UserSession(new SessionId(resultSet.getObject("session_id", UUID.class)),
				new TenantId(resultSet.getObject("tenant_id", UUID.class)),
				new UserId(resultSet.getObject("user_id", UUID.class)),
				authenticationMethod(resultSet.getString("authentication_method")),
				status(resultSet.getString("status")), resultSet.getLong("issued_tenant_version"),
				resultSet.getLong("issued_user_version"), resultSet.getLong("version"),
				resultSet.getObject("authenticated_at", OffsetDateTime.class).toInstant(),
				resultSet.getObject("updated_at", OffsetDateTime.class).toInstant(),
				resultSet.getObject("expires_at", OffsetDateTime.class).toInstant(),
				revokedAt == null ? null : revokedAt.toInstant());
	}

	private static String databaseValue(SessionAuthenticationMethod method) {
		return switch (method) {
			case PASSWORD -> "password";
		};
	}

	private static String databaseValue(SessionStatus status) {
		return switch (status) {
			case ACTIVE -> "active";
			case REVOKED -> "revoked";
		};
	}

	private static OffsetDateTime databaseValue(Instant instant) {
		return instant == null ? null : OffsetDateTime.ofInstant(instant, ZoneOffset.UTC);
	}

	private static SessionAuthenticationMethod authenticationMethod(String value) {
		return switch (value) {
			case "password" -> SessionAuthenticationMethod.PASSWORD;
			default -> throw new IllegalStateException(
					"Unsupported session authentication method in the database: " + value);
		};
	}

	private static SessionStatus status(String value) {
		return switch (value) {
			case "active" -> SessionStatus.ACTIVE;
			case "revoked" -> SessionStatus.REVOKED;
			default -> throw new IllegalStateException("Unsupported session status in the database: " + value);
		};
	}

	private static void requireWriteTransaction() {
		if (!TransactionSynchronizationManager.isActualTransactionActive()
				|| TransactionSynchronizationManager.isCurrentTransactionReadOnly()) {
			throw new IllegalTransactionStateException("User session write requires an existing read-write transaction");
		}
	}

}
