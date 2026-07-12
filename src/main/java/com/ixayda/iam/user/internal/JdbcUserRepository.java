package com.ixayda.iam.user.internal;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.LoginIdentifier;
import com.ixayda.iam.user.LoginIdentifierType;
import com.ixayda.iam.user.LoginKey;
import com.ixayda.iam.user.User;
import com.ixayda.iam.user.UserId;
import com.ixayda.iam.user.UserStatus;
import org.springframework.jdbc.core.ResultSetExtractor;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

@Repository
class JdbcUserRepository {

	private static final ResultSetExtractor<Optional<User>> USER_EXTRACTOR = JdbcUserRepository::extractUser;

	private static final String FIND_BY_ID = """
			SELECT u.user_id,
			       u.tenant_id,
			       u.status,
			       u.version,
			       u.created_at,
			       u.updated_at,
			       u.last_login_at,
			       i.identifier_type,
			       i.identifier_value,
			       i.canonical_value
			FROM users u
			LEFT JOIN user_login_identifiers i
			  ON i.tenant_id = u.tenant_id
			 AND i.user_id = u.user_id
			WHERE u.tenant_id = :tenantId
			  AND u.user_id = :userId
			ORDER BY CASE i.identifier_type
			             WHEN 'username' THEN 0
			             WHEN 'email' THEN 1
			             WHEN 'phone' THEN 2
			             ELSE 3
			         END
			""";

	private static final String FIND_BY_LOGIN = """
			SELECT u.user_id,
			       u.tenant_id,
			       u.status,
			       u.version,
			       u.created_at,
			       u.updated_at,
			       u.last_login_at,
			       i.identifier_type,
			       i.identifier_value,
			       i.canonical_value
			FROM user_login_identifiers matched
			JOIN users u
			  ON u.tenant_id = matched.tenant_id
			 AND u.user_id = matched.user_id
			JOIN user_login_identifiers i
			  ON i.tenant_id = u.tenant_id
			 AND i.user_id = u.user_id
			WHERE matched.tenant_id = :tenantId
			  AND matched.canonical_value = :canonicalValue
			ORDER BY CASE i.identifier_type
			             WHEN 'username' THEN 0
			             WHEN 'email' THEN 1
			             WHEN 'phone' THEN 2
			             ELSE 3
			         END
			""";

	private final JdbcClient jdbcClient;

	JdbcUserRepository(JdbcClient jdbcClient) {
		this.jdbcClient = jdbcClient;
	}

	Optional<User> findById(TenantId tenantId, UserId userId) {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		Objects.requireNonNull(userId, "User ID must not be null");
		return this.jdbcClient.sql(FIND_BY_ID)
			.param("tenantId", tenantId.value())
			.param("userId", userId.value())
			.query(USER_EXTRACTOR);
	}

	Optional<User> findByLogin(TenantId tenantId, LoginKey loginKey) {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		Objects.requireNonNull(loginKey, "Login key must not be null");
		return this.jdbcClient.sql(FIND_BY_LOGIN)
			.param("tenantId", tenantId.value())
			.param("canonicalValue", loginKey.canonicalValue())
			.query(USER_EXTRACTOR);
	}

	private static Optional<User> extractUser(ResultSet resultSet) throws SQLException {
		if (!resultSet.next()) {
			return Optional.empty();
		}

		UserId userId = new UserId(resultSet.getObject("user_id", UUID.class));
		TenantId tenantId = new TenantId(resultSet.getObject("tenant_id", UUID.class));
		UserStatus status = status(resultSet.getString("status"));
		long version = resultSet.getLong("version");
		OffsetDateTime createdAt = resultSet.getObject("created_at", OffsetDateTime.class);
		OffsetDateTime updatedAt = resultSet.getObject("updated_at", OffsetDateTime.class);
		OffsetDateTime lastLoginAt = resultSet.getObject("last_login_at", OffsetDateTime.class);
		List<LoginIdentifier> identifiers = new ArrayList<>();

		do {
			if (!userId.value().equals(resultSet.getObject("user_id", UUID.class))
					|| !tenantId.value().equals(resultSet.getObject("tenant_id", UUID.class))) {
				throw new IllegalStateException("User lookup returned more than one tenant-scoped user");
			}
			String identifierType = resultSet.getString("identifier_type");
			if (identifierType == null) {
				throw new IllegalStateException("User has no login identifiers: " + userId);
			}
			identifiers.add(new LoginIdentifier(identifierType(identifierType),
					resultSet.getString("identifier_value"), resultSet.getString("canonical_value")));
		}
		while (resultSet.next());

		return Optional.of(new User(userId, tenantId, identifiers, status, version, createdAt.toInstant(),
				updatedAt.toInstant(), lastLoginAt == null ? null : lastLoginAt.toInstant()));
	}

	private static LoginIdentifierType identifierType(String value) {
		return switch (value) {
			case "username" -> LoginIdentifierType.USERNAME;
			case "email" -> LoginIdentifierType.EMAIL;
			case "phone" -> LoginIdentifierType.PHONE;
			default -> throw new IllegalStateException("Unsupported login identifier type in the database: " + value);
		};
	}

	private static UserStatus status(String value) {
		return switch (value) {
			case "active" -> UserStatus.ACTIVE;
			case "disabled" -> UserStatus.DISABLED;
			case "locked" -> UserStatus.LOCKED;
			case "deleted" -> UserStatus.DELETED;
			default -> throw new IllegalStateException("Unsupported user status in the database: " + value);
		};
	}

}
