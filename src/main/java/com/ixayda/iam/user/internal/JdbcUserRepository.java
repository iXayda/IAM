package com.ixayda.iam.user.internal;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.LoginIdentifier;
import com.ixayda.iam.user.LoginIdentifierType;
import com.ixayda.iam.user.LoginKey;
import com.ixayda.iam.user.User;
import com.ixayda.iam.user.UserAlreadyExistsException;
import com.ixayda.iam.user.UserConcurrentUpdateException;
import com.ixayda.iam.user.UserDirectoryQuery;
import com.ixayda.iam.user.UserId;
import com.ixayda.iam.user.UserPage;
import com.ixayda.iam.user.UserProfile;
import com.ixayda.iam.user.UserStatus;
import org.springframework.jdbc.core.ResultSetExtractor;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.IllegalTransactionStateException;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronizationManager;

@Repository
class JdbcUserRepository {

	private static final ResultSetExtractor<Optional<User>> USER_EXTRACTOR = JdbcUserRepository::extractUser;

	private static final ResultSetExtractor<UserPage> USER_PAGE_EXTRACTOR = JdbcUserRepository::extractUserPage;

	private static final String VISIBLE_USER_CONDITION = "u.status <> 'deleted'";

	private static final String NO_USERS_CONDITION = "false";

	private static final String ID_EQUALS_CONDITION = VISIBLE_USER_CONDITION + " AND u.user_id = :matchedUserId";

	private static final String USER_NAME_EQUALS_CONDITION = VISIBLE_USER_CONDITION + """
			 AND u.user_id = (
			     SELECT matched_identifier.user_id
			     FROM user_login_identifiers matched_identifier
			     WHERE matched_identifier.tenant_id = :tenantId
			       AND (
			           matched_identifier.identifier_type IN ('username', 'email')
			           AND matched_identifier.canonical_value = lower(:matchedUserName)
			           OR matched_identifier.identifier_type = 'phone'
			           AND matched_identifier.identifier_value = :matchedUserName
			       )
			       AND NOT EXISTS (
			           SELECT 1
			           FROM user_login_identifiers higher_priority
			           WHERE higher_priority.tenant_id = matched_identifier.tenant_id
			             AND higher_priority.user_id = matched_identifier.user_id
			             AND CASE higher_priority.identifier_type
			                     WHEN 'username' THEN 0
			                     WHEN 'email' THEN 1
			                     WHEN 'phone' THEN 2
			                     ELSE 3
			                 END
			                 < CASE matched_identifier.identifier_type
			                       WHEN 'username' THEN 0
			                       WHEN 'email' THEN 1
			                       WHEN 'phone' THEN 2
			                       ELSE 3
			                   END
			       )
			 )
			 """;

	private static final String FIND_BY_ID = """
			SELECT u.user_id,
			       u.tenant_id,
			       u.status,
			       u.display_name,
			       u.formatted_name,
			       u.given_name,
			       u.family_name,
			       u.version,
			       u.security_version,
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
			       u.display_name,
			       u.formatted_name,
			       u.given_name,
			       u.family_name,
			       u.version,
			       u.security_version,
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

	private static final String FIND_BY_ID_FOR_SHARE = FIND_BY_ID + "\nFOR SHARE OF u";

	private static final String FIND_BY_ID_FOR_UPDATE = FIND_BY_ID + "\nFOR UPDATE OF u";

	private final JdbcClient jdbcClient;

	JdbcUserRepository(JdbcClient jdbcClient) {
		this.jdbcClient = jdbcClient;
	}

	@Transactional(propagation = Propagation.MANDATORY)
	public User insert(User user) {
		Objects.requireNonNull(user, "User must not be null");
		requireWriteTransaction();
		int affected = this.jdbcClient.sql("""
				INSERT INTO users
				    (user_id, tenant_id, status, display_name, formatted_name, given_name, family_name,
				     version, security_version, created_at, updated_at, last_login_at)
				VALUES
				    (:userId, :tenantId, :status, :displayName, :formattedName, :givenName, :familyName,
				     :version, :securityVersion, :createdAt, :updatedAt,
				     CAST(:lastLoginAt AS timestamptz))
				""")
			.param("userId", user.id().value())
			.param("tenantId", user.tenantId().value())
			.param("status", databaseValue(user.status()))
			.param("displayName", user.profile().displayName())
			.param("formattedName", user.profile().formattedName())
			.param("givenName", user.profile().givenName())
			.param("familyName", user.profile().familyName())
			.param("version", user.version())
			.param("securityVersion", user.securityVersion())
			.param("createdAt", databaseValue(user.createdAt()))
			.param("updatedAt", databaseValue(user.updatedAt()))
			.param("lastLoginAt", databaseValue(user.lastLoginAt()))
			.update();
		if (affected != 1) {
			throw new IllegalStateException("Creating a user affected an unexpected number of rows: " + affected);
		}

		for (LoginIdentifier identifier : user.identifiers()) {
			insertIdentifier(user, identifier);
		}
		return user;
	}

	Optional<User> findById(TenantId tenantId, UserId userId) {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		Objects.requireNonNull(userId, "User ID must not be null");
		return this.jdbcClient.sql(FIND_BY_ID)
			.param("tenantId", tenantId.value())
			.param("userId", userId.value())
			.query(USER_EXTRACTOR);
	}

	UserPage findDirectoryPage(TenantId tenantId, UserDirectoryQuery query) {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		Objects.requireNonNull(query, "User directory query must not be null");
		String condition = switch (query.criterion()) {
			case UserDirectoryQuery.All ignored -> VISIBLE_USER_CONDITION;
			case UserDirectoryQuery.None ignored -> NO_USERS_CONDITION;
			case UserDirectoryQuery.IdEquals ignored -> ID_EQUALS_CONDITION;
			case UserDirectoryQuery.PrimaryIdentifierEquals ignored -> USER_NAME_EQUALS_CONDITION;
		};
		JdbcClient.StatementSpec statement = this.jdbcClient.sql(directoryPageQuery(condition))
			.param("tenantId", tenantId.value())
			.param("offset", query.offset())
			.param("limit", query.limit());
		if (query.criterion() instanceof UserDirectoryQuery.IdEquals idEquals) {
			statement = statement.param("matchedUserId", idEquals.userId().value());
		}
		else if (query.criterion() instanceof UserDirectoryQuery.PrimaryIdentifierEquals primaryIdentifierEquals) {
			statement = statement.param("matchedUserName", primaryIdentifierEquals.value());
		}
		return statement.query(USER_PAGE_EXTRACTOR);
	}

	@Transactional(propagation = Propagation.MANDATORY)
	Optional<User> findByIdForShare(TenantId tenantId, UserId userId) {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		Objects.requireNonNull(userId, "User ID must not be null");
		requireWriteTransaction();
		return this.jdbcClient.sql(FIND_BY_ID_FOR_SHARE)
			.param("tenantId", tenantId.value())
			.param("userId", userId.value())
			.query(USER_EXTRACTOR);
	}

	@Transactional(propagation = Propagation.MANDATORY)
	Optional<User> findByIdForUpdate(TenantId tenantId, UserId userId) {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		Objects.requireNonNull(userId, "User ID must not be null");
		requireWriteTransaction();
		return this.jdbcClient.sql(FIND_BY_ID_FOR_UPDATE)
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

	@Transactional(propagation = Propagation.MANDATORY, noRollbackFor = UserConcurrentUpdateException.class)
	public User updateStatus(User current, User changed) {
		Objects.requireNonNull(current, "Current user must not be null");
		Objects.requireNonNull(changed, "Changed user must not be null");
		requireWriteTransaction();
		if (!current.id().equals(changed.id()) || !current.tenantId().equals(changed.tenantId())
				|| !current.identifiers().equals(changed.identifiers())
				|| !current.profile().equals(changed.profile())
				|| !current.createdAt().equals(changed.createdAt())
				|| !Objects.equals(current.lastLoginAt(), changed.lastLoginAt()) || current.status() == changed.status()
				|| current.version() == Long.MAX_VALUE || current.securityVersion() == Long.MAX_VALUE
				|| changed.version() != current.version() + 1
				|| changed.securityVersion() != current.securityVersion() + 1
				|| changed.updatedAt().isBefore(current.updatedAt())) {
			throw new IllegalArgumentException(
					"User status update must preserve ownership and identity, and advance one version to a different status");
		}

		int affected = this.jdbcClient.sql("""
				UPDATE users
				SET status = :newStatus, version = :newVersion,
				    security_version = :newSecurityVersion, updated_at = :updatedAt
				WHERE tenant_id = :tenantId
				  AND user_id = :userId
				  AND version = :expectedVersion
				  AND security_version = :expectedSecurityVersion
				  AND status = :expectedStatus
				""")
			.param("newStatus", databaseValue(changed.status()))
			.param("newVersion", changed.version())
			.param("newSecurityVersion", changed.securityVersion())
			.param("updatedAt", databaseValue(changed.updatedAt()))
			.param("tenantId", current.tenantId().value())
			.param("userId", current.id().value())
			.param("expectedVersion", current.version())
			.param("expectedSecurityVersion", current.securityVersion())
			.param("expectedStatus", databaseValue(current.status()))
			.update();
		if (affected == 0) {
			throw new UserConcurrentUpdateException(current.tenantId(), current.id(), current.version());
		}
		if (affected != 1) {
			throw new IllegalStateException("Updating a user affected an unexpected number of rows: " + affected);
		}
		return changed;
	}

	@Transactional(propagation = Propagation.MANDATORY, noRollbackFor = UserConcurrentUpdateException.class)
	public User updateProfile(User current, User changed) {
		Objects.requireNonNull(current, "Current user must not be null");
		Objects.requireNonNull(changed, "Changed user must not be null");
		requireWriteTransaction();
		if (!current.id().equals(changed.id()) || !current.tenantId().equals(changed.tenantId())
				|| !current.identifiers().equals(changed.identifiers()) || current.profile().equals(changed.profile())
				|| current.status() != changed.status() || !current.createdAt().equals(changed.createdAt())
				|| !Objects.equals(current.lastLoginAt(), changed.lastLoginAt()) || current.version() == Long.MAX_VALUE
				|| changed.version() != current.version() + 1
				|| changed.securityVersion() != current.securityVersion()
				|| changed.updatedAt().isBefore(current.updatedAt())) {
			throw new IllegalArgumentException(
					"User profile update must preserve ownership and lifecycle state, and advance one version");
		}

		int affected = this.jdbcClient.sql("""
				UPDATE users
				SET display_name = :displayName,
				    formatted_name = :formattedName,
				    given_name = :givenName,
				    family_name = :familyName,
				    version = :newVersion,
				    updated_at = :updatedAt
				WHERE tenant_id = :tenantId
				  AND user_id = :userId
				  AND version = :expectedVersion
				  AND security_version = :expectedSecurityVersion
				  AND status = :expectedStatus
				""")
			.param("displayName", changed.profile().displayName())
			.param("formattedName", changed.profile().formattedName())
			.param("givenName", changed.profile().givenName())
			.param("familyName", changed.profile().familyName())
			.param("newVersion", changed.version())
			.param("updatedAt", databaseValue(changed.updatedAt()))
			.param("tenantId", current.tenantId().value())
			.param("userId", current.id().value())
			.param("expectedVersion", current.version())
			.param("expectedSecurityVersion", current.securityVersion())
			.param("expectedStatus", databaseValue(current.status()))
			.update();
		if (affected == 0) {
			throw new UserConcurrentUpdateException(current.tenantId(), current.id(), current.version());
		}
		if (affected != 1) {
			throw new IllegalStateException("Updating a user profile affected an unexpected number of rows: " + affected);
		}
		return changed;
	}

	@Transactional(propagation = Propagation.MANDATORY, noRollbackFor = UserConcurrentUpdateException.class)
	public User updateMemberships(User current, User changed) {
		Objects.requireNonNull(current, "Current user must not be null");
		Objects.requireNonNull(changed, "Changed user must not be null");
		requireWriteTransaction();
		if (!current.id().equals(changed.id()) || !current.tenantId().equals(changed.tenantId())
				|| !current.identifiers().equals(changed.identifiers())
				|| !current.profile().equals(changed.profile()) || current.status() != changed.status()
				|| !current.createdAt().equals(changed.createdAt())
				|| !Objects.equals(current.lastLoginAt(), changed.lastLoginAt()) || current.isDeleted()
				|| current.version() == Long.MAX_VALUE || changed.version() != current.version() + 1
				|| changed.securityVersion() != current.securityVersion()
				|| changed.updatedAt().isBefore(current.updatedAt())) {
			throw new IllegalArgumentException(
					"User membership update must preserve ownership and lifecycle state, and advance one directory version");
		}

		int affected = this.jdbcClient.sql("""
				UPDATE users
				SET version = :newVersion, updated_at = :updatedAt
				WHERE tenant_id = :tenantId
				  AND user_id = :userId
				  AND version = :expectedVersion
				  AND security_version = :expectedSecurityVersion
				  AND status = :expectedStatus
				""")
			.param("newVersion", changed.version())
			.param("updatedAt", databaseValue(changed.updatedAt()))
			.param("tenantId", current.tenantId().value())
			.param("userId", current.id().value())
			.param("expectedVersion", current.version())
			.param("expectedSecurityVersion", current.securityVersion())
			.param("expectedStatus", databaseValue(current.status()))
			.update();
		if (affected == 0) {
			throw new UserConcurrentUpdateException(current.tenantId(), current.id(), current.version());
		}
		if (affected != 1) {
			throw new IllegalStateException("Updating user memberships affected an unexpected number of rows: " + affected);
		}
		return changed;
	}

	private void insertIdentifier(User user, LoginIdentifier identifier) {
		int affected = this.jdbcClient.sql("""
				INSERT INTO user_login_identifiers
				    (tenant_id, user_id, identifier_type, identifier_value, canonical_value, created_at, updated_at)
				VALUES
				    (:tenantId, :userId, :type, :value, :canonicalValue, :createdAt, :updatedAt)
				ON CONFLICT ON CONSTRAINT user_login_identifiers_tenant_canonical_key DO NOTHING
				""")
			.param("tenantId", user.tenantId().value())
			.param("userId", user.id().value())
			.param("type", databaseValue(identifier.type()))
			.param("value", identifier.value())
			.param("canonicalValue", identifier.canonicalValue())
			.param("createdAt", databaseValue(user.createdAt()))
			.param("updatedAt", databaseValue(user.updatedAt()))
			.update();
		if (affected == 0) {
			throw new UserAlreadyExistsException(user.tenantId());
		}
		if (affected != 1) {
			throw new IllegalStateException("Creating a login identifier affected an unexpected number of rows: "
					+ affected);
		}
	}

	private static void requireWriteTransaction() {
		if (!TransactionSynchronizationManager.isActualTransactionActive()
				|| TransactionSynchronizationManager.isCurrentTransactionReadOnly()) {
			throw new IllegalTransactionStateException("User write requires an existing read-write transaction");
		}
	}

	private static Optional<User> extractUser(ResultSet resultSet) throws SQLException {
		if (!resultSet.next()) {
			return Optional.empty();
		}

		UserId userId = new UserId(resultSet.getObject("user_id", UUID.class));
		TenantId tenantId = new TenantId(resultSet.getObject("tenant_id", UUID.class));
		UserStatus status = status(resultSet.getString("status"));
		UserProfile profile = new UserProfile(resultSet.getString("display_name"),
				resultSet.getString("formatted_name"), resultSet.getString("given_name"),
				resultSet.getString("family_name"));
		long version = resultSet.getLong("version");
		long securityVersion = resultSet.getLong("security_version");
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

		return Optional.of(new User(userId, tenantId, identifiers, profile, status, version, securityVersion,
				createdAt.toInstant(), updatedAt.toInstant(), lastLoginAt == null ? null : lastLoginAt.toInstant()));
	}

	private static UserPage extractUserPage(ResultSet resultSet) throws SQLException {
		if (!resultSet.next()) {
			throw new IllegalStateException("User directory query did not return its total result row");
		}
		long totalResults = resultSet.getLong("total_results");
		Map<UserId, PageUser> pageUsers = new LinkedHashMap<>();
		do {
			if (resultSet.getObject("user_id") == null) {
				continue;
			}
			UserRow row = readUserRow(resultSet);
			PageUser pageUser = pageUsers.computeIfAbsent(row.userId(), ignored -> new PageUser(row));
			if (!pageUser.row().equals(row)) {
				throw new IllegalStateException("User directory query returned inconsistent rows for " + row.userId());
			}
			pageUser.identifiers().add(readIdentifier(resultSet, row.userId()));
		}
		while (resultSet.next());
		List<User> users = pageUsers.values().stream().map(PageUser::toUser).toList();
		return new UserPage(totalResults, users);
	}

	private static UserRow readUserRow(ResultSet resultSet) throws SQLException {
		OffsetDateTime lastLoginAt = resultSet.getObject("last_login_at", OffsetDateTime.class);
		return new UserRow(new UserId(resultSet.getObject("user_id", UUID.class)),
				new TenantId(resultSet.getObject("tenant_id", UUID.class)), status(resultSet.getString("status")),
				new UserProfile(resultSet.getString("display_name"), resultSet.getString("formatted_name"),
						resultSet.getString("given_name"), resultSet.getString("family_name")),
				resultSet.getLong("version"), resultSet.getLong("security_version"),
				resultSet.getObject("created_at", OffsetDateTime.class).toInstant(),
				resultSet.getObject("updated_at", OffsetDateTime.class).toInstant(),
				lastLoginAt == null ? null : lastLoginAt.toInstant());
	}

	private static LoginIdentifier readIdentifier(ResultSet resultSet, UserId userId) throws SQLException {
		String identifierType = resultSet.getString("identifier_type");
		if (identifierType == null) {
			throw new IllegalStateException("User has no login identifiers: " + userId);
		}
		return new LoginIdentifier(identifierType(identifierType), resultSet.getString("identifier_value"),
				resultSet.getString("canonical_value"));
	}

	private static String directoryPageQuery(String condition) {
		return """
				WITH total AS (
				    SELECT count(*) AS total_results
				    FROM users u
				    WHERE u.tenant_id = :tenantId
				      AND %1$s
				), page AS (
				    SELECT u.user_id,
				           u.tenant_id,
				           u.status,
				           u.display_name,
				           u.formatted_name,
				           u.given_name,
				           u.family_name,
				           u.version,
				           u.security_version,
				           u.created_at,
				           u.updated_at,
				           u.last_login_at
				    FROM users u
				    WHERE u.tenant_id = :tenantId
				      AND %1$s
				    ORDER BY u.user_id
				    OFFSET :offset
				    LIMIT :limit
				)
				SELECT total.total_results,
				       page.user_id,
				       page.tenant_id,
				       page.status,
				       page.display_name,
				       page.formatted_name,
				       page.given_name,
				       page.family_name,
				       page.version,
				       page.security_version,
				       page.created_at,
				       page.updated_at,
				       page.last_login_at,
				       identifier.identifier_type,
				       identifier.identifier_value,
				       identifier.canonical_value
				FROM total
				LEFT JOIN page ON true
				LEFT JOIN user_login_identifiers identifier
				  ON identifier.tenant_id = page.tenant_id
				 AND identifier.user_id = page.user_id
				ORDER BY page.user_id,
				         CASE identifier.identifier_type
				             WHEN 'username' THEN 0
				             WHEN 'email' THEN 1
				             WHEN 'phone' THEN 2
				             ELSE 3
				         END
				""".formatted(condition);
	}

	private record UserRow(UserId userId, TenantId tenantId, UserStatus status, UserProfile profile, long version,
			long securityVersion, Instant createdAt, Instant updatedAt, Instant lastLoginAt) {

		User toUser(List<LoginIdentifier> identifiers) {
			return new User(this.userId, this.tenantId, identifiers, this.profile, this.status, this.version,
					this.securityVersion, this.createdAt, this.updatedAt, this.lastLoginAt);
		}

	}

	private record PageUser(UserRow row, List<LoginIdentifier> identifiers) {

		PageUser(UserRow row) {
			this(row, new ArrayList<>());
		}

		User toUser() {
			return this.row.toUser(List.copyOf(this.identifiers));
		}

	}

	private static LoginIdentifierType identifierType(String value) {
		return switch (value) {
			case "username" -> LoginIdentifierType.USERNAME;
			case "email" -> LoginIdentifierType.EMAIL;
			case "phone" -> LoginIdentifierType.PHONE;
			default -> throw new IllegalStateException("Unsupported login identifier type in the database: " + value);
		};
	}

	private static String databaseValue(LoginIdentifierType type) {
		return switch (type) {
			case USERNAME -> "username";
			case EMAIL -> "email";
			case PHONE -> "phone";
		};
	}

	private static String databaseValue(UserStatus status) {
		return switch (status) {
			case ACTIVE -> "active";
			case DISABLED -> "disabled";
			case LOCKED -> "locked";
			case DELETED -> "deleted";
		};
	}

	private static OffsetDateTime databaseValue(Instant instant) {
		return instant == null ? null : OffsetDateTime.ofInstant(instant, ZoneOffset.UTC);
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
