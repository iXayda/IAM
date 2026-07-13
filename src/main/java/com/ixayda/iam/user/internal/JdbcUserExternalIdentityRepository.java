package com.ixayda.iam.user.internal;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.ExternalIdentityProviderId;
import com.ixayda.iam.user.ExternalSubjectId;
import com.ixayda.iam.user.UserExternalIdentity;
import com.ixayda.iam.user.UserId;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.IllegalTransactionStateException;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronizationManager;

@Repository
class JdbcUserExternalIdentityRepository {

	private static final String COLUMNS = "tenant_id, provider_id, subject_id, user_id, linked_at";

	private static final RowMapper<UserExternalIdentity> ROW_MAPPER =
			JdbcUserExternalIdentityRepository::mapIdentity;

	private final JdbcClient jdbcClient;

	JdbcUserExternalIdentityRepository(JdbcClient jdbcClient) {
		this.jdbcClient = jdbcClient;
	}

	@Transactional(propagation = Propagation.MANDATORY,
			noRollbackFor = { ExternalSubjectAlreadyLinkedException.class, UserProviderAlreadyLinkedException.class })
	UserExternalIdentity insert(UserExternalIdentity identity) {
		Objects.requireNonNull(identity, "External identity must not be null");
		requireWriteTransaction();

		int affected = this.jdbcClient.sql("""
				INSERT INTO user_external_identities
				    (tenant_id, provider_id, subject_id, user_id, linked_at)
				VALUES
				    (:tenantId, :providerId, :subjectId, :userId, :linkedAt)
				ON CONFLICT DO NOTHING
				""")
			.param("tenantId", identity.tenantId().value())
			.param("providerId", identity.providerId().value())
			.param("subjectId", identity.subjectId().value())
			.param("userId", identity.userId().value())
			.param("linkedAt", databaseValue(identity.linkedAt()))
			.update();
		if (affected == 0) {
			throwClassifiedConflict(identity);
		}
		if (affected != 1) {
			throw new IllegalStateException(
					"Creating an external identity mapping affected an unexpected number of rows: " + affected);
		}
		return identity;
	}

	private void throwClassifiedConflict(UserExternalIdentity identity) {
		// Under PostgreSQL READ COMMITTED, these statements see the committed winner
		// after ON CONFLICT has waited for a concurrent unique-key insertion.
		if (findBySubject(identity.tenantId(), identity.providerId(), identity.subjectId()).isPresent()) {
			throw new ExternalSubjectAlreadyLinkedException(identity.tenantId(), identity.providerId());
		}
		if (findByUserAndProvider(identity.tenantId(), identity.userId(), identity.providerId()).isPresent()) {
			throw new UserProviderAlreadyLinkedException(identity.tenantId(), identity.providerId(), identity.userId());
		}
		throw new IllegalStateException("External identity conflict could not be classified");
	}

	Optional<UserExternalIdentity> findBySubject(TenantId tenantId, ExternalIdentityProviderId providerId,
			ExternalSubjectId subjectId) {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		Objects.requireNonNull(providerId, "External identity provider ID must not be null");
		Objects.requireNonNull(subjectId, "External subject ID must not be null");
		return this.jdbcClient.sql("SELECT " + COLUMNS
				+ " FROM user_external_identities WHERE tenant_id = :tenantId"
				+ " AND provider_id = :providerId AND subject_id = :subjectId")
			.param("tenantId", tenantId.value())
			.param("providerId", providerId.value())
			.param("subjectId", subjectId.value())
			.query(ROW_MAPPER)
			.optional();
	}

	Optional<UserExternalIdentity> findByUserAndProvider(TenantId tenantId, UserId userId,
			ExternalIdentityProviderId providerId) {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		Objects.requireNonNull(userId, "User ID must not be null");
		Objects.requireNonNull(providerId, "External identity provider ID must not be null");
		return this.jdbcClient.sql("SELECT " + COLUMNS
				+ " FROM user_external_identities WHERE tenant_id = :tenantId"
				+ " AND user_id = :userId AND provider_id = :providerId")
			.param("tenantId", tenantId.value())
			.param("userId", userId.value())
			.param("providerId", providerId.value())
			.query(ROW_MAPPER)
			.optional();
	}

	private static UserExternalIdentity mapIdentity(ResultSet resultSet, int rowNumber) throws SQLException {
		return new UserExternalIdentity(new TenantId(resultSet.getObject("tenant_id", UUID.class)),
				new ExternalIdentityProviderId(resultSet.getString("provider_id")),
				new ExternalSubjectId(resultSet.getString("subject_id")),
				new UserId(resultSet.getObject("user_id", UUID.class)),
				resultSet.getObject("linked_at", OffsetDateTime.class).toInstant());
	}

	private static OffsetDateTime databaseValue(Instant instant) {
		return OffsetDateTime.ofInstant(instant, ZoneOffset.UTC);
	}

	private static void requireWriteTransaction() {
		if (!TransactionSynchronizationManager.isActualTransactionActive()
				|| TransactionSynchronizationManager.isCurrentTransactionReadOnly()) {
			throw new IllegalTransactionStateException(
					"External identity write requires an existing read-write transaction");
		}
	}

}
