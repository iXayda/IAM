package com.ixayda.iam.user;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import com.ixayda.iam.ApplicationIntegrationTest;
import com.ixayda.iam.tenant.CreateTenantRequest;
import com.ixayda.iam.tenant.Tenant;
import com.ixayda.iam.tenant.TenantDisabledException;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.tenant.TenantOperations;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

class UserExternalIdentityOperationsIntegrationTests extends ApplicationIntegrationTest {

	private static final ExternalIdentityProviderId PROVIDER_ID =
			ExternalIdentityProviderId.from("corporate");

	private static final ExternalIdentityProviderId SECOND_PROVIDER_ID =
			ExternalIdentityProviderId.from("partner");

	private static final ExternalSubjectId SUBJECT_ID = ExternalSubjectId.from("subject-a");

	private static final ExternalSubjectId SECOND_SUBJECT_ID = ExternalSubjectId.from("subject-b");

	private final List<UserReference> usersToDelete = new ArrayList<>();

	private final List<TenantId> tenantsToDelete = new ArrayList<>();

	@Autowired
	private UserExternalIdentityOperations identities;

	@Autowired
	private UserOperations users;

	@Autowired
	private TenantOperations tenants;

	@Autowired
	private JdbcClient jdbcClient;

	@Autowired
	private PlatformTransactionManager transactionManager;

	@AfterEach
	void deleteFixtures() {
		this.usersToDelete.forEach(reference -> {
			this.jdbcClient.sql("""
					DELETE FROM user_external_identities
					WHERE tenant_id = :tenantId AND user_id = :userId
					""")
				.param("tenantId", reference.tenantId().value())
				.param("userId", reference.userId().value())
				.update();
			this.jdbcClient.sql("""
					DELETE FROM user_login_identifiers
					WHERE tenant_id = :tenantId AND user_id = :userId
					""")
				.param("tenantId", reference.tenantId().value())
				.param("userId", reference.userId().value())
				.update();
			this.jdbcClient.sql("DELETE FROM users WHERE tenant_id = :tenantId AND user_id = :userId")
				.param("tenantId", reference.tenantId().value())
				.param("userId", reference.userId().value())
				.update();
		});
		this.tenantsToDelete.reversed().forEach(tenantId -> this.jdbcClient
			.sql("DELETE FROM tenants WHERE tenant_id = :tenantId")
			.param("tenantId", tenantId.value())
			.update());
	}

	@Test
	void linksAndFindsMappingsIdempotently() {
		User user = createUser(TenantId.DEFAULT, "lifecycle");

		UserExternalIdentity linked =
				this.identities.link(TenantId.DEFAULT, user.id(), PROVIDER_ID, SUBJECT_ID);

		assertThat(linked.tenantId()).isEqualTo(TenantId.DEFAULT);
		assertThat(linked.userId()).isEqualTo(user.id());
		assertThat(linked.providerId()).isEqualTo(PROVIDER_ID);
		assertThat(linked.subjectId()).isEqualTo(SUBJECT_ID);
		assertThat(this.identities.findBySubject(TenantId.DEFAULT, PROVIDER_ID, SUBJECT_ID)).contains(linked);
		assertThat(this.identities.findByUserAndProvider(TenantId.DEFAULT, user.id(), PROVIDER_ID)).contains(linked);
		assertThat(this.identities.findBySubject(TenantId.random(), PROVIDER_ID, SUBJECT_ID)).isEmpty();
		assertThat(this.identities.findBySubject(TenantId.DEFAULT, SECOND_PROVIDER_ID, SUBJECT_ID)).isEmpty();

		UserExternalIdentity retried =
				this.identities.link(TenantId.DEFAULT, user.id(), PROVIDER_ID, SUBJECT_ID);
		assertThat(retried).isEqualTo(linked);
		assertThat(retried.linkedAt()).isEqualTo(linked.linkedAt());
		assertThat(identityCount(TenantId.DEFAULT, PROVIDER_ID)).isOne();
	}

	@Test
	void rejectsMissingInactiveAndCrossTenantUsersAndDisabledTenants() {
		User disabled = createUser(TenantId.DEFAULT, "disabled");
		User locked = createUser(TenantId.DEFAULT, "locked");
		User deleted = createUser(TenantId.DEFAULT, "deleted");
		this.users.disable(TenantId.DEFAULT, disabled.id());
		this.users.lock(TenantId.DEFAULT, locked.id());
		this.users.delete(TenantId.DEFAULT, deleted.id());

		assertInactiveUser(disabled.id(), ExternalSubjectId.from("disabled-subject"));
		assertInactiveUser(locked.id(), ExternalSubjectId.from("locked-subject"));
		assertInactiveUser(deleted.id(), ExternalSubjectId.from("deleted-subject"));
		assertThatThrownBy(() -> this.identities.link(TenantId.DEFAULT, UserId.random(), PROVIDER_ID,
				ExternalSubjectId.from("missing-subject"))).isInstanceOf(UserNotFoundException.class);

		Tenant secondTenant = createTenant("cross-tenant");
		User secondTenantUser = createUser(secondTenant.id(), "cross-tenant");
		assertThatThrownBy(() -> this.identities.link(TenantId.DEFAULT, secondTenantUser.id(), PROVIDER_ID,
				ExternalSubjectId.from("cross-tenant-subject"))).isInstanceOf(UserNotFoundException.class);

		Tenant disabledTenant = createTenant("disabled-tenant");
		User disabledTenantUser = createUser(disabledTenant.id(), "disabled-tenant");
		this.tenants.disable(disabledTenant.id());
		assertThatThrownBy(() -> this.identities.link(disabledTenant.id(), disabledTenantUser.id(), PROVIDER_ID,
				ExternalSubjectId.from("disabled-tenant-subject")))
			.isInstanceOf(TenantDisabledException.class);

		assertThat(identityCount(TenantId.DEFAULT, PROVIDER_ID)).isZero();
		assertThat(identityCount(disabledTenant.id(), PROVIDER_ID)).isZero();
	}

	@Test
	void rawLookupsRetainMappingsAfterLifecycleDeactivationButRelinkingRemainsBlocked() {
		Tenant tenant = createTenant("retained");
		User user = createUser(tenant.id(), "retained");
		UserExternalIdentity linked = this.identities.link(tenant.id(), user.id(), PROVIDER_ID, SUBJECT_ID);

		this.users.disable(tenant.id(), user.id());
		this.tenants.disable(tenant.id());

		assertThat(this.identities.findBySubject(tenant.id(), PROVIDER_ID, SUBJECT_ID)).contains(linked);
		assertThat(this.identities.findByUserAndProvider(tenant.id(), user.id(), PROVIDER_ID)).contains(linked);
		assertThatThrownBy(() -> this.identities.link(tenant.id(), user.id(), PROVIDER_ID, SUBJECT_ID))
			.isInstanceOf(TenantDisabledException.class);
	}

	@Test
	void exposesOneGenericConflictForEveryOwnershipCollision() {
		User first = createUser(TenantId.DEFAULT, "conflict-first");
		User second = createUser(TenantId.DEFAULT, "conflict-second");
		this.identities.link(TenantId.DEFAULT, first.id(), PROVIDER_ID, SUBJECT_ID);

		assertGenericConflict(second.id(), SUBJECT_ID);
		assertGenericConflict(first.id(), SECOND_SUBJECT_ID);

		this.identities.link(TenantId.DEFAULT, second.id(), PROVIDER_ID, SECOND_SUBJECT_ID);
		assertGenericConflict(second.id(), SUBJECT_ID);
		assertThat(identityCount(TenantId.DEFAULT, PROVIDER_ID)).isEqualTo(2);
	}

	@Test
	void participatesInCallerRollback() {
		User user = createUser(TenantId.DEFAULT, "rollback");

		transactionTemplate().executeWithoutResult(status -> {
			this.identities.link(TenantId.DEFAULT, user.id(), PROVIDER_ID, SUBJECT_ID);
			status.setRollbackOnly();
		});

		assertThat(this.identities.findBySubject(TenantId.DEFAULT, PROVIDER_ID, SUBJECT_ID)).isEmpty();
	}

	@Test
	void neverFallsBackToMatchingLocalLoginValues() {
		User user = createUserWithUsername(TenantId.DEFAULT, SUBJECT_ID.value());

		assertThat(this.users.findByLogin(TenantId.DEFAULT, LoginKey.from(SUBJECT_ID.value()))).contains(user);
		assertThat(this.identities.findBySubject(TenantId.DEFAULT, PROVIDER_ID, SUBJECT_ID)).isEmpty();
		assertThat(this.identities.findByUserAndProvider(TenantId.DEFAULT, user.id(), PROVIDER_ID)).isEmpty();
		assertThat(identityCount(TenantId.DEFAULT, PROVIDER_ID)).isZero();
	}

	private void assertInactiveUser(UserId userId, ExternalSubjectId subjectId) {
		assertThatThrownBy(() -> this.identities.link(TenantId.DEFAULT, userId, PROVIDER_ID, subjectId))
			.isInstanceOf(UserNotActiveException.class);
		assertThat(this.identities.findBySubject(TenantId.DEFAULT, PROVIDER_ID, subjectId)).isEmpty();
	}

	private void assertGenericConflict(UserId attemptedUserId, ExternalSubjectId attemptedSubjectId) {
		ExternalIdentityLinkConflictException conflict = catchThrowableOfType(
				ExternalIdentityLinkConflictException.class,
				() -> this.identities.link(TenantId.DEFAULT, attemptedUserId, PROVIDER_ID, attemptedSubjectId));

		assertThat(conflict.tenantId()).isEqualTo(TenantId.DEFAULT);
		assertThat(conflict.userId()).isEqualTo(attemptedUserId);
		assertThat(conflict.providerId()).isEqualTo(PROVIDER_ID);
		assertThat(conflict).hasNoCause();
		assertThat(conflict.getMessage()).doesNotContain(SUBJECT_ID.value(), SECOND_SUBJECT_ID.value());
	}

	private Tenant createTenant(String purpose) {
		String suffix = UUID.randomUUID().toString().substring(0, 8);
		Tenant tenant = this.tenants.create(
				new CreateTenantRequest("external-identity-" + purpose + "-" + suffix, "External Identity " + purpose));
		this.tenantsToDelete.add(tenant.id());
		return tenant;
	}

	private User createUser(TenantId tenantId, String purpose) {
		String suffix = UUID.randomUUID().toString().substring(0, 8);
		return createUserWithUsername(tenantId, "external-identity-" + purpose + "-" + suffix);
	}

	private User createUserWithUsername(TenantId tenantId, String username) {
		User user = this.users.create(tenantId,
				new CreateUserRequest(List.of(LoginIdentifier.username(username))));
		this.usersToDelete.add(new UserReference(tenantId, user.id()));
		return user;
	}

	private int identityCount(TenantId tenantId, ExternalIdentityProviderId providerId) {
		return this.jdbcClient.sql("""
				SELECT count(*) FROM user_external_identities
				WHERE tenant_id = :tenantId AND provider_id = :providerId
				""")
			.param("tenantId", tenantId.value())
			.param("providerId", providerId.value())
			.query(Integer.class)
			.single();
	}

	private TransactionTemplate transactionTemplate() {
		return new TransactionTemplate(this.transactionManager);
	}

	private record UserReference(TenantId tenantId, UserId userId) {
	}

}
