package com.ixayda.iam.user.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

import java.time.Instant;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import com.ixayda.iam.ApplicationIntegrationTest;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.ExternalIdentityProviderId;
import com.ixayda.iam.user.ExternalSubjectId;
import com.ixayda.iam.user.UserExternalIdentity;
import com.ixayda.iam.user.UserId;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.transaction.IllegalTransactionStateException;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

class JdbcUserExternalIdentityRepositoryIntegrationTests extends ApplicationIntegrationTest {

	private static final TenantId SECOND_TENANT_ID =
			TenantId.from("019bc1e7-14d1-7d38-bd23-0877f2cd0e81");

	private static final UserId USER_ID = UserId.from("019bc1e7-14d1-7d38-bd23-0877f2cd0e82");

	private static final UserId SAME_TENANT_USER_ID =
			UserId.from("019bc1e7-14d1-7d38-bd23-0877f2cd0e83");

	private static final UserId SECOND_TENANT_USER_ID =
			UserId.from("019bc1e7-14d1-7d38-bd23-0877f2cd0e84");

	private static final ExternalIdentityProviderId PROVIDER_ID =
			ExternalIdentityProviderId.from("corporate");

	private static final ExternalIdentityProviderId SECOND_PROVIDER_ID =
			ExternalIdentityProviderId.from("partner");

	private static final ExternalSubjectId SUBJECT_ID = ExternalSubjectId.from("subject-a");

	private static final ExternalSubjectId SECOND_SUBJECT_ID = ExternalSubjectId.from("subject-b");

	private static final Instant LINKED_AT = Instant.parse("2026-01-01T00:00:00Z");

	@Autowired
	private JdbcUserExternalIdentityRepository repository;

	@Autowired
	private JdbcClient jdbcClient;

	@Autowired
	private PlatformTransactionManager transactionManager;

	@BeforeEach
	void createParents() {
		this.jdbcClient.sql("""
				INSERT INTO tenants (tenant_id, slug, display_name)
				VALUES (:tenantId, 'external-identity-store', 'External Identity Store')
				""")
			.param("tenantId", SECOND_TENANT_ID.value())
			.update();
		insertUser(TenantId.DEFAULT, USER_ID);
		insertUser(TenantId.DEFAULT, SAME_TENANT_USER_ID);
		insertUser(SECOND_TENANT_ID, SECOND_TENANT_USER_ID);
	}

	@AfterEach
	void deleteFixtures() {
		this.jdbcClient.sql("""
				DELETE FROM user_external_identities
				WHERE user_id IN (:userId, :sameTenantUserId, :secondTenantUserId)
				""")
			.param("userId", USER_ID.value())
			.param("sameTenantUserId", SAME_TENANT_USER_ID.value())
			.param("secondTenantUserId", SECOND_TENANT_USER_ID.value())
			.update();
		this.jdbcClient.sql("""
				DELETE FROM users
				WHERE user_id IN (:userId, :sameTenantUserId, :secondTenantUserId)
				""")
			.param("userId", USER_ID.value())
			.param("sameTenantUserId", SAME_TENANT_USER_ID.value())
			.param("secondTenantUserId", SECOND_TENANT_USER_ID.value())
			.update();
		this.jdbcClient.sql("DELETE FROM tenants WHERE tenant_id = :tenantId")
			.param("tenantId", SECOND_TENANT_ID.value())
			.update();
	}

	@Test
	void storesAndFindsTenantScopedMappingsByBothUniqueKeys() {
		UserExternalIdentity first = identity(TenantId.DEFAULT, PROVIDER_ID, SUBJECT_ID, USER_ID);
		UserExternalIdentity second =
				identity(SECOND_TENANT_ID, PROVIDER_ID, SUBJECT_ID, SECOND_TENANT_USER_ID);

		assertThat(insert(first)).isSameAs(first);
		assertThat(this.repository.findBySubject(TenantId.DEFAULT, PROVIDER_ID, SUBJECT_ID)).contains(first);
		assertThat(this.repository.findByUserAndProvider(TenantId.DEFAULT, USER_ID, PROVIDER_ID)).contains(first);
		assertThat(this.repository.findBySubject(SECOND_TENANT_ID, PROVIDER_ID, SUBJECT_ID)).isEmpty();
		assertThat(this.repository.findBySubject(TenantId.DEFAULT, SECOND_PROVIDER_ID, SUBJECT_ID)).isEmpty();
		assertThat(this.repository.findBySubject(TenantId.DEFAULT, PROVIDER_ID, SECOND_SUBJECT_ID)).isEmpty();
		assertThat(this.repository.findByUserAndProvider(TenantId.DEFAULT, SAME_TENANT_USER_ID, PROVIDER_ID))
			.isEmpty();

		insert(second);
		assertThat(this.repository.findBySubject(SECOND_TENANT_ID, PROVIDER_ID, SUBJECT_ID)).contains(second);
		assertThat(this.repository
			.findByUserAndProvider(SECOND_TENANT_ID, SECOND_TENANT_USER_ID, PROVIDER_ID)).contains(second);
	}

	@Test
	void allowsTheSameSubjectAndUserInDifferentProviderNamespaces() {
		UserExternalIdentity first = identity(TenantId.DEFAULT, PROVIDER_ID, SUBJECT_ID, USER_ID);
		UserExternalIdentity second = identity(TenantId.DEFAULT, SECOND_PROVIDER_ID, SUBJECT_ID, USER_ID);

		insert(first);
		insert(second);

		assertThat(this.repository.findBySubject(TenantId.DEFAULT, PROVIDER_ID, SUBJECT_ID)).contains(first);
		assertThat(this.repository.findBySubject(TenantId.DEFAULT, SECOND_PROVIDER_ID, SUBJECT_ID)).contains(second);
	}

	@Test
	void classifiesUniqueConflictsWithoutAbortingTheCallerTransactionOrExposingSubjects() {
		UserExternalIdentity original = identity(TenantId.DEFAULT, PROVIDER_ID, SUBJECT_ID, USER_ID);
		UserExternalIdentity exactDuplicate = identity(TenantId.DEFAULT, PROVIDER_ID, SUBJECT_ID, USER_ID);
		UserExternalIdentity subjectOnlyConflict =
				identity(TenantId.DEFAULT, PROVIDER_ID, SUBJECT_ID, SAME_TENANT_USER_ID);
		UserExternalIdentity userOnlyConflict =
				identity(TenantId.DEFAULT, PROVIDER_ID, SECOND_SUBJECT_ID, USER_ID);
		UserExternalIdentity secondMapping =
				identity(TenantId.DEFAULT, PROVIDER_ID, SECOND_SUBJECT_ID, SAME_TENANT_USER_ID);
		UserExternalIdentity bothConstraintsConflict =
				identity(TenantId.DEFAULT, PROVIDER_ID, SUBJECT_ID, SAME_TENANT_USER_ID);

		transactionTemplate().executeWithoutResult(status -> {
			this.repository.insert(original);
			assertSubjectConflict(exactDuplicate);
			assertSubjectConflict(subjectOnlyConflict);
			assertUserProviderConflict(userOnlyConflict);
			this.repository.insert(secondMapping);
			assertSubjectConflict(bothConstraintsConflict);
			assertThat(this.repository.findBySubject(TenantId.DEFAULT, PROVIDER_ID, SUBJECT_ID)).contains(original);
			assertThat(this.repository.findBySubject(TenantId.DEFAULT, PROVIDER_ID, SECOND_SUBJECT_ID))
				.contains(secondMapping);
		});

		assertThat(this.repository.findBySubject(TenantId.DEFAULT, PROVIDER_ID, SUBJECT_ID)).contains(original);
		assertThat(this.repository.findBySubject(TenantId.DEFAULT, PROVIDER_ID, SECOND_SUBJECT_ID))
			.contains(secondMapping);
	}

	@Test
	void classifiesConcurrentSubjectAndUserProviderRaces() throws Exception {
		UserExternalIdentity subjectWinner = identity(TenantId.DEFAULT, PROVIDER_ID, SUBJECT_ID, USER_ID);
		UserExternalIdentity subjectLoser =
				identity(TenantId.DEFAULT, PROVIDER_ID, SUBJECT_ID, SAME_TENANT_USER_ID);

		assertThat(raceWhileWinnerIsUncommitted(subjectWinner, subjectLoser))
			.isEqualTo(AttemptResult.SUBJECT_CONFLICT);
		assertThat(this.repository.findBySubject(TenantId.DEFAULT, PROVIDER_ID, SUBJECT_ID))
			.contains(subjectWinner);
		assertThat(identityCount(PROVIDER_ID)).isOne();

		UserExternalIdentity userProviderWinner =
				identity(TenantId.DEFAULT, SECOND_PROVIDER_ID, SUBJECT_ID, USER_ID);
		UserExternalIdentity userProviderLoser =
				identity(TenantId.DEFAULT, SECOND_PROVIDER_ID, SECOND_SUBJECT_ID, USER_ID);

		assertThat(raceWhileWinnerIsUncommitted(userProviderWinner, userProviderLoser))
			.isEqualTo(AttemptResult.USER_PROVIDER_CONFLICT);
		assertThat(this.repository.findByUserAndProvider(TenantId.DEFAULT, USER_ID, SECOND_PROVIDER_ID))
			.contains(userProviderWinner);
		assertThat(identityCount(SECOND_PROVIDER_ID)).isOne();
	}

	@Test
	void participatesInCallerRollback() {
		UserExternalIdentity identity = identity(TenantId.DEFAULT, PROVIDER_ID, SUBJECT_ID, USER_ID);

		transactionTemplate().executeWithoutResult(status -> {
			this.repository.insert(identity);
			status.setRollbackOnly();
		});

		assertThat(this.repository.findBySubject(TenantId.DEFAULT, PROVIDER_ID, SUBJECT_ID)).isEmpty();
	}

	@Test
	void requiresAnExistingReadWriteTransaction() {
		UserExternalIdentity identity = identity(TenantId.DEFAULT, PROVIDER_ID, SUBJECT_ID, USER_ID);

		assertThatThrownBy(() -> this.repository.insert(identity))
			.isInstanceOf(IllegalTransactionStateException.class);
		TransactionTemplate readOnly = transactionTemplate();
		readOnly.setReadOnly(true);
		assertThatThrownBy(() -> readOnly.execute(status -> this.repository.insert(identity)))
			.isInstanceOf(IllegalTransactionStateException.class)
			.hasMessage("External identity write requires an existing read-write transaction");
		assertThat(this.repository.findBySubject(TenantId.DEFAULT, PROVIDER_ID, SUBJECT_ID)).isEmpty();
	}

	@Test
	void rejectsNullRepositoryArguments() {
		assertThatThrownBy(() -> transactionTemplate().execute(status -> this.repository.insert(null)))
			.isInstanceOf(NullPointerException.class);
		assertThatThrownBy(() -> this.repository.findBySubject(null, PROVIDER_ID, SUBJECT_ID))
			.isInstanceOf(NullPointerException.class);
		assertThatThrownBy(() -> this.repository.findBySubject(TenantId.DEFAULT, null, SUBJECT_ID))
			.isInstanceOf(NullPointerException.class);
		assertThatThrownBy(() -> this.repository.findBySubject(TenantId.DEFAULT, PROVIDER_ID, null))
			.isInstanceOf(NullPointerException.class);
		assertThatThrownBy(() -> this.repository.findByUserAndProvider(null, USER_ID, PROVIDER_ID))
			.isInstanceOf(NullPointerException.class);
		assertThatThrownBy(() -> this.repository.findByUserAndProvider(TenantId.DEFAULT, null, PROVIDER_ID))
			.isInstanceOf(NullPointerException.class);
		assertThatThrownBy(() -> this.repository.findByUserAndProvider(TenantId.DEFAULT, USER_ID, null))
			.isInstanceOf(NullPointerException.class);
	}

	private void assertSubjectConflict(UserExternalIdentity identity) {
		ExternalSubjectAlreadyLinkedException conflict = catchThrowableOfType(
				ExternalSubjectAlreadyLinkedException.class, () -> this.repository.insert(identity));

		assertThat(conflict.tenantId()).isEqualTo(TenantId.DEFAULT);
		assertThat(conflict.providerId()).isEqualTo(PROVIDER_ID);
		assertThat(conflict).hasNoCause();
		assertThat(conflict.getMessage()).doesNotContain(SUBJECT_ID.value(), SECOND_SUBJECT_ID.value());
	}

	private void assertUserProviderConflict(UserExternalIdentity identity) {
		UserProviderAlreadyLinkedException conflict = catchThrowableOfType(
				UserProviderAlreadyLinkedException.class, () -> this.repository.insert(identity));

		assertThat(conflict.tenantId()).isEqualTo(TenantId.DEFAULT);
		assertThat(conflict.providerId()).isEqualTo(PROVIDER_ID);
		assertThat(conflict.userId()).isEqualTo(identity.userId());
		assertThat(conflict).hasNoCause();
		assertThat(conflict.getMessage()).doesNotContain(SUBJECT_ID.value(), SECOND_SUBJECT_ID.value());
	}

	private AttemptResult raceWhileWinnerIsUncommitted(UserExternalIdentity winner, UserExternalIdentity loser)
			throws Exception {
		CountDownLatch winnerInserted = new CountDownLatch(1);
		CountDownLatch releaseWinner = new CountDownLatch(1);
		CountDownLatch loserStarted = new CountDownLatch(1);
		AtomicInteger loserBackendId = new AtomicInteger();
		try (ExecutorService executor = Executors.newFixedThreadPool(2)) {
			Future<UserExternalIdentity> winnerResult = executor.submit(() -> transactionTemplate().execute(status -> {
				UserExternalIdentity inserted = this.repository.insert(winner);
				winnerInserted.countDown();
				await(releaseWinner, "Timed out holding an uncommitted external identity insert");
				return inserted;
			}));
			Future<AttemptResult> loserResult;
			try {
				assertThat(winnerInserted.await(5, TimeUnit.SECONDS)).isTrue();
				loserResult = executor.submit(() -> attemptInsert(loser, loserBackendId, loserStarted));
				assertThat(loserStarted.await(5, TimeUnit.SECONDS)).isTrue();
				assertThat(waitUntilBlocked(loserBackendId.get())).isTrue();
			}
			finally {
				releaseWinner.countDown();
			}

			assertThat(winnerResult.get(5, TimeUnit.SECONDS)).isSameAs(winner);
			return loserResult.get(5, TimeUnit.SECONDS);
		}
	}

	private AttemptResult attemptInsert(UserExternalIdentity identity, AtomicInteger backendIdHolder,
			CountDownLatch started) {
		try {
			return transactionTemplate().execute(status -> {
				backendIdHolder.set(backendId());
				started.countDown();
				this.repository.insert(identity);
				return AttemptResult.INSERTED;
			});
		}
		catch (ExternalSubjectAlreadyLinkedException exception) {
			return AttemptResult.SUBJECT_CONFLICT;
		}
		catch (UserProviderAlreadyLinkedException exception) {
			return AttemptResult.USER_PROVIDER_CONFLICT;
		}
	}

	private UserExternalIdentity insert(UserExternalIdentity identity) {
		return transactionTemplate().execute(status -> this.repository.insert(identity));
	}

	private UserExternalIdentity identity(TenantId tenantId, ExternalIdentityProviderId providerId,
			ExternalSubjectId subjectId, UserId userId) {
		return new UserExternalIdentity(tenantId, providerId, subjectId, userId, LINKED_AT);
	}

	private void insertUser(TenantId tenantId, UserId userId) {
		this.jdbcClient.sql("INSERT INTO users (tenant_id, user_id) VALUES (:tenantId, :userId)")
			.param("tenantId", tenantId.value())
			.param("userId", userId.value())
			.update();
	}

	private int identityCount(ExternalIdentityProviderId providerId) {
		return this.jdbcClient.sql("""
				SELECT count(*) FROM user_external_identities
				WHERE tenant_id = :tenantId AND provider_id = :providerId
				""")
			.param("tenantId", TenantId.DEFAULT.value())
			.param("providerId", providerId.value())
			.query(Integer.class)
			.single();
	}

	private TransactionTemplate transactionTemplate() {
		return new TransactionTemplate(this.transactionManager);
	}

	private int backendId() {
		return this.jdbcClient.sql("SELECT pg_backend_pid()").query(Integer.class).single();
	}

	private boolean waitUntilBlocked(int backendId) throws InterruptedException {
		long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
		do {
			boolean blocked = this.jdbcClient.sql("SELECT cardinality(pg_blocking_pids(:backendId)) > 0")
				.param("backendId", backendId)
				.query(Boolean.class)
				.single();
			if (blocked) {
				return true;
			}
			Thread.sleep(10);
		}
		while (System.nanoTime() < deadline);
		return false;
	}

	private static void await(CountDownLatch latch, String timeoutMessage) {
		try {
			if (!latch.await(5, TimeUnit.SECONDS)) {
				throw new IllegalStateException(timeoutMessage);
			}
		}
		catch (InterruptedException exception) {
			Thread.currentThread().interrupt();
			throw new IllegalStateException("Interrupted while coordinating external identity inserts", exception);
		}
	}

	private enum AttemptResult {

		INSERTED,

		SUBJECT_CONFLICT,

		USER_PROVIDER_CONFLICT

	}

}
