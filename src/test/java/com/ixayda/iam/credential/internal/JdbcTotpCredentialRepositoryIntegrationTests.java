package com.ixayda.iam.credential.internal;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import com.ixayda.iam.ApplicationIntegrationTest;
import com.ixayda.iam.credential.TotpAlgorithm;
import com.ixayda.iam.credential.TotpCredential;
import com.ixayda.iam.credential.TotpCredentialId;
import com.ixayda.iam.credential.TotpCredentialStatus;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.transaction.IllegalTransactionStateException;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JdbcTotpCredentialRepositoryIntegrationTests extends ApplicationIntegrationTest {

	private static final UserId USER_ID = UserId.from("019f5aff-f979-7653-8001-67ea4274f501");

	private static final TotpCredentialId CREDENTIAL_ID =
			TotpCredentialId.from("019f5aff-f979-7653-8001-67ea4274f502");

	private static final TotpCredentialId SECOND_CREDENTIAL_ID =
			TotpCredentialId.from("019f5aff-f979-7653-8001-67ea4274f503");

	private static final Instant CREATED_AT = Instant.parse("2026-07-20T00:00:00Z");

	@Autowired
	private JdbcTotpCredentialRepository repository;

	@Autowired
	private JdbcClient jdbcClient;

	@Autowired
	private PlatformTransactionManager transactionManager;

	@BeforeEach
	void createUser() {
		this.jdbcClient.sql("INSERT INTO users (tenant_id, user_id) VALUES (:tenantId, :userId)")
			.param("tenantId", TenantId.DEFAULT.value())
			.param("userId", USER_ID.value())
			.update();
	}

	@AfterEach
	void deleteFixtures() {
		this.jdbcClient.sql("DELETE FROM user_totp_credentials WHERE user_id = :userId")
			.param("userId", USER_ID.value())
			.update();
		this.jdbcClient.sql("DELETE FROM users WHERE tenant_id = :tenantId AND user_id = :userId")
			.param("tenantId", TenantId.DEFAULT.value())
			.param("userId", USER_ID.value())
			.update();
	}

	@Test
	void persistsTheCompleteCredentialLifecycleAndErasesRevokedSecrets() {
		StoredTotpCredential pending = storedPending(CREDENTIAL_ID, 1);
		insert(pending);

		StoredTotpCredential foundPending = this.repository.findPendingByUser(TenantId.DEFAULT, USER_ID).orElseThrow();
		assertCredential(foundPending, TotpCredentialStatus.PENDING, null, 0);
		assertThat(this.repository.findById(TenantId.random(), USER_ID, CREDENTIAL_ID)).isEmpty();

		TotpCredential active = foundPending.credential().activate(100, CREATED_AT.plusSeconds(30));
		assertThat(activate(foundPending, active)).isSameAs(active);
		StoredTotpCredential foundActive = this.repository.findActiveByUser(TenantId.DEFAULT, USER_ID).orElseThrow();
		assertCredential(foundActive, TotpCredentialStatus.ACTIVE, 100L, 1);

		StoredTotpCredential accepted = accept(foundActive, 101, CREATED_AT.plusSeconds(60)).orElseThrow();
		assertCredential(accepted, TotpCredentialStatus.ACTIVE, 101L, 2);
		assertThat(accept(foundActive, 101, CREATED_AT.plusSeconds(60))).isEmpty();

		TotpCredential revoked = accepted.credential().revoke(CREATED_AT.plusSeconds(90));
		assertThat(revoke(accepted, revoked)).isSameAs(revoked);
		assertThat(this.repository.findActiveByUser(TenantId.DEFAULT, USER_ID)).isEmpty();
		StoredTotpCredential history =
				this.repository.findById(TenantId.DEFAULT, USER_ID, CREDENTIAL_ID).orElseThrow();
		assertCredential(history, TotpCredentialStatus.REVOKED, 101L, 3);
		assertThat(history.protectedSecret()).isNull();
		assertThat(this.jdbcClient.sql("""
				SELECT secret_encryption_key_id IS NULL
				   AND secret_initialization_vector IS NULL
				   AND secret_ciphertext IS NULL
				FROM user_totp_credentials WHERE credential_id = :credentialId
				""").param("credentialId", CREDENTIAL_ID.value()).query(Boolean.class).single()).isTrue();
	}

	@Test
	void rejectsDuplicatePendingCredentialsWithoutAbortingTheCallerTransaction() {
		StoredTotpCredential first = storedPending(CREDENTIAL_ID, 1);
		StoredTotpCredential duplicate = storedPending(SECOND_CREDENTIAL_ID, 2);

		transactionTemplate().executeWithoutResult(status -> {
			this.repository.insert(first);
			assertThatThrownBy(() -> this.repository.insert(duplicate))
				.isInstanceOf(TotpCredentialAlreadyExistsException.class)
				.extracting("tenantId", "userId", "credentialId")
				.containsExactly(TenantId.DEFAULT, USER_ID, SECOND_CREDENTIAL_ID);
			assertThat(this.repository.findPendingByUser(TenantId.DEFAULT, USER_ID)).isPresent();
		});
	}

	@Test
	void acceptsAConcurrentTimeStepOnlyOnce() throws Exception {
		StoredTotpCredential pending = storedPending(CREDENTIAL_ID, 1);
		insert(pending);
		StoredTotpCredential active = this.repository.findById(TenantId.DEFAULT, USER_ID, CREDENTIAL_ID)
			.map(stored -> {
				TotpCredential activated = stored.credential().activate(100, CREATED_AT.plusSeconds(30));
				activate(stored, activated);
				return this.repository.findActiveByUser(TenantId.DEFAULT, USER_ID).orElseThrow();
			})
			.orElseThrow();

		CountDownLatch ready = new CountDownLatch(2);
		CountDownLatch start = new CountDownLatch(1);
		try (ExecutorService executor = Executors.newFixedThreadPool(2)) {
			List<Future<Optional<StoredTotpCredential>>> attempts = List.of(
					executor.submit(() -> concurrentAccept(active, ready, start)),
					executor.submit(() -> concurrentAccept(active, ready, start)));
			assertThat(ready.await(5, TimeUnit.SECONDS)).isTrue();
			start.countDown();
			List<Optional<StoredTotpCredential>> results = attempts.stream().map(this::result).toList();
			assertThat(results).filteredOn(Optional::isPresent).hasSize(1);
			assertThat(results).filteredOn(Optional::isEmpty).hasSize(1);
		}

		StoredTotpCredential stored = this.repository.findActiveByUser(TenantId.DEFAULT, USER_ID).orElseThrow();
		assertCredential(stored, TotpCredentialStatus.ACTIVE, 101L, 2);
	}

	@Test
	void preservesOptimisticLifecycleTransitions() {
		StoredTotpCredential pending = storedPending(CREDENTIAL_ID, 1);
		insert(pending);
		TotpCredential active = pending.credential().activate(100, CREATED_AT.plusSeconds(30));

		activate(pending, active);
		assertThatThrownBy(() -> activate(pending, active))
			.isInstanceOf(TotpCredentialConcurrentUpdateException.class)
			.extracting("credentialId", "expectedVersion")
			.containsExactly(CREDENTIAL_ID, 0L);
		assertThat(this.repository.findActiveByUser(TenantId.DEFAULT, USER_ID)).isPresent();
	}

	@Test
	void rejectsForgedLifecycleState() {
		StoredTotpCredential pending = storedPending(CREDENTIAL_ID, 1);
		TotpCredential forgedActivation = new TotpCredential(CREDENTIAL_ID, TenantId.DEFAULT, USER_ID,
				TotpCredentialStatus.ACTIVE, TotpAlgorithm.SHA1, 6, 30, 100L, 1, CREATED_AT,
				CREATED_AT.plusSeconds(60), null, CREATED_AT.plusSeconds(30), null);

		assertThatThrownBy(() -> transactionTemplate()
			.execute(status -> this.repository.activate(pending, forgedActivation)))
			.isInstanceOf(IllegalArgumentException.class);

		insert(pending);
		TotpCredential active = pending.credential().activate(100, CREATED_AT.plusSeconds(30));
		activate(pending, active);
		StoredTotpCredential storedActive = this.repository.findActiveByUser(TenantId.DEFAULT, USER_ID).orElseThrow();
		TotpCredential forgedRevocation = new TotpCredential(CREDENTIAL_ID, TenantId.DEFAULT, USER_ID,
				TotpCredentialStatus.REVOKED, TotpAlgorithm.SHA1, 6, 30, 101L, 2, CREATED_AT,
				CREATED_AT.plusSeconds(60), null, active.activatedAt(), CREATED_AT.plusSeconds(60));

		assertThatThrownBy(() -> transactionTemplate()
			.execute(status -> this.repository.revoke(storedActive, forgedRevocation)))
			.isInstanceOf(IllegalArgumentException.class);
		assertCredential(this.repository.findActiveByUser(TenantId.DEFAULT, USER_ID).orElseThrow(),
				TotpCredentialStatus.ACTIVE, 100L, 1);
	}

	@Test
	void requiresAnExistingReadWriteTransactionForEveryWrite() {
		StoredTotpCredential pending = storedPending(CREDENTIAL_ID, 1);

		assertThatThrownBy(() -> this.repository.insert(pending))
			.isInstanceOf(IllegalTransactionStateException.class);
		TransactionTemplate readOnly = transactionTemplate();
		readOnly.setReadOnly(true);
		assertThatThrownBy(() -> readOnly.execute(status -> this.repository.insert(pending)))
			.isInstanceOf(IllegalTransactionStateException.class)
			.hasMessage("TOTP credential write requires an existing read-write transaction");
	}

	private StoredTotpCredential storedPending(TotpCredentialId credentialId, int offset) {
		TotpCredential credential = new TotpCredential(credentialId, TenantId.DEFAULT, USER_ID,
				TotpCredentialStatus.PENDING, TotpAlgorithm.SHA1, 6, 30, null, 0, CREATED_AT, CREATED_AT,
				CREATED_AT.plusSeconds(600), null, null);
		return new StoredTotpCredential(credential, new TotpSecretCipher.ProtectedTotpSecret(1, "v1",
				bytes(12, offset), bytes(36, offset + 20)));
	}

	private StoredTotpCredential insert(StoredTotpCredential credential) {
		return transactionTemplate().execute(status -> this.repository.insert(credential));
	}

	private TotpCredential activate(StoredTotpCredential current, TotpCredential active) {
		return transactionTemplate().execute(status -> this.repository.activate(current, active));
	}

	private Optional<StoredTotpCredential> accept(StoredTotpCredential observed, long timeStep, Instant verifiedAt) {
		return transactionTemplate().execute(status -> this.repository.acceptTimeStep(observed, timeStep, verifiedAt));
	}

	private TotpCredential revoke(StoredTotpCredential current, TotpCredential revoked) {
		return transactionTemplate().execute(status -> this.repository.revoke(current, revoked));
	}

	private Optional<StoredTotpCredential> concurrentAccept(StoredTotpCredential active, CountDownLatch ready,
			CountDownLatch start) {
		ready.countDown();
		await(start);
		return accept(active, 101, CREATED_AT.plusSeconds(60));
	}

	private <T> T result(Future<T> future) {
		try {
			return future.get(5, TimeUnit.SECONDS);
		}
		catch (Exception exception) {
			throw new IllegalStateException("Concurrent TOTP repository operation failed", exception);
		}
	}

	private TransactionTemplate transactionTemplate() {
		return new TransactionTemplate(this.transactionManager);
	}

	private static void assertCredential(StoredTotpCredential stored, TotpCredentialStatus status,
			Long lastAcceptedTimeStep, long version) {
		assertThat(stored.credential().status()).isEqualTo(status);
		assertThat(stored.credential().lastAcceptedTimeStep()).isEqualTo(lastAcceptedTimeStep);
		assertThat(stored.credential().version()).isEqualTo(version);
		if (status != TotpCredentialStatus.REVOKED) {
			assertThat(stored.protectedSecret()).isNotNull();
		}
	}

	private static byte[] bytes(int length, int offset) {
		byte[] bytes = new byte[length];
		for (int index = 0; index < length; index++) {
			bytes[index] = (byte) (offset + index);
		}
		return bytes;
	}

	private static void await(CountDownLatch latch) {
		try {
			if (!latch.await(5, TimeUnit.SECONDS)) {
				throw new IllegalStateException("Timed out coordinating concurrent TOTP repository updates");
			}
		}
		catch (InterruptedException exception) {
			Thread.currentThread().interrupt();
			throw new IllegalStateException("Interrupted coordinating concurrent TOTP repository updates", exception);
		}
	}

}
