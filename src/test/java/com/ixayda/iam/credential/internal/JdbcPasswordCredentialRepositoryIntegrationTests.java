package com.ixayda.iam.credential.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import com.ixayda.iam.ApplicationIntegrationTest;
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

class JdbcPasswordCredentialRepositoryIntegrationTests extends ApplicationIntegrationTest {

	private static final TenantId SECOND_TENANT_ID =
			new TenantId(UUID.fromString("019bc1e7-14d1-7d38-bd23-0877f2cd0e11"));

	private static final UserId USER_ID = UserId.from("019bc1e7-14d1-7d38-bd23-0877f2cd0e12");

	private static final UserId SECOND_USER_ID = UserId.from("019bc1e7-14d1-7d38-bd23-0877f2cd0e13");

	private static final Instant CREATED_AT = Instant.parse("2026-01-01T00:00:00Z");

	private static final String ENCODED_PASSWORD =
			"{bcrypt}$2a$10$dXJ3SW6G7P50lGmMkkmwe.20cQQubK3.HZWzG3YB1tlRy.fqvM/BG";

	private static final String NEXT_ENCODED_PASSWORD =
			"{pbkdf2@SpringSecurity_v5_8}0123456789abcdef0123456789abcdef";

	@Autowired
	private JdbcPasswordCredentialRepository repository;

	@Autowired
	private JdbcClient jdbcClient;

	@Autowired
	private PlatformTransactionManager transactionManager;

	@BeforeEach
	void createUsers() {
		this.jdbcClient.sql("""
				INSERT INTO tenants (tenant_id, slug, display_name)
				VALUES (:tenantId, 'password-store-tenant', 'Password Store Tenant')
				""").param("tenantId", SECOND_TENANT_ID.value()).update();
		insertUser(TenantId.DEFAULT, USER_ID);
		insertUser(SECOND_TENANT_ID, SECOND_USER_ID);
	}

	@AfterEach
	void deleteFixtures() {
		this.jdbcClient.sql("""
				DELETE FROM user_password_credentials
				WHERE user_id = :userId OR user_id = :secondUserId
				""")
			.param("userId", USER_ID.value())
			.param("secondUserId", SECOND_USER_ID.value())
			.update();
		this.jdbcClient.sql("DELETE FROM users WHERE user_id = :userId OR user_id = :secondUserId")
			.param("userId", USER_ID.value())
			.param("secondUserId", SECOND_USER_ID.value())
			.update();
		this.jdbcClient.sql("DELETE FROM tenants WHERE tenant_id = :tenantId")
			.param("tenantId", SECOND_TENANT_ID.value())
			.update();
	}

	@Test
	void storesAndFindsTenantScopedCredentials() {
		PasswordCredential first = credential(TenantId.DEFAULT, USER_ID, ENCODED_PASSWORD);
		PasswordCredential second = credential(SECOND_TENANT_ID, SECOND_USER_ID, NEXT_ENCODED_PASSWORD);

		assertThat(insert(first)).isSameAs(first);
		assertCredential(this.repository.findByUser(TenantId.DEFAULT, USER_ID), first);
		assertThat(this.repository.findByUser(SECOND_TENANT_ID, USER_ID)).isEmpty();

		insert(second);
		assertCredential(this.repository.findByUser(SECOND_TENANT_ID, SECOND_USER_ID), second);
	}

	@Test
	void rejectsDuplicatesWithoutAbortingTheCallerTransaction() {
		PasswordCredential first = credential(TenantId.DEFAULT, ENCODED_PASSWORD);
		PasswordCredential duplicate = credential(TenantId.DEFAULT, NEXT_ENCODED_PASSWORD);

		transactionTemplate().executeWithoutResult(status -> {
			this.repository.insert(first);
			assertThatThrownBy(() -> this.repository.insert(duplicate))
				.isInstanceOf(PasswordCredentialAlreadyExistsException.class)
				.extracting("tenantId", "userId")
				.containsExactly(TenantId.DEFAULT, USER_ID);
			assertCredential(this.repository.findByUser(TenantId.DEFAULT, USER_ID), first);
		});

		assertCredential(this.repository.findByUser(TenantId.DEFAULT, USER_ID), first);
	}

	@Test
	void updatesUsingTenantScopedOptimisticLocking() {
		PasswordCredential current = insert(credential(TenantId.DEFAULT, ENCODED_PASSWORD));
		PasswordCredential changed = current.replaceWith(NEXT_ENCODED_PASSWORD, CREATED_AT.plusSeconds(1));

		assertThat(update(current, changed)).isSameAs(changed);
		assertCredential(this.repository.findByUser(TenantId.DEFAULT, USER_ID), changed);
		assertThatThrownBy(() -> update(current, changed))
			.isInstanceOf(PasswordCredentialConcurrentUpdateException.class)
			.extracting("tenantId", "userId", "expectedVersion")
			.containsExactly(TenantId.DEFAULT, USER_ID, 0L);

		PasswordCredential wrongTenant = credential(SECOND_TENANT_ID, USER_ID, ENCODED_PASSWORD);
		assertThatThrownBy(() -> update(wrongTenant,
				wrongTenant.replaceWith(NEXT_ENCODED_PASSWORD, CREATED_AT.plusSeconds(1))))
			.isInstanceOf(PasswordCredentialConcurrentUpdateException.class);
		assertCredential(this.repository.findByUser(TenantId.DEFAULT, USER_ID), changed);
	}

	@Test
	void keepsTheCallerTransactionUsableAfterAConcurrentUpdate() {
		PasswordCredential initial = insert(credential(TenantId.DEFAULT, ENCODED_PASSWORD));
		PasswordCredential winner = initial.replaceWith(NEXT_ENCODED_PASSWORD, CREATED_AT.plusSeconds(1));
		update(initial, winner);

		PasswordCredential recovered = transactionTemplate().execute(status -> {
			assertThatThrownBy(() -> this.repository.update(initial, winner))
				.isInstanceOf(PasswordCredentialConcurrentUpdateException.class);
			PasswordCredential latest = this.repository.findByUser(TenantId.DEFAULT, USER_ID).orElseThrow();
			return this.repository.update(latest,
					latest.replaceWith(ENCODED_PASSWORD, CREATED_AT.plusSeconds(2)));
		});

		assertThat(recovered.version()).isEqualTo(2);
		assertCredential(this.repository.findByUser(TenantId.DEFAULT, USER_ID), recovered);
	}

	@Test
	void participatesInCallerRollback() {
		PasswordCredential initial = credential(TenantId.DEFAULT, ENCODED_PASSWORD);
		transactionTemplate().executeWithoutResult(status -> {
			this.repository.insert(initial);
			status.setRollbackOnly();
		});
		assertThat(this.repository.findByUser(TenantId.DEFAULT, USER_ID)).isEmpty();

		insert(initial);
		PasswordCredential changed = initial.replaceWith(NEXT_ENCODED_PASSWORD, CREATED_AT.plusSeconds(1));
		transactionTemplate().executeWithoutResult(status -> {
			this.repository.update(initial, changed);
			status.setRollbackOnly();
		});
		assertCredential(this.repository.findByUser(TenantId.DEFAULT, USER_ID), initial);
	}

	@Test
	void requiresAnExistingReadWriteTransaction() {
		PasswordCredential initial = credential(TenantId.DEFAULT, ENCODED_PASSWORD);

		assertThatThrownBy(() -> this.repository.insert(initial))
			.isInstanceOf(IllegalTransactionStateException.class);
		TransactionTemplate readOnly = transactionTemplate();
		readOnly.setReadOnly(true);
		assertThatThrownBy(() -> readOnly.execute(status -> this.repository.insert(initial)))
			.isInstanceOf(IllegalTransactionStateException.class)
			.hasMessage("Password credential write requires an existing read-write transaction");
		PasswordCredential nonInitial = initial.replaceWith(NEXT_ENCODED_PASSWORD, CREATED_AT.plusSeconds(1));
		assertThatThrownBy(() -> transactionTemplate().execute(status -> this.repository.insert(nonInitial)))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("New password credential must start at version zero and creation time");

		insert(initial);
		PasswordCredential changed = initial.replaceWith(NEXT_ENCODED_PASSWORD, CREATED_AT.plusSeconds(1));
		assertThatThrownBy(() -> this.repository.update(initial, changed))
			.isInstanceOf(IllegalTransactionStateException.class);
		assertThatThrownBy(() -> readOnly.execute(status -> this.repository.update(initial, changed)))
			.isInstanceOf(IllegalTransactionStateException.class)
			.hasMessage("Password credential write requires an existing read-write transaction");
		assertCredential(this.repository.findByUser(TenantId.DEFAULT, USER_ID), initial);
	}

	@Test
	void requiresAnExistingReadWriteTransactionForTheCredentialLock() {
		PasswordCredential initial = insert(credential(TenantId.DEFAULT, ENCODED_PASSWORD));

		assertThatThrownBy(() -> this.repository.findByUserForUpdate(TenantId.DEFAULT, USER_ID))
			.isInstanceOf(IllegalTransactionStateException.class);
		TransactionTemplate readOnly = transactionTemplate();
		readOnly.setReadOnly(true);
		assertThatThrownBy(() -> readOnly
			.execute(status -> this.repository.findByUserForUpdate(TenantId.DEFAULT, USER_ID)))
			.isInstanceOf(IllegalTransactionStateException.class)
			.hasMessage("Password credential write requires an existing read-write transaction");

		Optional<PasswordCredential> locked = transactionTemplate()
			.execute(status -> this.repository.findByUserForUpdate(TenantId.DEFAULT, USER_ID));
		assertCredential(locked, initial);
	}

	@Test
	void holdsTheCredentialLockUntilTheCallerTransactionCompletes() throws Exception {
		PasswordCredential initial = insert(credential(TenantId.DEFAULT, ENCODED_PASSWORD));
		CountDownLatch firstLockAcquired = new CountDownLatch(1);
		CountDownLatch releaseFirstLock = new CountDownLatch(1);
		CountDownLatch secondLockStarted = new CountDownLatch(1);
		AtomicInteger secondBackendId = new AtomicInteger();

		try (ExecutorService executor = Executors.newFixedThreadPool(2)) {
			Future<PasswordCredential> first = executor.submit(() -> transactionTemplate().execute(status -> {
				PasswordCredential locked = this.repository.findByUserForUpdate(TenantId.DEFAULT, USER_ID).orElseThrow();
				firstLockAcquired.countDown();
				await(releaseFirstLock, "Timed out holding the password credential lock");
				return locked;
			}));
			Future<PasswordCredential> second;
			try {
				assertThat(firstLockAcquired.await(5, TimeUnit.SECONDS)).isTrue();
				second = executor.submit(() -> transactionTemplate().execute(status -> {
					secondBackendId.set(backendId());
					secondLockStarted.countDown();
					return this.repository.findByUserForUpdate(TenantId.DEFAULT, USER_ID).orElseThrow();
				}));
				assertThat(secondLockStarted.await(5, TimeUnit.SECONDS)).isTrue();
				assertThat(waitUntilBlocked(secondBackendId.get())).isTrue();
			}
			finally {
				releaseFirstLock.countDown();
			}

			assertThat(first.get(5, TimeUnit.SECONDS).encodedPassword()).isEqualTo(initial.encodedPassword());
			assertThat(second.get(5, TimeUnit.SECONDS).encodedPassword()).isEqualTo(initial.encodedPassword());
		}
	}

	private PasswordCredential credential(TenantId tenantId, String encodedPassword) {
		return credential(tenantId, USER_ID, encodedPassword);
	}

	private PasswordCredential credential(TenantId tenantId, UserId userId, String encodedPassword) {
		return PasswordCredential.initial(tenantId, userId, encodedPassword, CREATED_AT);
	}

	private PasswordCredential insert(PasswordCredential credential) {
		return transactionTemplate().execute(status -> this.repository.insert(credential));
	}

	private PasswordCredential update(PasswordCredential current, PasswordCredential changed) {
		return transactionTemplate().execute(status -> this.repository.update(current, changed));
	}

	private void insertUser(TenantId tenantId, UserId userId) {
		this.jdbcClient.sql("INSERT INTO users (tenant_id, user_id) VALUES (:tenantId, :userId)")
			.param("tenantId", tenantId.value())
			.param("userId", userId.value())
			.update();
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
		catch (InterruptedException ex) {
			Thread.currentThread().interrupt();
			throw new IllegalStateException("Interrupted while coordinating password credential locks", ex);
		}
	}

	private static void assertCredential(Optional<PasswordCredential> actual, PasswordCredential expected) {
		assertThat(actual).hasValueSatisfying(credential -> {
			assertThat(credential.tenantId()).isEqualTo(expected.tenantId());
			assertThat(credential.userId()).isEqualTo(expected.userId());
			assertThat(credential.encodedPassword()).isEqualTo(expected.encodedPassword());
			assertThat(credential.version()).isEqualTo(expected.version());
			assertThat(credential.createdAt()).isEqualTo(expected.createdAt());
			assertThat(credential.updatedAt()).isEqualTo(expected.updatedAt());
		});
	}

}
