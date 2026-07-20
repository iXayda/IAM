package com.ixayda.iam.credential.internal;

import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import com.ixayda.iam.ApplicationIntegrationTest;
import com.ixayda.iam.credential.GeneratedRecoveryCodes;
import com.ixayda.iam.credential.RecoveryCodeAttempt;
import com.ixayda.iam.credential.RecoveryCodeOperations;
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

class RecoveryCodeOperationsIntegrationTests extends ApplicationIntegrationTest {

	private static final UserId USER_ID = UserId.from("019f5aff-f979-7653-8001-67ea4274f801");

	@Autowired
	private RecoveryCodeOperations operations;

	@Autowired
	private JdbcRecoveryCodeRepository repository;

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
		this.jdbcClient.sql("""
				INSERT INTO user_login_identifiers
				    (tenant_id, user_id, identifier_type, identifier_value, canonical_value)
				VALUES (:tenantId, :userId, 'username', 'recovery-code-operations', 'recovery-code-operations')
				""")
			.param("tenantId", TenantId.DEFAULT.value())
			.param("userId", USER_ID.value())
			.update();
	}

	@AfterEach
	void deleteFixtures() {
		this.jdbcClient.sql("DELETE FROM user_recovery_codes WHERE user_id = :userId")
			.param("userId", USER_ID.value())
			.update();
		this.jdbcClient.sql("DELETE FROM user_login_identifiers WHERE tenant_id = :tenantId AND user_id = :userId")
			.param("tenantId", TenantId.DEFAULT.value())
			.param("userId", USER_ID.value())
			.update();
		this.jdbcClient.sql("DELETE FROM users WHERE tenant_id = :tenantId AND user_id = :userId")
			.param("tenantId", TenantId.DEFAULT.value())
			.param("userId", USER_ID.value())
			.update();
	}

	@Test
	void replacesHashesConsumesOnceAndRejectsOldSets() {
		assertThat(this.operations.hasAvailableCode(TenantId.DEFAULT, USER_ID)).isFalse();
		char[][] first = replaceAndCopy();
		try {
			assertThat(this.operations.hasAvailableCode(TenantId.DEFAULT, USER_ID)).isTrue();
			assertThat(this.repository.countAvailable(TenantId.DEFAULT, USER_ID))
				.isEqualTo(GeneratedRecoveryCodes.CODE_COUNT);
			assertThat(storedValue(first[0])).doesNotContain(new String(first[0])).startsWith("{");
			try (RecoveryCodeAttempt attempt = new RecoveryCodeAttempt(first[0])) {
				assertThat(verify(attempt)).isTrue();
			}
			try (RecoveryCodeAttempt replay = new RecoveryCodeAttempt(first[0])) {
				assertThat(verify(replay)).isFalse();
			}
			assertThat(this.repository.countAvailable(TenantId.DEFAULT, USER_ID))
				.isEqualTo(GeneratedRecoveryCodes.CODE_COUNT - 1);

			char[][] replacement = replaceAndCopy();
			try {
				try (RecoveryCodeAttempt old = new RecoveryCodeAttempt(first[1])) {
					assertThat(verify(old)).isFalse();
				}
				try (RecoveryCodeAttempt current = new RecoveryCodeAttempt(replacement[0])) {
					assertThat(verify(current)).isTrue();
				}
			}
			finally {
				clear(replacement);
			}
		}
		finally {
			clear(first);
		}
	}

	@Test
	void enforcesReplacementAndVerificationTransactionBoundaries() {
		assertThatThrownBy(() -> transactionTemplate()
			.execute(status -> this.operations.replace(TenantId.DEFAULT, USER_ID)))
			.isInstanceOf(IllegalTransactionStateException.class);

		try (RecoveryCodeAttempt attempt = new RecoveryCodeAttempt("00000-00000-00000-00000".toCharArray())) {
			assertThatThrownBy(() -> this.operations.verifyAndConsume(TenantId.DEFAULT, USER_ID, attempt))
				.isInstanceOf(IllegalTransactionStateException.class);
			TransactionTemplate readOnly = transactionTemplate();
			readOnly.setReadOnly(true);
			assertThatThrownBy(() -> readOnly.execute(
					status -> this.operations.verifyAndConsume(TenantId.DEFAULT, USER_ID, attempt)))
				.isInstanceOf(IllegalTransactionStateException.class);
		}
	}

	@Test
	void consumesARecoveryCodeOnlyOnceAcrossConcurrentTransactions() throws Exception {
		char[][] codes = replaceAndCopy();
		try {
			StoredRecoveryCode observed;
			try (RecoveryCodeAttempt attempt = new RecoveryCodeAttempt(codes[0])) {
				observed = this.repository.findAvailable(TenantId.DEFAULT, USER_ID, attempt.selector()).orElseThrow();
			}
			CountDownLatch ready = new CountDownLatch(2);
			CountDownLatch start = new CountDownLatch(1);
			try (ExecutorService executor = Executors.newFixedThreadPool(2)) {
				Future<Boolean> first = executor.submit(() -> consumeConcurrently(observed, ready, start));
				Future<Boolean> second = executor.submit(() -> consumeConcurrently(observed, ready, start));
				assertThat(ready.await(10, TimeUnit.SECONDS)).isTrue();
				start.countDown();

				assertThat(List.of(first.get(), second.get())).containsExactlyInAnyOrder(true, false);
			}
			assertThat(this.repository.countAvailable(TenantId.DEFAULT, USER_ID))
				.isEqualTo(GeneratedRecoveryCodes.CODE_COUNT - 1);
		}
		finally {
			clear(codes);
		}
	}

	@Test
	void restoresConsumptionWhenTheCallingTransactionRollsBack() {
		char[][] codes = replaceAndCopy();
		try {
			try (RecoveryCodeAttempt attempt = new RecoveryCodeAttempt(codes[0])) {
				Boolean accepted = transactionTemplate().execute(status -> {
					boolean consumed = this.operations.verifyAndConsume(TenantId.DEFAULT, USER_ID, attempt);
					status.setRollbackOnly();
					return consumed;
				});
				assertThat(accepted).isTrue();
			}
			try (RecoveryCodeAttempt retry = new RecoveryCodeAttempt(codes[0])) {
				assertThat(verify(retry)).isTrue();
			}
		}
		finally {
			clear(codes);
		}
	}

	private char[][] replaceAndCopy() {
		try (GeneratedRecoveryCodes generated = this.operations.replace(TenantId.DEFAULT, USER_ID)) {
			return generated.copy();
		}
	}

	private boolean verify(RecoveryCodeAttempt attempt) {
		return transactionTemplate().execute(
				status -> this.operations.verifyAndConsume(TenantId.DEFAULT, USER_ID, attempt));
	}

	private String storedValue(char[] code) {
		try (RecoveryCodeAttempt attempt = new RecoveryCodeAttempt(code)) {
			return this.repository.findAvailable(TenantId.DEFAULT, USER_ID, attempt.selector())
				.map(StoredRecoveryCode::encodedCode)
				.orElseThrow();
		}
	}

	private TransactionTemplate transactionTemplate() {
		return new TransactionTemplate(this.transactionManager);
	}

	private boolean consumeConcurrently(StoredRecoveryCode observed, CountDownLatch ready, CountDownLatch start) {
		return transactionTemplate().execute(status -> {
			ready.countDown();
			await(start);
			return this.repository.consume(observed, observed.createdAt().plusSeconds(1)).isPresent();
		});
	}

	private static void await(CountDownLatch latch) {
		try {
			if (!latch.await(10, TimeUnit.SECONDS)) {
				throw new IllegalStateException("Timed out waiting for concurrent recovery code consumption");
			}
		}
		catch (InterruptedException ex) {
			Thread.currentThread().interrupt();
			throw new IllegalStateException("Interrupted while consuming a recovery code", ex);
		}
	}

	private static void clear(char[][] values) {
		for (char[] value : values) {
			Arrays.fill(value, '\0');
		}
	}

}
