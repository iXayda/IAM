package com.ixayda.iam.authorization.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import com.ixayda.iam.ApplicationIntegrationTest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.TestPropertySource;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
@TestPropertySource(properties = "iam.authorization.initialization-test-context=true")
class AuthorizationSigningKeyInitializationIntegrationTests extends ApplicationIntegrationTest {

	@Autowired
	private AuthorizationSigningKeyInitializer initializer;

	@Autowired
	private JdbcClient jdbcClient;

	@Autowired
	private PlatformTransactionManager transactionManager;

	@BeforeEach
	void deleteSigningKeys() {
		this.jdbcClient.sql("DELETE FROM oauth_signing_keys").update();
	}

	@AfterEach
	void restoreSigningKey() {
		this.jdbcClient.sql("DELETE FROM oauth_signing_keys").update();
		this.initializer.initialize();
	}

	@Test
	void initializesOnceAndReusesThePersistedPrivateKey() {
		String firstKid = this.initializer.initialize().activeSigningKey().getKeyID();
		StoredRow first = storedRow();

		String secondKid = this.initializer.initialize().activeSigningKey().getKeyID();
		StoredRow second = storedRow();

		assertThat(secondKid).isEqualTo(firstKid);
		assertThat(second.kid()).isEqualTo(first.kid());
		assertThat(second.ciphertext()).containsExactly(first.ciphertext());
		assertThat(second.createdAt()).isEqualTo(first.createdAt());
	}

	@Test
	void serializesConcurrentFirstStartupAcrossInstances() throws Exception {
		int instanceCount = 6;
		CountDownLatch ready = new CountDownLatch(instanceCount);
		CountDownLatch start = new CountDownLatch(1);
		List<Future<String>> results = new ArrayList<>();
		try (ExecutorService executor = Executors.newFixedThreadPool(instanceCount)) {
			for (int index = 0; index < instanceCount; index++) {
				results.add(executor.submit(() -> {
					ready.countDown();
					if (!start.await(10, TimeUnit.SECONDS)) {
						throw new IllegalStateException("Timed out waiting to initialize signing keys");
					}
					return this.initializer.initialize().activeSigningKey().getKeyID();
				}));
			}
			assertThat(ready.await(10, TimeUnit.SECONDS)).isTrue();
			start.countDown();
			List<String> kids = new ArrayList<>();
			for (Future<String> result : results) {
				kids.add(result.get(30, TimeUnit.SECONDS));
			}
			assertThat(kids).containsOnly(kids.getFirst());
		}

		assertThat(this.jdbcClient.sql("SELECT count(*) FROM oauth_signing_keys WHERE status = 'active'")
			.query(Integer.class)
			.single()).isOne();
	}

	@Test
	void waitsForAnotherInstanceHoldingTheInitializationLock() throws Exception {
		CountDownLatch lockAcquired = new CountDownLatch(1);
		CountDownLatch releaseLock = new CountDownLatch(1);
		try (ExecutorService executor = Executors.newFixedThreadPool(2)) {
			Future<Void> holder = executor.submit(() -> {
				new TransactionTemplate(this.transactionManager).executeWithoutResult(status -> {
					this.jdbcClient.sql("LOCK TABLE oauth_signing_keys IN SHARE ROW EXCLUSIVE MODE").update();
					lockAcquired.countDown();
					await(releaseLock, "Timed out holding the signing-key initialization lock");
				});
				return null;
			});
			assertThat(lockAcquired.await(10, TimeUnit.SECONDS)).isTrue();
			Future<String> contender = executor.submit(
					() -> this.initializer.initialize().activeSigningKey().getKeyID());
			try {
				assertThat(waitForWaitingInitializationLock()).isTrue();
			}
			finally {
				releaseLock.countDown();
			}
			holder.get(10, TimeUnit.SECONDS);
			assertThat(contender.get(30, TimeUnit.SECONDS)).matches("[A-Za-z0-9_-]{43}");
		}
	}

	@Test
	void failsClosedWhenPersistedPrivateMaterialIsCorrupted() {
		this.initializer.initialize();
		this.jdbcClient.sql("""
				UPDATE oauth_signing_keys
				SET private_key_ciphertext = set_byte(
				        private_key_ciphertext, 0, (get_byte(private_key_ciphertext, 0) + 1) % 256)
				WHERE status = 'active'
				""").update();

		assertThatThrownBy(this.initializer::initialize)
			.isInstanceOf(DataRetrievalFailureException.class)
			.hasMessage("Authorization signing-key attestation validation failed");
	}

	private StoredRow storedRow() {
		return this.jdbcClient.sql("""
				SELECT kid, private_key_ciphertext, created_at
				FROM oauth_signing_keys
				WHERE status = 'active'
				""").query((resultSet, rowNumber) -> new StoredRow(resultSet.getString("kid"),
				resultSet.getBytes("private_key_ciphertext"),
				resultSet.getObject("created_at", OffsetDateTime.class))).single();
	}

	private boolean waitForWaitingInitializationLock() throws InterruptedException {
		long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
		do {
			int waiting = this.jdbcClient.sql("""
					SELECT count(*)
					FROM pg_locks
					WHERE relation = 'oauth_signing_keys'::regclass
					  AND mode = 'ShareRowExclusiveLock'
					  AND NOT granted
					""").query(Integer.class).single();
			if (waiting > 0) {
				return true;
			}
			Thread.sleep(50);
		}
		while (System.nanoTime() < deadline);
		return false;
	}

	private static void await(CountDownLatch latch, String message) {
		try {
			if (!latch.await(10, TimeUnit.SECONDS)) {
				throw new IllegalStateException(message);
			}
		}
		catch (InterruptedException exception) {
			Thread.currentThread().interrupt();
			throw new IllegalStateException(message, exception);
		}
	}

	private record StoredRow(String kid, byte[] ciphertext, OffsetDateTime createdAt) {
	}

}
