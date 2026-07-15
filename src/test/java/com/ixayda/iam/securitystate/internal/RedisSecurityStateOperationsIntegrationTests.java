package com.ixayda.iam.securitystate.internal;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import com.ixayda.iam.ApplicationIntegrationTest;
import com.ixayda.iam.securitystate.SecurityStateConsumeStatus;
import com.ixayda.iam.securitystate.SecurityStateIssue;
import com.ixayda.iam.securitystate.SecurityStateKey;
import com.ixayda.iam.securitystate.SecurityStateOperations;
import com.ixayda.iam.securitystate.SecurityStateToken;
import com.ixayda.iam.tenant.TenantId;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;

class RedisSecurityStateOperationsIntegrationTests extends ApplicationIntegrationTest {

	private static final SecurityStateKey KEY =
			new SecurityStateKey(TenantId.DEFAULT, "mfa-login", "user:internal-123");

	@Autowired
	private SecurityStateOperations operations;

	@Autowired
	private StringRedisTemplate redis;

	@Autowired
	private SecurityStateProperties properties;

	@AfterEach
	void deleteSecurityStateKeys() {
		Set<String> keys = this.redis.keys("iam:test:security-state:*");
		if (keys != null && !keys.isEmpty()) {
			this.redis.delete(keys);
		}
	}

	@Test
	void storesNoRawScopeOrTokenDataAndRejectsReplay() {
		SecurityStateIssue issued = this.operations.issue(KEY, Duration.ofMinutes(5));
		SecurityStateToken token = issued.token().orElseThrow();
		Set<String> storedKeys = this.redis.keys("iam:test:security-state:*");

		assertThat(storedKeys).hasSize(1);
		assertThat(storedKeys.iterator().next()).doesNotContain(TenantId.DEFAULT.value().toString(), KEY.purpose(),
				KEY.binding(), token.value());
		assertThat(this.operations.consume(KEY, token)).isEqualTo(SecurityStateConsumeStatus.CONSUMED);
		assertThat(this.operations.consume(KEY, token)).isEqualTo(SecurityStateConsumeStatus.REJECTED);
	}

	@Test
	void bindsTokensToTenantPurposeAndSubjectWithoutConsumingOnMismatch() {
		SecurityStateToken token = this.operations.issue(KEY, Duration.ofMinutes(5)).token().orElseThrow();
		SecurityStateToken differentToken =
				SecurityStateToken.from("A".repeat(SecurityStateToken.ENCODED_LENGTH));

		assertThat(this.operations.consume(
				new SecurityStateKey(TenantId.random(), KEY.purpose(), KEY.binding()), token))
			.isEqualTo(SecurityStateConsumeStatus.REJECTED);
		assertThat(this.operations.consume(
				new SecurityStateKey(KEY.tenantId(), "password-reset", KEY.binding()), token))
			.isEqualTo(SecurityStateConsumeStatus.REJECTED);
		assertThat(this.operations.consume(
				new SecurityStateKey(KEY.tenantId(), KEY.purpose(), "user:internal-456"), token))
			.isEqualTo(SecurityStateConsumeStatus.REJECTED);
		assertThat(this.operations.consume(KEY, differentToken)).isEqualTo(SecurityStateConsumeStatus.REJECTED);
		assertThat(this.operations.consume(KEY, token)).isEqualTo(SecurityStateConsumeStatus.CONSUMED);
	}

	@Test
	void sharesStateAcrossOperationInstances() {
		SecurityStateOperations second =
				new RedisSecurityStateOperations(this.redis, this.properties, new SimpleMeterRegistry());
		SecurityStateToken token = this.operations.issue(KEY, Duration.ofMinutes(5)).token().orElseThrow();

		assertThat(second.consume(KEY, token)).isEqualTo(SecurityStateConsumeStatus.CONSUMED);
		assertThat(this.operations.consume(KEY, token)).isEqualTo(SecurityStateConsumeStatus.REJECTED);
	}

	@Test
	void allowsParallelTokensForTheSameBinding() {
		SecurityStateToken first = this.operations.issue(KEY, Duration.ofMinutes(5)).token().orElseThrow();
		SecurityStateToken second = this.operations.issue(KEY, Duration.ofMinutes(5)).token().orElseThrow();

		assertThat(first).isNotEqualTo(second);
		assertThat(this.operations.consume(KEY, first)).isEqualTo(SecurityStateConsumeStatus.CONSUMED);
		assertThat(this.operations.consume(KEY, second)).isEqualTo(SecurityStateConsumeStatus.CONSUMED);
	}

	@Test
	void allowsExactlyOneConcurrentConsumer() throws Exception {
		SecurityStateToken token = this.operations.issue(KEY, Duration.ofMinutes(5)).token().orElseThrow();
		List<Future<SecurityStateConsumeStatus>> futures = new ArrayList<>();

		try (ExecutorService executor = Executors.newFixedThreadPool(16)) {
			for (int index = 0; index < 32; index++) {
				futures.add(executor.submit(() -> this.operations.consume(KEY, token)));
			}
		}

		long consumed = 0;
		for (Future<SecurityStateConsumeStatus> future : futures) {
			if (future.get(5, TimeUnit.SECONDS) == SecurityStateConsumeStatus.CONSUMED) {
				consumed++;
			}
		}
		assertThat(consumed).isOne();
	}

	@Test
	void rejectsExpiredState() throws Exception {
		SecurityStateToken token = this.operations.issue(KEY, Duration.ofMillis(50)).token().orElseThrow();
		String redisKey = encodedKey(KEY, token);

		assertThat(awaitMissing(redisKey, Duration.ofSeconds(2))).isTrue();
		assertThat(this.operations.consume(KEY, token)).isEqualTo(SecurityStateConsumeStatus.REJECTED);
	}

	private String encodedKey(SecurityStateKey key, SecurityStateToken token) {
		byte[] secret = this.properties.decodedKeySecret().orElseThrow();
		try {
			return new SecurityStateKeys(secret, this.properties.keyPrefix()).encode(key, token);
		}
		finally {
			Arrays.fill(secret, (byte) 0);
		}
	}

	private boolean awaitMissing(String key, Duration timeout) throws InterruptedException {
		long deadline = System.nanoTime() + timeout.toNanos();
		do {
			if (Boolean.FALSE.equals(this.redis.hasKey(key))) {
				return true;
			}
			Thread.sleep(5);
		}
		while (System.nanoTime() < deadline);
		return false;
	}

}
