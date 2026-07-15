package com.ixayda.iam.securitystate.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.function.Supplier;

import com.ixayda.iam.securitystate.SecurityStateConsumeStatus;
import com.ixayda.iam.securitystate.SecurityStateIssue;
import com.ixayda.iam.securitystate.SecurityStateIssueStatus;
import com.ixayda.iam.securitystate.SecurityStateKey;
import com.ixayda.iam.securitystate.SecurityStateToken;
import com.ixayda.iam.tenant.TenantId;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.transaction.IllegalTransactionStateException;
import org.springframework.transaction.support.TransactionSynchronizationManager;

class RedisSecurityStateOperationsTests {

	private static final String KEY_SECRET = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

	private static final SecurityStateKey KEY =
			new SecurityStateKey(TenantId.DEFAULT, "mfa-login", "user:internal-123");

	private static final SecurityStateToken TOKEN =
			SecurityStateToken.from("0123456789abcdefghijklmnopqrstuvwxyz-ABCDEF");

	private final StringRedisTemplate redis = mock(StringRedisTemplate.class);

	@SuppressWarnings("unchecked")
	private final ValueOperations<String, String> values = mock(ValueOperations.class);

	private final SimpleMeterRegistry meterRegistry = new SimpleMeterRegistry();

	private final SecurityStateProperties properties =
			new SecurityStateProperties(Duration.ofMinutes(15), KEY_SECRET, "iam:security-state");

	private final RedisSecurityStateOperations operations = operations(this.properties, () -> TOKEN);

	RedisSecurityStateOperationsTests() {
		when(this.redis.opsForValue()).thenReturn(this.values);
	}

	@Test
	void atomicallyIssuesConsumesAndRejectsReplay() {
		String encodedKey = encodedKey(KEY, TOKEN);
		when(this.values.setIfAbsent(encodedKey, "1", Duration.ofMinutes(5))).thenReturn(true);
		when(this.values.getAndDelete(encodedKey)).thenReturn("1").thenReturn(null);

		SecurityStateIssue issued = this.operations.issue(KEY, Duration.ofMinutes(5));
		SecurityStateConsumeStatus consumed = this.operations.consume(KEY, TOKEN);
		SecurityStateConsumeStatus replayed = this.operations.consume(KEY, TOKEN);

		assertThat(issued.status()).isEqualTo(SecurityStateIssueStatus.ISSUED);
		assertThat(issued.token()).contains(TOKEN);
		assertThat(consumed).isEqualTo(SecurityStateConsumeStatus.CONSUMED);
		assertThat(replayed).isEqualTo(SecurityStateConsumeStatus.REJECTED);
		assertThat(issueCount("issued")).isEqualTo(1.0);
		assertThat(consumeCount("consumed")).isEqualTo(1.0);
		assertThat(consumeCount("rejected")).isEqualTo(1.0);
	}

	@Test
	void retriesAnImprobableTokenCollision() {
		SecurityStateToken second = SecurityStateToken.from("A".repeat(SecurityStateToken.ENCODED_LENGTH));
		@SuppressWarnings("unchecked")
		Supplier<SecurityStateToken> issuer = mock(Supplier.class);
		when(issuer.get()).thenReturn(TOKEN, second);
		when(this.values.setIfAbsent(encodedKey(KEY, TOKEN), "1", Duration.ofMinutes(5))).thenReturn(false);
		when(this.values.setIfAbsent(encodedKey(KEY, second), "1", Duration.ofMinutes(5))).thenReturn(true);
		RedisSecurityStateOperations operations = operations(this.properties, issuer);

		SecurityStateIssue result = operations.issue(KEY, Duration.ofMinutes(5));

		assertThat(result.token()).contains(second);
		verify(issuer, times(2)).get();
	}

	@Test
	void failsClosedWhenConfigurationOrRedisIsUnavailable() {
		RedisSecurityStateOperations unconfigured = new RedisSecurityStateOperations(this.redis,
				new SecurityStateProperties(Duration.ofMinutes(15), null, "iam:security-state"),
				new SimpleMeterRegistry(), () -> TOKEN);

		assertThat(unconfigured.issue(KEY, Duration.ofMinutes(5)))
			.isSameAs(SecurityStateIssue.unavailable());
		assertThat(unconfigured.consume(KEY, TOKEN)).isEqualTo(SecurityStateConsumeStatus.UNAVAILABLE);

		when(this.values.setIfAbsent(encodedKey(KEY, TOKEN), "1", Duration.ofMinutes(5)))
			.thenThrow(new RedisConnectionFailureException("unavailable"));
		when(this.values.getAndDelete(encodedKey(KEY, TOKEN)))
			.thenThrow(new RedisConnectionFailureException("unavailable"));
		assertThat(this.operations.issue(KEY, Duration.ofMinutes(5)))
			.isSameAs(SecurityStateIssue.unavailable());
		assertThat(this.operations.consume(KEY, TOKEN)).isEqualTo(SecurityStateConsumeStatus.UNAVAILABLE);
		assertThat(issueCount("unavailable")).isEqualTo(1.0);
		assertThat(consumeCount("unavailable")).isEqualTo(1.0);
	}

	@Test
	void rejectsInvalidInputsBeforeAccessingRedis() {
		assertThatThrownBy(() -> this.operations.issue(null, Duration.ofMinutes(1)))
			.isInstanceOf(NullPointerException.class);
		assertThatThrownBy(() -> this.operations.issue(KEY, null)).isInstanceOf(NullPointerException.class);
		assertThatThrownBy(() -> this.operations.issue(KEY, Duration.ZERO))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> this.operations.issue(KEY, Duration.ofMinutes(16)))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> this.operations.consume(null, TOKEN)).isInstanceOf(NullPointerException.class);
		assertThatThrownBy(() -> this.operations.consume(KEY, null)).isInstanceOf(NullPointerException.class);
		verifyNoInteractions(this.values);
	}

	@Test
	void refusesRedisAccessInsideADatabaseTransaction() {
		TransactionSynchronizationManager.setActualTransactionActive(true);
		try {
			assertThatThrownBy(() -> this.operations.issue(KEY, Duration.ofMinutes(1)))
				.isInstanceOf(IllegalTransactionStateException.class);
			assertThatThrownBy(() -> this.operations.consume(KEY, TOKEN))
				.isInstanceOf(IllegalTransactionStateException.class);
		}
		finally {
			TransactionSynchronizationManager.setActualTransactionActive(false);
		}

		verifyNoInteractions(this.values);
	}

	private RedisSecurityStateOperations operations(SecurityStateProperties stateProperties,
			Supplier<SecurityStateToken> issuer) {
		return new RedisSecurityStateOperations(this.redis, stateProperties, this.meterRegistry, issuer);
	}

	private String encodedKey(SecurityStateKey key, SecurityStateToken token) {
		byte[] secret = Base64.getDecoder().decode(KEY_SECRET);
		try {
			return new SecurityStateKeys(secret, this.properties.keyPrefix()).encode(key, token);
		}
		finally {
			Arrays.fill(secret, (byte) 0);
		}
	}

	private double issueCount(String status) {
		return this.meterRegistry.get(RedisSecurityStateOperations.ISSUE_METRIC)
			.tags("status", status)
			.counter()
			.count();
	}

	private double consumeCount(String status) {
		return this.meterRegistry.get(RedisSecurityStateOperations.CONSUME_METRIC)
			.tags("status", status)
			.counter()
			.count();
	}

}
