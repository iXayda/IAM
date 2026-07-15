package com.ixayda.iam.ratelimit.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Locale;

import com.ixayda.iam.ratelimit.LoginAttemptDecision;
import com.ixayda.iam.ratelimit.LoginAttemptKey;
import com.ixayda.iam.ratelimit.LoginAttemptLease;
import com.ixayda.iam.ratelimit.LoginAttemptSource;
import com.ixayda.iam.ratelimit.LoginAttemptStatus;
import com.ixayda.iam.ratelimit.internal.LoginRateLimitKeys.Keys;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.LoginKey;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.transaction.IllegalTransactionStateException;
import org.springframework.transaction.support.TransactionSynchronizationManager;

class RedisLoginAttemptLimiterTests {

	private static final String KEY_SECRET = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

	private static final LoginAttemptLease LEASE = LoginAttemptLease.from("AAAAAAAAAAAAAAAAAAAAAA");

	private static final LoginAttemptKey KEY = new LoginAttemptKey(TenantId.DEFAULT, LoginKey.from("alice"),
			LoginAttemptSource.trusted("203.0.113.10"));

	private final StringRedisTemplate redis = mock(StringRedisTemplate.class);

	private final RedisScript<Long> acquireScript = script();

	private final RedisScript<Boolean> clearScript = script();

	private final SimpleMeterRegistry meterRegistry = new SimpleMeterRegistry();

	private final LoginRateLimitProperties properties = properties(KEY_SECRET);

	private final RedisLoginAttemptLimiter limiter = new RedisLoginAttemptLimiter(this.redis, this.acquireScript,
			this.clearScript, this.properties, this.meterRegistry, () -> LEASE);

	@Test
	void mapsScriptResultsToAllowedAndThrottledDecisions() {
		when(execute()).thenReturn(0L, 12_345L);

		LoginAttemptDecision allowed = this.limiter.acquire(KEY);
		LoginAttemptDecision throttled = this.limiter.acquire(KEY);

		assertThat(allowed.status()).isEqualTo(LoginAttemptStatus.ALLOWED);
		assertThat(allowed.lease()).contains(LEASE);
		assertThat(throttled.status()).isEqualTo(LoginAttemptStatus.THROTTLED);
		assertThat(throttled.retryAfter()).contains(Duration.ofMillis(12_345));
		assertThat(counter(LoginAttemptStatus.ALLOWED)).isEqualTo(1.0);
		assertThat(counter(LoginAttemptStatus.THROTTLED)).isEqualTo(1.0);
	}

	@Test
	void failsClosedForMissingConfigurationOrRedisFailures() {
		RedisLoginAttemptLimiter unconfigured = new RedisLoginAttemptLimiter(this.redis, this.acquireScript,
				this.clearScript, properties(null), this.meterRegistry, () -> LEASE);

		assertThat(unconfigured.acquire(KEY).status()).isEqualTo(LoginAttemptStatus.UNAVAILABLE);
		verifyNoInteractions(this.redis);

		when(execute()).thenThrow(new RedisConnectionFailureException("unavailable"));
		assertThat(this.limiter.acquire(KEY).status()).isEqualTo(LoginAttemptStatus.UNAVAILABLE);
		assertThat(counter(LoginAttemptStatus.UNAVAILABLE)).isEqualTo(2.0);
	}

	@Test
	void clearsOnlyTheMatchingPrincipalLeaseAfterSuccess() {
		Keys encoded = encoded();
		when(clear()).thenReturn(true);

		this.limiter.recordSuccess(KEY, LEASE);

		verify(this.redis).execute(this.clearScript, List.of(encoded.lease(), encoded.principal()), LEASE.value());
		assertThat(this.meterRegistry.get(RedisLoginAttemptLimiter.RESET_METRIC)
			.tags("status", "cleared")
			.counter()
			.count()).isEqualTo(1.0);
	}

	@Test
	void recordsStaleLeasesAndRedisResetFailuresWithoutThrowing() {
		when(clear()).thenReturn(false).thenThrow(new RedisConnectionFailureException("unavailable"));

		this.limiter.recordSuccess(KEY, LEASE);
		this.limiter.recordSuccess(KEY, LEASE);

		assertThat(resetCounter("stale")).isEqualTo(1.0);
		assertThat(resetCounter("unavailable")).isEqualTo(1.0);
	}

	@Test
	void refusesRedisAccessInsideADatabaseTransaction() {
		TransactionSynchronizationManager.setActualTransactionActive(true);
		try {
			assertThatThrownBy(() -> this.limiter.acquire(KEY))
				.isInstanceOf(IllegalTransactionStateException.class);
			assertThatThrownBy(() -> this.limiter.recordSuccess(KEY, LEASE))
				.isInstanceOf(IllegalTransactionStateException.class);
		}
		finally {
			TransactionSynchronizationManager.setActualTransactionActive(false);
		}

		verifyNoInteractions(this.redis);
	}

	private Long execute() {
		Keys encoded = encoded();
		return this.redis.execute(this.acquireScript, List.of(encoded.principal(), encoded.source(), encoded.lease()),
				"5", "900000", "100", "60000", LEASE.value());
	}

	private Boolean clear() {
		Keys encoded = encoded();
		return this.redis.execute(this.clearScript, List.of(encoded.lease(), encoded.principal()), LEASE.value());
	}

	private Keys encoded() {
		return new LoginRateLimitKeys(Base64.getDecoder().decode(KEY_SECRET), this.properties.keyPrefix()).encode(KEY);
	}

	private double counter(LoginAttemptStatus status) {
		return this.meterRegistry.get(RedisLoginAttemptLimiter.DECISION_METRIC)
			.tags("status", status.name().toLowerCase(Locale.ROOT))
			.counter()
			.count();
	}

	private double resetCounter(String status) {
		return this.meterRegistry.get(RedisLoginAttemptLimiter.RESET_METRIC)
			.tags("status", status)
			.counter()
			.count();
	}

	private static LoginRateLimitProperties properties(String keySecret) {
		return new LoginRateLimitProperties(5, Duration.ofMinutes(15), 100, Duration.ofMinutes(1), keySecret,
				"iam:ratelimit:login");
	}

	@SuppressWarnings("unchecked")
	private static <T> RedisScript<T> script() {
		return mock(RedisScript.class);
	}

}
