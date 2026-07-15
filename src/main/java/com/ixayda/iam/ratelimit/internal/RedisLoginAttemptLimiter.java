package com.ixayda.iam.ratelimit.internal;

import java.security.SecureRandom;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.EnumMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.function.Supplier;

import com.ixayda.iam.ratelimit.LoginAttemptDecision;
import com.ixayda.iam.ratelimit.LoginAttemptKey;
import com.ixayda.iam.ratelimit.LoginAttemptLease;
import com.ixayda.iam.ratelimit.LoginAttemptLimiter;
import com.ixayda.iam.ratelimit.LoginAttemptStatus;
import com.ixayda.iam.ratelimit.internal.LoginRateLimitKeys.Keys;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.transaction.IllegalTransactionStateException;
import org.springframework.transaction.support.TransactionSynchronizationManager;

final class RedisLoginAttemptLimiter implements LoginAttemptLimiter {

	static final String DECISION_METRIC = "iam.auth.login.rate_limit.decisions";

	static final String RESET_METRIC = "iam.auth.login.rate_limit.resets";

	private final StringRedisTemplate redis;

	private final RedisScript<Long> acquireScript;

	private final RedisScript<Boolean> clearScript;

	private final LoginRateLimitProperties properties;

	private final LoginRateLimitKeys keys;

	private final Supplier<LoginAttemptLease> leaseIssuer;

	private final Map<LoginAttemptStatus, Counter> decisionCounters;

	private final Map<String, Counter> resetCounters;

	RedisLoginAttemptLimiter(StringRedisTemplate redis, RedisScript<Long> acquireScript, RedisScript<Boolean> clearScript,
			LoginRateLimitProperties properties, MeterRegistry meterRegistry) {
		this(redis, acquireScript, clearScript, properties, meterRegistry, secureLeaseIssuer());
	}

	RedisLoginAttemptLimiter(StringRedisTemplate redis, RedisScript<Long> acquireScript, RedisScript<Boolean> clearScript,
			LoginRateLimitProperties properties, MeterRegistry meterRegistry, Supplier<LoginAttemptLease> leaseIssuer) {
		this.redis = Objects.requireNonNull(redis, "String Redis template must not be null");
		this.acquireScript = Objects.requireNonNull(acquireScript, "Login rate-limit script must not be null");
		this.clearScript = Objects.requireNonNull(clearScript, "Login rate-limit clear script must not be null");
		this.properties = Objects.requireNonNull(properties, "Login rate-limit properties must not be null");
		Objects.requireNonNull(meterRegistry, "Meter registry must not be null");
		this.leaseIssuer = Objects.requireNonNull(leaseIssuer, "Login attempt lease issuer must not be null");
		byte[] keySecret = properties.decodedKeySecret().orElse(null);
		try {
			this.keys = keySecret == null ? null : new LoginRateLimitKeys(keySecret, properties.keyPrefix());
		}
		finally {
			if (keySecret != null) {
				Arrays.fill(keySecret, (byte) 0);
			}
		}
		this.decisionCounters = decisionCounters(meterRegistry);
		this.resetCounters = Map.of("cleared", resetCounter(meterRegistry, "cleared"), "stale",
				resetCounter(meterRegistry, "stale"), "unavailable", resetCounter(meterRegistry, "unavailable"));
	}

	@Override
	public LoginAttemptDecision acquire(LoginAttemptKey key) {
		Objects.requireNonNull(key, "Login attempt key must not be null");
		requireNoTransaction();
		if (this.keys == null) {
			return record(LoginAttemptDecision.unavailable());
		}
		LoginAttemptLease lease = Objects.requireNonNull(this.leaseIssuer.get(),
				"Issued login attempt lease must not be null");
		Keys encoded = this.keys.encode(key);
		Long retryAfterMillis;
		try {
			retryAfterMillis = this.redis.execute(this.acquireScript,
					List.of(encoded.principal(), encoded.source(), encoded.lease()),
					Integer.toString(this.properties.principalLimit()),
					Long.toString(this.properties.principalWindow().toMillis()),
					Integer.toString(this.properties.sourceLimit()),
					Long.toString(this.properties.sourceWindow().toMillis()), lease.value());
		}
		catch (DataAccessException exception) {
			return record(LoginAttemptDecision.unavailable());
		}
		if (retryAfterMillis == null || retryAfterMillis < 0) {
			return record(LoginAttemptDecision.unavailable());
		}
		if (retryAfterMillis == 0) {
			return record(LoginAttemptDecision.allowed(lease));
		}
		return record(LoginAttemptDecision.throttled(Duration.ofMillis(retryAfterMillis)));
	}

	@Override
	public void recordSuccess(LoginAttemptKey key, LoginAttemptLease lease) {
		Objects.requireNonNull(key, "Login attempt key must not be null");
		Objects.requireNonNull(lease, "Login attempt lease must not be null");
		requireNoTransaction();
		if (this.keys == null) {
			recordReset("unavailable");
			return;
		}
		Keys encoded = this.keys.encode(key);
		try {
			Boolean cleared = this.redis.execute(this.clearScript, List.of(encoded.lease(), encoded.principal()),
					lease.value());
			recordReset(Boolean.TRUE.equals(cleared) ? "cleared" : "stale");
		}
		catch (DataAccessException exception) {
			recordReset("unavailable");
		}
	}

	private LoginAttemptDecision record(LoginAttemptDecision decision) {
		this.decisionCounters.get(decision.status()).increment();
		return decision;
	}

	private void recordReset(String status) {
		this.resetCounters.get(status).increment();
	}

	private static Map<LoginAttemptStatus, Counter> decisionCounters(MeterRegistry registry) {
		Map<LoginAttemptStatus, Counter> counters = new EnumMap<>(LoginAttemptStatus.class);
		for (LoginAttemptStatus status : LoginAttemptStatus.values()) {
			counters.put(status, Counter.builder(DECISION_METRIC)
				.description("Login rate-limit decisions")
				.tag("status", status.name().toLowerCase(Locale.ROOT))
				.register(registry));
		}
		return Map.copyOf(counters);
	}

	private static Counter resetCounter(MeterRegistry registry, String status) {
		return Counter.builder(RESET_METRIC)
			.description("Login rate-limit principal reset outcomes")
			.tag("status", status)
			.register(registry);
	}

	private static Supplier<LoginAttemptLease> secureLeaseIssuer() {
		SecureRandom random = new SecureRandom();
		return () -> issueLease(random);
	}

	private static LoginAttemptLease issueLease(SecureRandom randomGenerator) {
		byte[] random = new byte[16];
		randomGenerator.nextBytes(random);
		try {
			return LoginAttemptLease.from(Base64.getUrlEncoder().withoutPadding().encodeToString(random));
		}
		finally {
			Arrays.fill(random, (byte) 0);
		}
	}

	private static void requireNoTransaction() {
		if (TransactionSynchronizationManager.isActualTransactionActive()) {
			throw new IllegalTransactionStateException(
					"Login rate limiting must not run inside a database transaction");
		}
	}

}
