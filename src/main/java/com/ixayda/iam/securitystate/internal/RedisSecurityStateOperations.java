package com.ixayda.iam.securitystate.internal;

import java.security.SecureRandom;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.EnumMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.function.Supplier;

import com.ixayda.iam.securitystate.SecurityStateConsumeStatus;
import com.ixayda.iam.securitystate.SecurityStateIssue;
import com.ixayda.iam.securitystate.SecurityStateIssueStatus;
import com.ixayda.iam.securitystate.SecurityStateKey;
import com.ixayda.iam.securitystate.SecurityStateOperations;
import com.ixayda.iam.securitystate.SecurityStateToken;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.transaction.IllegalTransactionStateException;
import org.springframework.transaction.support.TransactionSynchronizationManager;

final class RedisSecurityStateOperations implements SecurityStateOperations {

	static final String ISSUE_METRIC = "iam.security.state.issues";

	static final String CONSUME_METRIC = "iam.security.state.consumptions";

	private static final int TOKEN_BYTES = 32;

	private static final int MAXIMUM_ISSUE_ATTEMPTS = 3;

	private static final String VALUE_MARKER = "1";

	private final StringRedisTemplate redis;

	private final SecurityStateProperties properties;

	private final SecurityStateKeys keys;

	private final Supplier<SecurityStateToken> tokenIssuer;

	private final Map<SecurityStateIssueStatus, Counter> issueCounters;

	private final Map<SecurityStateConsumeStatus, Counter> consumeCounters;

	RedisSecurityStateOperations(StringRedisTemplate redis, SecurityStateProperties properties,
			MeterRegistry meterRegistry) {
		this(redis, properties, meterRegistry, secureTokenIssuer());
	}

	RedisSecurityStateOperations(StringRedisTemplate redis, SecurityStateProperties properties,
			MeterRegistry meterRegistry, Supplier<SecurityStateToken> tokenIssuer) {
		this.redis = Objects.requireNonNull(redis, "String Redis template must not be null");
		this.properties = Objects.requireNonNull(properties, "Security state properties must not be null");
		Objects.requireNonNull(meterRegistry, "Meter registry must not be null");
		this.tokenIssuer = Objects.requireNonNull(tokenIssuer, "Security state token issuer must not be null");
		byte[] keySecret = properties.decodedKeySecret().orElse(null);
		try {
			this.keys = keySecret == null ? null : new SecurityStateKeys(keySecret, properties.keyPrefix());
		}
		finally {
			if (keySecret != null) {
				Arrays.fill(keySecret, (byte) 0);
			}
		}
		this.issueCounters = counters(meterRegistry, ISSUE_METRIC, "One-time security state issue outcomes",
				SecurityStateIssueStatus.class);
		this.consumeCounters = counters(meterRegistry, CONSUME_METRIC,
				"One-time security state consumption outcomes", SecurityStateConsumeStatus.class);
	}

	@Override
	public SecurityStateIssue issue(SecurityStateKey key, Duration timeToLive) {
		Objects.requireNonNull(key, "Security state key must not be null");
		Duration validatedTtl = this.properties.validateTtl(timeToLive);
		requireNoTransaction();
		if (this.keys == null) {
			return record(SecurityStateIssue.unavailable());
		}

		for (int attempt = 0; attempt < MAXIMUM_ISSUE_ATTEMPTS; attempt++) {
			SecurityStateToken token = Objects.requireNonNull(this.tokenIssuer.get(),
					"Issued security state token must not be null");
			Boolean stored;
			try {
				stored = this.redis.opsForValue()
					.setIfAbsent(this.keys.encode(key, token), VALUE_MARKER, validatedTtl);
			}
			catch (DataAccessException exception) {
				return record(SecurityStateIssue.unavailable());
			}
			if (Boolean.TRUE.equals(stored)) {
				return record(SecurityStateIssue.issued(token));
			}
			if (stored == null) {
				return record(SecurityStateIssue.unavailable());
			}
		}
		return record(SecurityStateIssue.unavailable());
	}

	@Override
	public SecurityStateConsumeStatus consume(SecurityStateKey key, SecurityStateToken token) {
		Objects.requireNonNull(key, "Security state key must not be null");
		Objects.requireNonNull(token, "Security state token must not be null");
		requireNoTransaction();
		if (this.keys == null) {
			return record(SecurityStateConsumeStatus.UNAVAILABLE);
		}

		String value;
		try {
			value = this.redis.opsForValue().getAndDelete(this.keys.encode(key, token));
		}
		catch (DataAccessException exception) {
			return record(SecurityStateConsumeStatus.UNAVAILABLE);
		}
		return record(VALUE_MARKER.equals(value) ? SecurityStateConsumeStatus.CONSUMED
				: SecurityStateConsumeStatus.REJECTED);
	}

	private SecurityStateIssue record(SecurityStateIssue issue) {
		this.issueCounters.get(issue.status()).increment();
		return issue;
	}

	private SecurityStateConsumeStatus record(SecurityStateConsumeStatus status) {
		this.consumeCounters.get(status).increment();
		return status;
	}

	private static <E extends Enum<E>> Map<E, Counter> counters(MeterRegistry registry, String metric,
			String description, Class<E> statusType) {
		Map<E, Counter> counters = new EnumMap<>(statusType);
		for (E status : statusType.getEnumConstants()) {
			counters.put(status, Counter.builder(metric)
				.description(description)
				.tag("status", status.name().toLowerCase(Locale.ROOT))
				.register(registry));
		}
		return Map.copyOf(counters);
	}

	private static Supplier<SecurityStateToken> secureTokenIssuer() {
		SecureRandom random = new SecureRandom();
		return () -> issueToken(random);
	}

	private static SecurityStateToken issueToken(SecureRandom randomGenerator) {
		byte[] random = new byte[TOKEN_BYTES];
		randomGenerator.nextBytes(random);
		try {
			return SecurityStateToken.from(Base64.getUrlEncoder().withoutPadding().encodeToString(random));
		}
		finally {
			Arrays.fill(random, (byte) 0);
		}
	}

	private static void requireNoTransaction() {
		if (TransactionSynchronizationManager.isActualTransactionActive()) {
			throw new IllegalTransactionStateException(
					"One-time security state operations must not run inside a database transaction");
		}
	}

}
