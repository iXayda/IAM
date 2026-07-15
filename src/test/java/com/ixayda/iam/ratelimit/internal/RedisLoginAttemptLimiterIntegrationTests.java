package com.ixayda.iam.ratelimit.internal;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import com.ixayda.iam.ApplicationIntegrationTest;
import com.ixayda.iam.ratelimit.LoginAttemptDecision;
import com.ixayda.iam.ratelimit.LoginAttemptKey;
import com.ixayda.iam.ratelimit.LoginAttemptLease;
import com.ixayda.iam.ratelimit.LoginAttemptLimiter;
import com.ixayda.iam.ratelimit.LoginAttemptSource;
import com.ixayda.iam.ratelimit.LoginAttemptStatus;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.LoginKey;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.data.redis.serializer.StringRedisSerializer;

class RedisLoginAttemptLimiterIntegrationTests extends ApplicationIntegrationTest {

	private static final String KEY_SECRET = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

	@Autowired
	private LoginAttemptLimiter limiter;

	@Autowired
	private StringRedisTemplate redis;

	@Autowired
	private RedisScript<Long> acquireScript;

	@Autowired
	private RedisScript<Boolean> clearScript;

	@Autowired
	private ListableBeanFactory beanFactory;

	@AfterEach
	void deleteRateLimitKeys() {
		var keys = this.redis.keys("iam:test:ratelimit:*");
		if (keys != null && !keys.isEmpty()) {
			this.redis.delete(keys);
		}
	}

	@Test
	void enforcesPrincipalAndSourceLimitsWithFixedTtls() {
		assertThat(this.limiter.acquire(key("wired", uniqueSource())).status())
			.isEqualTo(LoginAttemptStatus.ALLOWED);
		LimiterFixture shortFixture = fixture(3, Duration.ofSeconds(2), 4, Duration.ofSeconds(3));
		LoginAttemptLimiter shortLimiter = shortFixture.limiter();
		LoginAttemptKey principal = key("alice", uniqueSource());

		assertThat(shortLimiter.acquire(principal).status()).isEqualTo(LoginAttemptStatus.ALLOWED);
		LoginRateLimitKeys.Keys encoded = shortFixture.keys(principal);
		long initialTtl = ttlMillis(encoded.principal());
		assertThat(Math.abs(initialTtl - ttlMillis(encoded.lease()))).isLessThanOrEqualTo(100);
		long beforeSecondAcquire = awaitTtlAtMost(encoded.principal(), initialTtl - 100, Duration.ofSeconds(1));
		assertThat(shortLimiter.acquire(principal).status()).isEqualTo(LoginAttemptStatus.ALLOWED);
		assertThat(ttlMillis(encoded.principal())).isLessThanOrEqualTo(beforeSecondAcquire);
		assertThat(shortLimiter.acquire(principal).status()).isEqualTo(LoginAttemptStatus.ALLOWED);
		LoginAttemptDecision principalThrottle = shortLimiter.acquire(principal);

		assertThat(principalThrottle.status()).isEqualTo(LoginAttemptStatus.THROTTLED);
		assertThat(principalThrottle.retryAfter()).hasValueSatisfying(retryAfter -> assertThat(retryAfter)
			.isPositive()
			.isLessThanOrEqualTo(Duration.ofSeconds(2)));

		String sharedSource = uniqueSource();
		for (int index = 0; index < 4; index++) {
			assertThat(shortLimiter.acquire(key("source-user-" + index, sharedSource)).status())
				.isEqualTo(LoginAttemptStatus.ALLOWED);
		}
		assertThat(shortLimiter.acquire(key("source-user-4", sharedSource)).status())
			.isEqualTo(LoginAttemptStatus.THROTTLED);
	}

	@Test
	@SuppressWarnings("rawtypes")
	void exposesOnlyAStringSerializedRedisTemplate() {
		var templates = this.beanFactory.getBeansOfType(RedisTemplate.class);

		assertThat(templates).containsOnlyKeys("redisTemplate");
		assertThat(templates.get("redisTemplate")).isInstanceOf(StringRedisTemplate.class);
		RedisTemplate template = templates.get("redisTemplate");
		assertThat(template.getKeySerializer()).isInstanceOf(StringRedisSerializer.class);
		assertThat(template.getValueSerializer()).isInstanceOf(StringRedisSerializer.class);
		assertThat(template.getHashKeySerializer()).isInstanceOf(StringRedisSerializer.class);
		assertThat(template.getHashValueSerializer()).isInstanceOf(StringRedisSerializer.class);
	}

	@Test
	void atomicallyAllowsExactlyTheConfiguredConcurrentBudget() throws Exception {
		LoginAttemptLimiter concurrentLimiter = limiter(5, Duration.ofMinutes(1), 100, Duration.ofMinutes(1));
		LoginAttemptKey key = key("concurrent", uniqueSource());
		List<Future<LoginAttemptDecision>> futures = new ArrayList<>();

		try (ExecutorService executor = Executors.newFixedThreadPool(16)) {
			for (int index = 0; index < 32; index++) {
				futures.add(executor.submit(() -> concurrentLimiter.acquire(key)));
			}
		}

		long allowed = 0;
		for (Future<LoginAttemptDecision> future : futures) {
			if (future.get(5, TimeUnit.SECONDS).status() == LoginAttemptStatus.ALLOWED) {
				allowed++;
			}
		}
		assertThat(allowed).isEqualTo(5);
	}

	@Test
	void sharesThePrincipalBudgetAcrossLimiterInstances() {
		String prefix = "iam:test:ratelimit:" + UUID.randomUUID().toString().replace("-", "");
		LoginRateLimitProperties properties = new LoginRateLimitProperties(2, Duration.ofMinutes(1), 100,
				Duration.ofMinutes(1), KEY_SECRET, prefix);
		LoginAttemptLimiter first = new RedisLoginAttemptLimiter(this.redis, this.acquireScript, this.clearScript,
				properties, new SimpleMeterRegistry());
		LoginAttemptLimiter second = new RedisLoginAttemptLimiter(this.redis, this.acquireScript, this.clearScript,
				properties, new SimpleMeterRegistry());
		LoginAttemptKey key = key("shared-instances", uniqueSource());

		assertThat(first.acquire(key).status()).isEqualTo(LoginAttemptStatus.ALLOWED);
		assertThat(second.acquire(key).status()).isEqualTo(LoginAttemptStatus.ALLOWED);
		assertThat(first.acquire(key).status()).isEqualTo(LoginAttemptStatus.THROTTLED);
	}

	@Test
	void resetsThePrincipalBudgetWithoutResettingTheSourceBudget() {
		LoginAttemptLimiter scopedLimiter = limiter(1, Duration.ofMinutes(1), 2, Duration.ofMinutes(1));
		String source = uniqueSource();
		LoginAttemptKey first = key("reset-one", source);

		LoginAttemptDecision allowed = scopedLimiter.acquire(first);
		assertThat(allowed.status()).isEqualTo(LoginAttemptStatus.ALLOWED);
		scopedLimiter.recordSuccess(first, allowed.lease().orElseThrow());
		assertThat(scopedLimiter.acquire(first).status()).isEqualTo(LoginAttemptStatus.ALLOWED);
		assertThat(scopedLimiter.acquire(key("reset-two", source)).status())
			.isEqualTo(LoginAttemptStatus.THROTTLED);
	}

	@Test
	void allowsOnlyTheLatestLeaseToClearAConcurrentPrincipalBudget() {
		LimiterFixture fixture = fixture(2, Duration.ofMinutes(1), 100, Duration.ofMinutes(1));
		LoginAttemptLimiter concurrentLimiter = fixture.limiter();
		LoginAttemptKey key = key("lease-order", uniqueSource());
		LoginAttemptDecision first = concurrentLimiter.acquire(key);
		LoginAttemptDecision second = concurrentLimiter.acquire(key);

		concurrentLimiter.recordSuccess(key, first.lease().orElseThrow());
		assertThat(fixture.resetCount("stale")).isEqualTo(1.0);
		concurrentLimiter.recordSuccess(key, second.lease().orElseThrow());
		assertThat(fixture.resetCount("cleared")).isEqualTo(1.0);

		assertThat(concurrentLimiter.acquire(key).status()).isEqualTo(LoginAttemptStatus.ALLOWED);
	}

	@Test
	void rejectsLeasesInvalidatedByLaterAttemptsOtherKeysOrReplay() {
		LoginAttemptLimiter singleAttemptLimiter = limiter(1, Duration.ofMinutes(1), 100, Duration.ofMinutes(1));
		LoginAttemptKey original = key("lease-original", uniqueSource());
		LoginAttemptDecision originalAllowed = singleAttemptLimiter.acquire(original);

		assertThat(singleAttemptLimiter.acquire(original).status()).isEqualTo(LoginAttemptStatus.THROTTLED);
		singleAttemptLimiter.recordSuccess(original, originalAllowed.lease().orElseThrow());
		assertThat(singleAttemptLimiter.acquire(original).status()).isEqualTo(LoginAttemptStatus.THROTTLED);

		LoginAttemptLimiter otherKeyLimiter = limiter(1, Duration.ofMinutes(1), 100, Duration.ofMinutes(1));
		LoginAttemptKey otherKeyOriginal = key("lease-other-key", uniqueSource());
		LoginAttemptLease otherKeyLease = otherKeyLimiter.acquire(otherKeyOriginal).lease().orElseThrow();
		otherKeyLimiter.recordSuccess(key("lease-different", otherKeyOriginal.source().value()), otherKeyLease);
		assertThat(otherKeyLimiter.acquire(otherKeyOriginal).status()).isEqualTo(LoginAttemptStatus.THROTTLED);

		LoginAttemptLimiter otherTenantLimiter = limiter(1, Duration.ofMinutes(1), 100, Duration.ofMinutes(1));
		LoginAttemptKey otherTenantOriginal = key("lease-other-tenant", uniqueSource());
		LoginAttemptLease otherTenantLease = otherTenantLimiter.acquire(otherTenantOriginal).lease().orElseThrow();
		otherTenantLimiter.recordSuccess(
				new LoginAttemptKey(TenantId.random(), otherTenantOriginal.loginKey(), otherTenantOriginal.source()),
				otherTenantLease);
		assertThat(otherTenantLimiter.acquire(otherTenantOriginal).status())
			.isEqualTo(LoginAttemptStatus.THROTTLED);

		LimiterFixture replayFixture = fixture(1, Duration.ofMinutes(1), 100, Duration.ofMinutes(1));
		LoginAttemptKey replayKey = key("lease-replay", uniqueSource());
		LoginAttemptLease replayLease = replayFixture.limiter().acquire(replayKey).lease().orElseThrow();
		replayFixture.limiter().recordSuccess(replayKey, replayLease);
		replayFixture.limiter().recordSuccess(replayKey, replayLease);
		assertThat(replayFixture.resetCount("cleared")).isEqualTo(1.0);
		assertThat(replayFixture.resetCount("stale")).isEqualTo(1.0);
		assertThat(replayFixture.limiter().acquire(replayKey).status()).isEqualTo(LoginAttemptStatus.ALLOWED);
	}

	@Test
	void isolatesTenantsAndRecoversAfterWindowExpiry() throws Exception {
		LoginAttemptLimiter expiringLimiter = limiter(1, Duration.ofMillis(100), 10, Duration.ofMillis(100));
		String source = uniqueSource();
		LoginAttemptKey firstTenant = key(TenantId.DEFAULT, "expiry", source);
		LoginAttemptKey secondTenant = key(TenantId.random(), "expiry", source);

		assertThat(expiringLimiter.acquire(firstTenant).status()).isEqualTo(LoginAttemptStatus.ALLOWED);
		assertThat(expiringLimiter.acquire(firstTenant).status()).isEqualTo(LoginAttemptStatus.THROTTLED);
		assertThat(expiringLimiter.acquire(secondTenant).status()).isEqualTo(LoginAttemptStatus.ALLOWED);
		assertThat(awaitAllowed(expiringLimiter, firstTenant, Duration.ofSeconds(2))).isTrue();
	}

	private LoginAttemptLimiter limiter(int principalLimit, Duration principalWindow, int sourceLimit,
			Duration sourceWindow) {
		return fixture(principalLimit, principalWindow, sourceLimit, sourceWindow).limiter();
	}

	private LimiterFixture fixture(int principalLimit, Duration principalWindow, int sourceLimit,
			Duration sourceWindow) {
		String prefix = "iam:test:ratelimit:" + UUID.randomUUID().toString().replace("-", "");
		LoginRateLimitProperties properties = new LoginRateLimitProperties(principalLimit, principalWindow, sourceLimit,
				sourceWindow, KEY_SECRET, prefix);
		SimpleMeterRegistry meterRegistry = new SimpleMeterRegistry();
		return new LimiterFixture(new RedisLoginAttemptLimiter(this.redis, this.acquireScript, this.clearScript,
				properties, meterRegistry), meterRegistry, properties);
	}

	private static LoginAttemptKey key(String login, String source) {
		return key(TenantId.DEFAULT, login, source);
	}

	private static LoginAttemptKey key(TenantId tenantId, String login, String source) {
		return new LoginAttemptKey(tenantId, LoginKey.from(login), LoginAttemptSource.trusted(source));
	}

	private static String uniqueSource() {
		return "source-" + UUID.randomUUID();
	}

	private static boolean awaitAllowed(LoginAttemptLimiter limiter, LoginAttemptKey key, Duration timeout)
			throws InterruptedException {
		long deadline = System.nanoTime() + timeout.toNanos();
		do {
			if (limiter.acquire(key).status() == LoginAttemptStatus.ALLOWED) {
				return true;
			}
			Thread.sleep(10);
		}
		while (System.nanoTime() < deadline);
		return false;
	}

	private long awaitTtlAtMost(String key, long expectedMaximum, Duration timeout) {
		long deadline = System.nanoTime() + timeout.toNanos();
		long ttl;
		do {
			ttl = ttlMillis(key);
			if (ttl <= expectedMaximum) {
				return ttl;
			}
			try {
				Thread.sleep(5);
			}
			catch (InterruptedException exception) {
				Thread.currentThread().interrupt();
				throw new IllegalStateException("Interrupted while waiting for Redis TTL", exception);
			}
		}
		while (System.nanoTime() < deadline);
		return ttl;
	}

	private long ttlMillis(String key) {
		Long ttl = this.redis.getExpire(key, TimeUnit.MILLISECONDS);
		return ttl == null ? -2 : ttl;
	}

	private record LimiterFixture(LoginAttemptLimiter limiter, SimpleMeterRegistry meterRegistry,
			LoginRateLimitProperties properties) {

		LoginRateLimitKeys.Keys keys(LoginAttemptKey key) {
			byte[] secret = Base64.getDecoder().decode(KEY_SECRET);
			try {
				return new LoginRateLimitKeys(secret, this.properties.keyPrefix()).encode(key);
			}
			finally {
				Arrays.fill(secret, (byte) 0);
			}
		}

		double resetCount(String status) {
			return this.meterRegistry.get(RedisLoginAttemptLimiter.RESET_METRIC)
				.tags("status", status)
				.counter()
				.count();
		}

	}

}
