package com.ixayda.iam.ratelimit.internal;

import com.ixayda.iam.ratelimit.LoginAttemptLimiter;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.RuntimeHintsRegistrar;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthIndicator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportRuntimeHints;
import org.springframework.core.io.ClassPathResource;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(LoginRateLimitProperties.class)
@ImportRuntimeHints(LoginRateLimitConfiguration.LoginRateLimitRuntimeHints.class)
class LoginRateLimitConfiguration {

	private static final String ACQUIRE_SCRIPT =
			"com/ixayda/iam/ratelimit/internal/acquire-login-attempt.lua";

	private static final String CLEAR_SCRIPT =
			"com/ixayda/iam/ratelimit/internal/clear-login-attempt.lua";

	@Bean
	StringRedisTemplate redisTemplate(RedisConnectionFactory connectionFactory) {
		// Suppress Boot's generic JDK-serialized template; IAM stores only strings.
		return new StringRedisTemplate(connectionFactory);
	}

	@Bean
	RedisScript<Long> loginRateLimitAcquireScript() {
		return RedisScript.of(new ClassPathResource(ACQUIRE_SCRIPT), Long.class);
	}

	@Bean
	RedisScript<Boolean> loginRateLimitClearScript() {
		return RedisScript.of(new ClassPathResource(CLEAR_SCRIPT), Boolean.class);
	}

	@Bean
	LoginAttemptLimiter loginAttemptLimiter(StringRedisTemplate redisTemplate,
			RedisScript<Long> loginRateLimitAcquireScript, RedisScript<Boolean> loginRateLimitClearScript,
			LoginRateLimitProperties properties, MeterRegistry meterRegistry) {
		return new RedisLoginAttemptLimiter(redisTemplate, loginRateLimitAcquireScript, loginRateLimitClearScript,
				properties, meterRegistry);
	}

	@Bean
	HealthIndicator loginRateLimitHealthIndicator(LoginRateLimitProperties properties) {
		boolean configured = properties.hasKeySecret();
		return () -> configured ? Health.up().build()
				: Health.down().withDetail("configuration", "key-secret-not-configured").build();
	}

	static final class LoginRateLimitRuntimeHints implements RuntimeHintsRegistrar {

		@Override
		public void registerHints(RuntimeHints hints, ClassLoader classLoader) {
			hints.resources().registerPattern("com/ixayda/iam/ratelimit/internal/*.lua");
		}

	}

}
