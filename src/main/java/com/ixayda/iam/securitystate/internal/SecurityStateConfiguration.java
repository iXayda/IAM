package com.ixayda.iam.securitystate.internal;

import com.ixayda.iam.securitystate.SecurityStateOperations;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthIndicator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.StringRedisTemplate;

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(SecurityStateProperties.class)
class SecurityStateConfiguration {

	@Bean
	SecurityStateOperations securityStateOperations(StringRedisTemplate redisTemplate,
			SecurityStateProperties properties, MeterRegistry meterRegistry) {
		return new RedisSecurityStateOperations(redisTemplate, properties, meterRegistry);
	}

	@Bean
	HealthIndicator securityStateHealthIndicator(SecurityStateProperties properties) {
		boolean configured = properties.hasKeySecret();
		return () -> configured ? Health.up().build()
				: Health.down().withDetail("configuration", "key-secret-not-configured").build();
	}

}
