package com.ixayda.iam.credential.internal;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthIndicator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(TotpSecretProtectionProperties.class)
class CredentialTotpConfiguration {

	@Bean
	TotpSecretCipher totpSecretCipher(TotpSecretProtectionProperties properties) {
		return new TotpSecretCipher(properties);
	}

	@Bean
	HealthIndicator totpSecretProtectionHealthIndicator(TotpSecretProtectionProperties properties) {
		return () -> properties.isConfigured() ? Health.up().build()
				: Health.down().withDetail("configuration", "active-key-not-configured").build();
	}

}
