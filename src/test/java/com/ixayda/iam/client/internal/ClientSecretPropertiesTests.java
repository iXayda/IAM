package com.ixayda.iam.client.internal;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.time.Instant;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

class ClientSecretPropertiesTests {

	private final ApplicationContextRunner contextRunner =
			new ApplicationContextRunner().withUserConfiguration(ClientConfiguration.class);

	@Test
	void usesTheDefaultSecretLifetime() {
		this.contextRunner.run(context -> {
			ClientSecretProperties properties = context.getBean(ClientSecretProperties.class);
			assertThat(properties.secretLifetime()).isEqualTo(Duration.ofDays(90));
			assertThat(properties.expirationFrom(Instant.EPOCH)).isEqualTo(Instant.EPOCH.plus(Duration.ofDays(90)));
		});
	}

	@Test
	void bindsASecretLifetimeOverride() {
		this.contextRunner.withPropertyValues("iam.client.secret-lifetime=30d")
			.run(context -> assertThat(context.getBean(ClientSecretProperties.class).secretLifetime())
				.isEqualTo(Duration.ofDays(30)));
	}

	@Test
	void rejectsASecretLifetimeThatIsNotPositiveWholeSeconds() {
		this.contextRunner.withPropertyValues("iam.client.secret-lifetime=0s")
			.run(context -> assertThat(context.getStartupFailure()).isNotNull()
				.hasRootCauseInstanceOf(IllegalArgumentException.class));
		this.contextRunner.withPropertyValues("iam.client.secret-lifetime=1500ms")
			.run(context -> assertThat(context.getStartupFailure()).isNotNull()
				.hasRootCauseInstanceOf(IllegalArgumentException.class));
	}

}
