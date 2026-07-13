package com.ixayda.iam.auth.internal;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

class LocalPasswordLoginPropertiesTests {

	private final ApplicationContextRunner contextRunner =
			new ApplicationContextRunner().withUserConfiguration(LocalPasswordLoginConfiguration.class);

	@Test
	void usesTheDefaultAbsoluteTtl() {
		this.contextRunner.run(context -> assertThat(context.getBean(LocalPasswordLoginProperties.class)
			.absoluteTtl()
			.value()).isEqualTo(Duration.ofHours(8)));
	}

	@Test
	void bindsAnAbsoluteTtlOverride() {
		this.contextRunner.withPropertyValues("iam.auth.local.session-absolute-ttl=15m")
			.run(context -> assertThat(context.getBean(LocalPasswordLoginProperties.class)
				.absoluteTtl()
				.value()).isEqualTo(Duration.ofMinutes(15)));
	}

	@Test
	void rejectsAnInvalidAbsoluteTtl() {
		this.contextRunner.withPropertyValues("iam.auth.local.session-absolute-ttl=0s")
			.run(context -> assertThat(context.getStartupFailure()).isNotNull()
				.hasRootCauseInstanceOf(IllegalArgumentException.class));
	}

}
