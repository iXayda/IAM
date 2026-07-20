package com.ixayda.iam.auth.internal;

import java.time.Duration;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class MfaChallengePropertiesTests {

	@Test
	void acceptsTheDefaultAndBoundedChallengeTtl() {
		assertThat(new MfaChallengeProperties(Duration.ofMinutes(5)).challengeTtl())
			.isEqualTo(Duration.ofMinutes(5));
		assertThat(new MfaChallengeProperties(Duration.ofSeconds(30)).challengeTtl())
			.isEqualTo(Duration.ofSeconds(30));
		assertThat(new MfaChallengeProperties(Duration.ofMinutes(15)).challengeTtl())
			.isEqualTo(Duration.ofMinutes(15));
	}

	@Test
	void rejectsUnsafeChallengeTtlValues() {
		assertThatThrownBy(() -> new MfaChallengeProperties(Duration.ofSeconds(29)))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new MfaChallengeProperties(Duration.ofMinutes(16)))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new MfaChallengeProperties(null)).isInstanceOf(NullPointerException.class);
	}

}
