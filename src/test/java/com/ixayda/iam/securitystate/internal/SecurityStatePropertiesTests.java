package com.ixayda.iam.securitystate.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;

import org.junit.jupiter.api.Test;
import org.springframework.boot.health.contributor.Status;

class SecurityStatePropertiesTests {

	private static final String KEY_SECRET = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

	@Test
	void acceptsBoundedTtlsAndRedactsTheKeySecret() {
		SecurityStateProperties properties = properties(Duration.ofMinutes(15), KEY_SECRET, "iam:security-state");

		assertThat(properties.validateTtl(Duration.ofMinutes(5))).isEqualTo(Duration.ofMinutes(5));
		assertThat(properties.decodedKeySecret()).hasValueSatisfying(secret -> assertThat(secret).hasSize(32));
		assertThat(properties).hasToString("SecurityStateProperties[maximumTtl=PT15M, keySecret=redacted, "
				+ "keyPrefix=iam:security-state]");
		assertThat(properties.toString()).doesNotContain(KEY_SECRET);
		assertThat(properties(Duration.ofMinutes(15), null, "iam:security-state").decodedKeySecret()).isEmpty();
	}

	@Test
	void rejectsInvalidTtlsSecretsAndPrefixes() {
		assertThatThrownBy(() -> properties(Duration.ZERO, KEY_SECRET, "iam"))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> properties(Duration.ofNanos(1), KEY_SECRET, "iam"))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> properties(Duration.ofDays(1).plusMillis(1), KEY_SECRET, "iam"))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> properties(Duration.ofMinutes(15), "not-base64", "iam"))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> properties(Duration.ofMinutes(15), "YQ==", "iam"))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> properties(Duration.ofMinutes(15), KEY_SECRET, "iam{}"))
			.isInstanceOf(IllegalArgumentException.class);

		SecurityStateProperties properties = properties(Duration.ofMinutes(15), KEY_SECRET, "iam");
		assertThatThrownBy(() -> properties.validateTtl(null)).isInstanceOf(NullPointerException.class);
		assertThatThrownBy(() -> properties.validateTtl(Duration.ZERO))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> properties.validateTtl(Duration.ofMinutes(16)))
			.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void reportsMissingKeyConfigurationAsUnhealthy() {
		SecurityStateConfiguration configuration = new SecurityStateConfiguration();

		assertThat(configuration
			.securityStateHealthIndicator(properties(Duration.ofMinutes(15), null, "iam"))
			.health()
			.getStatus()).isEqualTo(Status.DOWN);
		assertThat(configuration
			.securityStateHealthIndicator(properties(Duration.ofMinutes(15), KEY_SECRET, "iam"))
			.health()
			.getStatus()).isEqualTo(Status.UP);
	}

	private static SecurityStateProperties properties(Duration maximumTtl, String keySecret, String keyPrefix) {
		return new SecurityStateProperties(maximumTtl, keySecret, keyPrefix);
	}

}
