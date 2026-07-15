package com.ixayda.iam.ratelimit.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;

import org.junit.jupiter.api.Test;
import org.springframework.boot.health.contributor.Status;

class LoginRateLimitPropertiesTests {

	private static final String KEY_SECRET = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

	@Test
	void acceptsBoundedLimitsAndRedactsTheKeySecret() {
		LoginRateLimitProperties properties = properties(5, Duration.ofMinutes(15), 100, Duration.ofMinutes(1),
				KEY_SECRET, "iam:ratelimit:login");

		assertThat(properties.decodedKeySecret()).hasValueSatisfying(secret -> assertThat(secret).hasSize(32));
		assertThat(properties).hasToString("LoginRateLimitProperties[principalLimit=5, principalWindow=PT15M, "
				+ "sourceLimit=100, sourceWindow=PT1M, keySecret=redacted, keyPrefix=iam:ratelimit:login]");
		assertThat(properties.toString()).doesNotContain(KEY_SECRET);
		assertThat(properties(5, Duration.ofMinutes(15), 100, Duration.ofMinutes(1), null,
				"iam:ratelimit:login").decodedKeySecret()).isEmpty();
	}

	@Test
	void rejectsInvalidLimitsWindowsSecretsAndPrefixes() {
		assertThatThrownBy(() -> properties(0, Duration.ofMinutes(1), 1, Duration.ofMinutes(1), KEY_SECRET, "iam"))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> properties(1, Duration.ZERO, 1, Duration.ofMinutes(1), KEY_SECRET, "iam"))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> properties(1, Duration.ofMinutes(1), 0, Duration.ofMinutes(1), KEY_SECRET, "iam"))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> properties(1, Duration.ofMinutes(1), 1, Duration.ofNanos(1), KEY_SECRET, "iam"))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> properties(1, Duration.ofDays(1).plusMillis(1), 1, Duration.ofMinutes(1),
				KEY_SECRET, "iam")).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> properties(1, Duration.ofMinutes(1), 1, Duration.ofMinutes(1), "not-base64", "iam"))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> properties(1, Duration.ofMinutes(1), 1, Duration.ofMinutes(1), "YQ==", "iam"))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> properties(1, Duration.ofMinutes(1), 1, Duration.ofMinutes(1), KEY_SECRET, "iam{}"))
			.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void reportsMissingKeyConfigurationAsUnhealthy() {
		LoginRateLimitConfiguration configuration = new LoginRateLimitConfiguration();

		assertThat(configuration.loginRateLimitHealthIndicator(
				properties(5, Duration.ofMinutes(15), 100, Duration.ofMinutes(1), null, "iam")).health().getStatus())
			.isEqualTo(Status.DOWN);
		assertThat(configuration.loginRateLimitHealthIndicator(
				properties(5, Duration.ofMinutes(15), 100, Duration.ofMinutes(1), KEY_SECRET, "iam"))
			.health()
			.getStatus()).isEqualTo(Status.UP);
	}

	private static LoginRateLimitProperties properties(int principalLimit, Duration principalWindow, int sourceLimit,
			Duration sourceWindow, String keySecret, String keyPrefix) {
		return new LoginRateLimitProperties(principalLimit, principalWindow, sourceLimit, sourceWindow, keySecret,
				keyPrefix);
	}

}
