package com.ixayda.iam.credential.internal;

import java.time.Duration;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TotpSettingsPropertiesTests {

	@Test
	void suppliesConservativeDefaults() {
		TotpSettingsProperties properties = new TotpSettingsProperties(null, null);

		assertThat(properties.enrollmentTtl()).isEqualTo(Duration.ofMinutes(10));
		assertThat(properties.allowedClockSkewSteps()).isOne();
	}

	@Test
	void rejectsUnsafeEnrollmentAndClockSkewSettings() {
		assertThatThrownBy(() -> new TotpSettingsProperties(Duration.ZERO, 1))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new TotpSettingsProperties(Duration.ofSeconds(59), 1))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new TotpSettingsProperties(Duration.ofMinutes(31), 1))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new TotpSettingsProperties(Duration.ofMinutes(10), -1))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new TotpSettingsProperties(Duration.ofMinutes(10), 3))
			.isInstanceOf(IllegalArgumentException.class);
	}

}
