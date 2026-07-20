package com.ixayda.iam.credential.internal;

import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("iam.credential.totp")
record TotpSettingsProperties(Duration enrollmentTtl, Integer allowedClockSkewSteps) {

	private static final Duration DEFAULT_ENROLLMENT_TTL = Duration.ofMinutes(10);

	private static final Duration MINIMUM_ENROLLMENT_TTL = Duration.ofMinutes(1);

	private static final Duration MAXIMUM_ENROLLMENT_TTL = Duration.ofMinutes(30);

	private static final int DEFAULT_ALLOWED_CLOCK_SKEW_STEPS = 1;

	TotpSettingsProperties {
		enrollmentTtl = enrollmentTtl == null ? DEFAULT_ENROLLMENT_TTL : enrollmentTtl;
		allowedClockSkewSteps = allowedClockSkewSteps == null ? DEFAULT_ALLOWED_CLOCK_SKEW_STEPS
				: allowedClockSkewSteps;
		if (enrollmentTtl.compareTo(MINIMUM_ENROLLMENT_TTL) < 0
				|| enrollmentTtl.compareTo(MAXIMUM_ENROLLMENT_TTL) > 0) {
			throw new IllegalArgumentException("TOTP enrollment TTL must be between 1 and 30 minutes");
		}
		if (allowedClockSkewSteps < 0 || allowedClockSkewSteps > 2) {
			throw new IllegalArgumentException("TOTP clock-skew allowance must contain zero to two steps");
		}
	}

}
