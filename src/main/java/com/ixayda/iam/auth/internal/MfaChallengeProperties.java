package com.ixayda.iam.auth.internal;

import java.time.Duration;
import java.util.Objects;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

@ConfigurationProperties("iam.auth.mfa")
record MfaChallengeProperties(Duration challengeTtl) {

	private static final Duration MINIMUM_TTL = Duration.ofSeconds(30);

	private static final Duration MAXIMUM_TTL = Duration.ofMinutes(15);

	MfaChallengeProperties(@DefaultValue("5m") Duration challengeTtl) {
		this.challengeTtl = Objects.requireNonNull(challengeTtl, "MFA challenge TTL must not be null");
		if (challengeTtl.compareTo(MINIMUM_TTL) < 0 || challengeTtl.compareTo(MAXIMUM_TTL) > 0) {
			throw new IllegalArgumentException("MFA challenge TTL must be between 30 seconds and 15 minutes");
		}
	}

}
