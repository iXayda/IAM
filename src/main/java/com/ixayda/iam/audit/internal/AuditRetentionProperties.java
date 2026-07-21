package com.ixayda.iam.audit.internal;

import java.time.Duration;
import java.util.Objects;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

@ConfigurationProperties("iam.audit.retention")
record AuditRetentionProperties(Duration hotRetention, Duration observationInterval) {

	private static final Duration MAXIMUM_HOT_RETENTION = Duration.ofDays(3650);

	private static final Duration MAXIMUM_OBSERVATION_INTERVAL = Duration.ofDays(1);

	AuditRetentionProperties(@DefaultValue("90d") Duration hotRetention,
			@DefaultValue("5m") Duration observationInterval) {
		this.hotRetention = requirePositive(hotRetention, MAXIMUM_HOT_RETENTION, "Audit hot retention");
		this.observationInterval = requirePositive(observationInterval, MAXIMUM_OBSERVATION_INTERVAL,
				"Audit retention observation interval");
	}

	private static Duration requirePositive(Duration value, Duration maximum, String name) {
		Objects.requireNonNull(value, name + " must not be null");
		if (value.isZero() || value.isNegative() || value.compareTo(maximum) > 0) {
			throw new IllegalArgumentException(name + " must be positive and not exceed " + maximum);
		}
		return value;
	}

}
