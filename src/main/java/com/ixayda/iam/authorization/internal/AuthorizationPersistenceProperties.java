package com.ixayda.iam.authorization.internal;

import java.time.Duration;
import java.util.Objects;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

@ConfigurationProperties("iam.authorization.persistence")
record AuthorizationPersistenceProperties(Duration pendingAuthorizationTtl, Duration tokenRetention) {

	private static final Duration MAXIMUM_PENDING_TTL = Duration.ofMinutes(30);

	private static final Duration MAXIMUM_TOKEN_RETENTION = Duration.ofDays(30);

	AuthorizationPersistenceProperties(
			@DefaultValue("10m") Duration pendingAuthorizationTtl,
			@DefaultValue("24h") Duration tokenRetention) {
		this.pendingAuthorizationTtl = requirePositive(pendingAuthorizationTtl, "Pending authorization TTL");
		this.tokenRetention = requirePositive(tokenRetention, "Authorization token retention");
		if (this.pendingAuthorizationTtl.compareTo(MAXIMUM_PENDING_TTL) > 0) {
			throw new IllegalArgumentException("Pending authorization TTL must not exceed 30 minutes");
		}
		if (this.tokenRetention.compareTo(MAXIMUM_TOKEN_RETENTION) > 0) {
			throw new IllegalArgumentException("Authorization token retention must not exceed 30 days");
		}
	}

	private static Duration requirePositive(Duration value, String name) {
		Objects.requireNonNull(value, name + " must not be null");
		if (value.isZero() || value.isNegative()) {
			throw new IllegalArgumentException(name + " must be positive");
		}
		return value;
	}

}
