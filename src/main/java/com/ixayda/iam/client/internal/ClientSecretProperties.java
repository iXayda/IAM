package com.ixayda.iam.client.internal;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

@ConfigurationProperties("iam.client")
record ClientSecretProperties(Duration secretLifetime) {

	ClientSecretProperties(@DefaultValue("90d") Duration secretLifetime) {
		this.secretLifetime = Objects.requireNonNull(secretLifetime, "Client secret lifetime must not be null");
		if (secretLifetime.isZero() || secretLifetime.isNegative() || secretLifetime.getNano() != 0) {
			throw new IllegalArgumentException("Client secret lifetime must be a positive whole number of seconds");
		}
	}

	Instant expirationFrom(Instant issuedAt) {
		return Objects.requireNonNull(issuedAt, "Client secret issue time must not be null").plus(this.secretLifetime);
	}

}
