package com.ixayda.iam.session;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.time.Instant;

import org.junit.jupiter.api.Test;

class SessionAbsoluteTtlTests {

	private static final Instant AUTHENTICATED_AT = Instant.parse("2026-01-01T00:00:00Z");

	@Test
	void calculatesAFixedExpirationFromAuthenticationTime() {
		SessionAbsoluteTtl ttl = new SessionAbsoluteTtl(Duration.ofHours(8));

		assertThat(ttl.expiresAt(AUTHENTICATED_AT)).isEqualTo(AUTHENTICATED_AT.plus(Duration.ofHours(8)));
		assertThat(ttl.value()).isEqualTo(Duration.ofHours(8));
	}

	@Test
	void acceptsTheDatabaseTimestampPrecisionBoundary() {
		SessionAbsoluteTtl ttl = new SessionAbsoluteTtl(SessionAbsoluteTtl.MINIMUM);

		assertThat(ttl.expiresAt(AUTHENTICATED_AT)).isEqualTo(AUTHENTICATED_AT.plusNanos(1_000));
	}

	@Test
	void rejectsInvalidDurationsAndExpirationOverflow() {
		assertThatThrownBy(() -> new SessionAbsoluteTtl(null)).isInstanceOf(NullPointerException.class);
		assertThatThrownBy(() -> new SessionAbsoluteTtl(Duration.ZERO))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new SessionAbsoluteTtl(Duration.ofNanos(999)))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new SessionAbsoluteTtl(Duration.ofSeconds(-1)))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new SessionAbsoluteTtl(Duration.ofSeconds(1)).expiresAt(null))
			.isInstanceOf(NullPointerException.class);
		assertThatThrownBy(() -> new SessionAbsoluteTtl(Duration.ofSeconds(1)).expiresAt(Instant.MAX))
			.isInstanceOf(IllegalArgumentException.class)
			.hasCauseInstanceOf(RuntimeException.class);
	}

}
