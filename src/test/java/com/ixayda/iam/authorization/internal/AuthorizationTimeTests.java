package com.ixayda.iam.authorization.internal;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;

import org.junit.jupiter.api.Test;

class AuthorizationTimeTests {

	@Test
	void roundsToPostgresqlMicrosecondPrecision() {
		assertThat(AuthorizationTime.toDatabasePrecision(Instant.parse("2026-01-01T00:00:00.123456499Z")))
			.isEqualTo(Instant.parse("2026-01-01T00:00:00.123456Z"));
		assertThat(AuthorizationTime.toDatabasePrecision(Instant.parse("2026-01-01T00:00:00.123456500Z")))
			.isEqualTo(Instant.parse("2026-01-01T00:00:00.123457Z"));
		assertThat(AuthorizationTime.toDatabasePrecision(Instant.parse("2026-01-01T00:00:00.999999999Z")))
			.isEqualTo(Instant.parse("2026-01-01T00:00:01Z"));
	}

}
