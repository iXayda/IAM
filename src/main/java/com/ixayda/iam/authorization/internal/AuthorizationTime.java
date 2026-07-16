package com.ixayda.iam.authorization.internal;

import java.time.Instant;
import java.util.Objects;

final class AuthorizationTime {

	private static final int NANOS_PER_MICROSECOND = 1_000;

	private AuthorizationTime() {
	}

	static Instant toDatabasePrecision(Instant value) {
		Objects.requireNonNull(value, "Authorization timestamp must not be null");
		int remainder = value.getNano() % NANOS_PER_MICROSECOND;
		Instant rounded = value.minusNanos(remainder);
		return remainder > 499 ? rounded.plusNanos(NANOS_PER_MICROSECOND) : rounded;
	}

}
