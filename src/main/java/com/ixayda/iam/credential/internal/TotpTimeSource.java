package com.ixayda.iam.credential.internal;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

final class TotpTimeSource {

	private final Clock clock;

	TotpTimeSource() {
		this(Clock.tick(Clock.systemUTC(), Duration.ofNanos(1_000)));
	}

	TotpTimeSource(Clock clock) {
		this.clock = Objects.requireNonNull(clock, "TOTP clock must not be null");
	}

	Instant now() {
		return this.clock.instant();
	}

}
