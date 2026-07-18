package com.ixayda.iam.group.internal;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

import org.springframework.stereotype.Component;

@Component
class GroupTimeSource {

	private final Clock clock = Clock.tick(Clock.systemUTC(), Duration.ofNanos(1_000));

	Instant now() {
		return this.clock.instant();
	}

}
