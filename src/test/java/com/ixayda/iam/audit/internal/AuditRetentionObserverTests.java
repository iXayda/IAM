package com.ixayda.iam.audit.internal;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AuditRetentionObserverTests {

	private static final Instant NOW = Instant.parse("2026-07-21T00:00:00Z");

	@Test
	void cachesTheOldestEventAgeAndRepresentsAnEmptyStoreAsZero() {
		SimpleMeterRegistry meters = new SimpleMeterRegistry();
		java.util.concurrent.atomic.AtomicReference<Optional<Instant>> oldest =
				new java.util.concurrent.atomic.AtomicReference<>(Optional.of(NOW.minusSeconds(91)));
		AuditRetentionProperties properties = new AuditRetentionProperties(Duration.ofDays(90), Duration.ofMinutes(5));
		AuditRetentionObserver observer = new AuditRetentionObserver(oldest::get, properties, meters,
				Clock.fixed(NOW, ZoneOffset.UTC));

		observer.observe();
		assertThat(meters.get(AuditRetentionObserver.OLDEST_EVENT_AGE_METRIC).gauge().value()).isEqualTo(91);
		assertThat(meters.get(AuditRetentionObserver.HOT_RETENTION_METRIC).gauge().value())
			.isEqualTo(Duration.ofDays(90).toSeconds());

		oldest.set(Optional.empty());
		observer.observe();
		assertThat(meters.get(AuditRetentionObserver.OLDEST_EVENT_AGE_METRIC).gauge().value()).isNaN();
	}

	@Test
	void validatesRetentionConfigurationBounds() {
		AuditRetentionProperties defaults = new AuditRetentionProperties(Duration.ofDays(90), Duration.ofMinutes(5));

		assertThat(defaults.hotRetention()).isEqualTo(Duration.ofDays(90));
		assertThat(defaults.observationInterval()).isEqualTo(Duration.ofMinutes(5));
		assertThatThrownBy(() -> new AuditRetentionProperties(Duration.ZERO, Duration.ofMinutes(5)))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new AuditRetentionProperties(Duration.ofDays(90), Duration.ofDays(2)))
			.isInstanceOf(IllegalArgumentException.class);
	}

}
