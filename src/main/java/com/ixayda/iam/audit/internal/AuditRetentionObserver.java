package com.ixayda.iam.audit.internal;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;

final class AuditRetentionObserver {

	static final String OLDEST_EVENT_AGE_METRIC = "iam.audit.oldest.event.age";

	static final String HOT_RETENTION_METRIC = "iam.audit.hot.retention";

	private static final Logger LOGGER = LoggerFactory.getLogger(AuditRetentionObserver.class);

	private final Supplier<Optional<Instant>> oldestRecordedAtReader;

	private final Clock clock;

	private final long hotRetentionSeconds;

	private final AtomicReference<Instant> oldestRecordedAt = new AtomicReference<>();

	AuditRetentionObserver(JdbcAuditEventRepository repository, AuditRetentionProperties properties,
			MeterRegistry meterRegistry) {
		this(repository::oldestRecordedAt, properties, meterRegistry, Clock.systemUTC());
	}

	AuditRetentionObserver(Supplier<Optional<Instant>> oldestRecordedAt, AuditRetentionProperties properties,
			MeterRegistry meterRegistry, Clock clock) {
		this.oldestRecordedAtReader = Objects.requireNonNull(oldestRecordedAt,
				"Oldest audit event supplier must not be null");
		this.clock = Objects.requireNonNull(clock, "Audit retention observation clock must not be null");
		this.hotRetentionSeconds = properties.hotRetention().toSeconds();
		Gauge.builder(OLDEST_EVENT_AGE_METRIC, this, AuditRetentionObserver::oldestEventAgeSeconds)
			.description("Age of the oldest audit event retained in PostgreSQL")
			.baseUnit("seconds")
			.register(meterRegistry);
		Gauge.builder(HOT_RETENTION_METRIC, this, observer -> observer.hotRetentionSeconds)
			.description("Configured audit event hot-retention target")
			.baseUnit("seconds")
			.register(meterRegistry);
	}

	@Scheduled(fixedDelayString = "${iam.audit.retention.observation-interval:5m}")
	void observe() {
		try {
			this.oldestRecordedAt.set(this.oldestRecordedAtReader.get().orElse(null));
		}
		catch (RuntimeException exception) {
			LOGGER.warn("Unable to observe audit event retention", exception);
		}
	}

	private double oldestEventAgeSeconds() {
		Instant recordedAt = this.oldestRecordedAt.get();
		return recordedAt == null ? Double.NaN
				: Math.max(0L, Duration.between(recordedAt, this.clock.instant()).toSeconds());
	}

}
