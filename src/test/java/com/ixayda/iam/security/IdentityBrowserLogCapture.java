package com.ixayda.iam.security;

import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.Logger;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.Property;

/** Captures immutable diagnostic events from request threads. */
final class IdentityBrowserLogCapture extends AbstractAppender implements AutoCloseable {

	private final Logger logger = (Logger) LogManager.getLogger(IdentityBrowserDiagnostics.class);
	private final List<LogEvent> events = new CopyOnWriteArrayList<>();

	IdentityBrowserLogCapture() {
		super("browser-diagnostics-" + UUID.randomUUID(), null, null, true, Property.EMPTY_ARRAY);
		start();
		this.logger.addAppender(this);
	}

	@Override
	public void append(LogEvent event) {
		this.events.add(event.toImmutable());
	}

	List<LogEvent> events() {
		return List.copyOf(this.events);
	}

	@Override
	public void close() {
		this.logger.removeAppender(this);
		stop();
	}

}
