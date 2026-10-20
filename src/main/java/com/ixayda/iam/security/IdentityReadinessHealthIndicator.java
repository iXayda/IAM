package com.ixayda.iam.security;

import java.time.Duration;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Supplier;

import com.ixayda.iam.service.IdentityReadiness;
import com.ixayda.iam.service.IdentityReadiness.Failure;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthIndicator;

/** One admitted waiter and one unqueued check keep public probes independent of browser admission. */
final class IdentityReadinessHealthIndicator implements HealthIndicator, AutoCloseable {

	private static final Health DOWN = Health.down().build();
	private static final Logger logger = LoggerFactory.getLogger(IdentityReadinessHealthIndicator.class);
	private final Supplier<IdentityReadiness> readiness;
	private final long waitNanos;
	private final long coalesceNanos;
	private final ThreadPoolExecutor worker;
	private Check running;
	private Health completed;
	private long completedAt;
	private Failure lastFailure;

	IdentityReadinessHealthIndicator(Supplier<IdentityReadiness> readiness) {
		this(readiness, Duration.ofSeconds(2), Duration.ofMillis(100));
	}

	IdentityReadinessHealthIndicator(Supplier<IdentityReadiness> readiness, Duration wait, Duration coalesce) {
		this.readiness = readiness; this.waitNanos = wait.toNanos(); this.coalesceNanos = coalesce.toNanos();
		this.worker = new ThreadPoolExecutor(1, 1, 0, TimeUnit.MILLISECONDS, new SynchronousQueue<>(), task -> {
			var thread = new Thread(task, "iam-readiness"); thread.setDaemon(true); return thread;
		});
	}

	@Override
	public Health health() {
		Check check;
		synchronized (this) {
			if (this.completed != null && System.nanoTime() - this.completedAt < this.coalesceNanos) { return this.completed; }
			if (this.running != null || this.worker.isShutdown()) { return DOWN; }
			check = new Check(); this.running = check;
		}
		var task = new FutureTask<>(() -> perform(check));
		try {
			this.worker.execute(task);
			return task.get(this.waitNanos, TimeUnit.NANOSECONDS);
		}
		catch (InterruptedException ex) {
			Thread.currentThread().interrupt(); return expire(check, Failure.INTERRUPTED);
		}
		catch (TimeoutException ex) { return expire(check, Failure.TIMEOUT); }
		catch (ExecutionException ex) { return DOWN; }
		catch (RejectedExecutionException ex) {
			synchronized (this) { if (this.running == check) { this.running = null; } }
			return DOWN;
		}
	}

	private Health perform(Check check) {
		Health result = DOWN;
		Failure failure = Failure.UNKNOWN;
		try {
			synchronized (this) { check.thread = Thread.currentThread(); if (check.expired) { return DOWN; } }
			this.readiness.get().requireReady(); result = Health.up().build(); failure = null;
		}
		catch (IdentityReadiness.Unavailable ex) { failure = ex.failure(); }
		catch (RuntimeException ex) { /* Never log arbitrary dependency or provider exception text. */ }
		finally {
			synchronized (this) {
				if (!check.expired) { recordTransition(failure); }
				result = check.expired ? DOWN : result; this.completed = result;
				this.completedAt = System.nanoTime(); this.running = null;
			}
		}
		return result;
	}

	private Health expire(Check check, Failure failure) {
		synchronized (this) {
			check.expired = true;
			if (this.running == check) {
				recordTransition(failure);
				this.completed = DOWN; this.completedAt = System.nanoTime();
				if (check.thread != null) { check.thread.interrupt(); }
			}
		}
		// Keep admission occupied until the callable exits, even if a dependency ignores interruption.
		return DOWN;
	}

	private void recordTransition(Failure failure) {
		if (failure == this.lastFailure) { return; }
		this.lastFailure = failure;
		if (failure == null) { logger.info("Readiness recovered"); }
		else { logger.warn("Readiness unavailable: {}", failure); }
	}

	@Override
	public void close() { this.worker.shutdownNow(); }

	private static final class Check { private boolean expired; private Thread thread; }
}
