package com.ixayda.iam.service;

import java.util.UUID;
import java.util.concurrent.TimeUnit;

import com.ixayda.iam.repository.IdentityAuthorizationInteractionRepository;
import com.ixayda.iam.repository.IdentityProtocolCleanupRepository;

import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;

/** Owner-only bounded maintenance. Business audits and active grants are retained. */
@Service
@Lazy
public class IdentityProtocolCleanup {

	private final IdentityProtocolCleanupRepository repository;
	private final IdentityAuthorizationInteractionRepository interactions;
	private final IdentityAuthorizations authorizations;
	private final IdentityAuthorizationBindings bindings;
	private final IdentityRefreshTokens refresh;
	private final PlatformTransactionManager transactions;

	IdentityProtocolCleanup(IdentityProtocolCleanupRepository repository, IdentityAuthorizationInteractionRepository interactions,
			IdentityAuthorizations authorizations, IdentityAuthorizationBindings bindings, IdentityRefreshTokens refresh, PlatformTransactionManager transactions) {
		this.repository = repository; this.interactions = interactions; this.authorizations = authorizations; this.bindings = bindings; this.refresh = refresh; this.transactions = transactions;
	}

	/** Counts are capped at the configured maximum per kind; preview takes no grant or interaction locks. */
	public Counts preview(Limits limits) {
		requireIndependent(limits);
		return transaction(limits.seconds()).execute(status -> {
			this.repository.requireDatabaseOwner(); this.repository.boundStatements(TimeUnit.SECONDS.toMillis(limits.seconds()));
			return new Counts(this.repository.candidates(limits.maximum(), null).size(), this.repository.expiredInteractions(limits.maximum()));
		});
	}

	/** Each batch commits independently; a failed batch rolls back completely and previous batches remain committed. */
	public Counts cleanUp(Limits limits) {
		requireIndependent(limits);
		long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(limits.seconds());
		Counts total = new Counts(0, 0);
		UUID cursor = null;
		while (total.total() < limits.maximum() && System.nanoTime() < deadline) {
			int maximum = (int) Math.min(limits.batchSize(), limits.maximum() - total.total());
			int seconds = (int) Math.max(1, TimeUnit.NANOSECONDS.toSeconds(deadline - System.nanoTime()));
			UUID after = cursor;
			Batch batch = transaction(seconds).execute(status -> {
				this.repository.requireDatabaseOwner(); this.repository.boundStatements(TimeUnit.SECONDS.toMillis(seconds));
				int removed = 0;
				var candidates = this.repository.candidates(maximum, after);
				for (var id : candidates) {
					if (System.nanoTime() >= deadline) { break; }
					if (!this.repository.tryLock(id)) { continue; }
					var stored = this.authorizations.lockForUse(id);
					if (stored.isEmpty() || !this.repository.isEligible(id)) { continue; }
					// Authenticate the original binding before removing its queryable projection.
					this.bindings.findByAuthorization(stored.orElseThrow().authorization());
					this.refresh.findByAuthorization(stored.orElseThrow().authorization());
					this.repository.removeDependencies(id);
					this.authorizations.remove(id, stored.orElseThrow().version());
					removed++;
				}
				int pending = System.nanoTime() < deadline && removed < maximum ? this.interactions.deleteExpired(maximum - removed) : 0;
				return new Batch(new Counts(removed, pending), candidates.isEmpty() ? after : candidates.getLast(), candidates.size() < maximum);
			});
			total = new Counts(total.authorizations() + batch.counts().authorizations(), total.interactions() + batch.counts().interactions());
			cursor = batch.cursor();
			if (batch.counts().total() == 0 && batch.exhausted()) { break; }
		}
		return total;
	}

	private TransactionTemplate transaction(int seconds) {
		var transaction = new TransactionTemplate(this.transactions);
		transaction.setIsolationLevel(TransactionDefinition.ISOLATION_READ_COMMITTED); transaction.setTimeout(seconds); return transaction;
	}

	private static void requireIndependent(Limits limits) {
		if (limits == null) { throw new IllegalArgumentException("Cleanup limits are required"); }
		if (TransactionSynchronizationManager.isActualTransactionActive()) { throw new IllegalStateException("Protocol cleanup requires independent transactions"); }
	}

	public record Limits(int batchSize, int maximum, int seconds) {
		public Limits {
			if (batchSize < 1 || batchSize > 100 || maximum < batchSize || maximum > 10_000 || seconds < 1 || seconds > 300) {
				throw new IllegalArgumentException("Cleanup limits must be batch 1..100, maximum batch..10000 and seconds 1..300");
			}
		}
	}

	public record Counts(long authorizations, long interactions) {
		public long total() { return this.authorizations + this.interactions; }
	}

	private record Batch(Counts counts, UUID cursor, boolean exhausted) { }
}
