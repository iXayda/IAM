package com.ixayda.iam.service;

import org.springframework.context.annotation.Lazy;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.QueryTimeoutException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.TransactionException;
import org.springframework.transaction.TransactionTimedOutException;
import org.springframework.transaction.support.TransactionTemplate;

/** Checks mandatory protocol dependencies without creating identities, sessions, grants or audit events. */
@Service
@Lazy
public class IdentityReadiness {

	private final IdentitySigningKeys keys;
	private final IdentityAuthorizations authorizations;
	private final SecurityAudits audits;
	private final TransactionTemplate transaction;

	IdentityReadiness(IdentitySigningKeys keys, IdentityAuthorizations authorizations, SecurityAudits audits, PlatformTransactionManager manager) {
		this.keys = keys; this.authorizations = authorizations; this.audits = audits;
		this.transaction = new TransactionTemplate(manager);
		this.transaction.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
		// JDBC applies the remaining transaction deadline to each statement, including lifecycle lock waits.
		this.transaction.setTimeout(1);
	}

	public void requireReady() {
		check(Failure.DATABASE, () -> this.transaction.executeWithoutResult(tx -> {
			check(Failure.SIGNING, this.keys::lockForIssuance);
			check(Failure.AUDIT, () -> { if (!this.audits.isAvailable()) { throw new Unavailable(Failure.AUDIT); } });
			check(Failure.AUTHORIZATION_PIN, this.authorizations::requireConfigured);
		}));
	}

	private static void check(Failure dependency, Runnable action) {
		try { action.run(); }
		catch (Unavailable ex) { throw ex; }
		catch (QueryTimeoutException | TransactionTimedOutException ex) { throw new Unavailable(Failure.TIMEOUT); }
		catch (DataAccessException | TransactionException ex) { throw new Unavailable(Failure.DATABASE); }
		catch (RuntimeException ex) { throw new Unavailable(dependency); }
	}

	public enum Failure { DATABASE, SIGNING, AUDIT, AUTHORIZATION_PIN, TIMEOUT, INTERRUPTED, UNKNOWN }

	public static final class Unavailable extends IllegalStateException {
		private final Failure failure;

		private Unavailable(Failure failure) { super(failure.name()); this.failure = failure; }

		public Failure failure() { return this.failure; }
	}
}
