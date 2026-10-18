package com.ixayda.iam.service;

import java.util.UUID;

import com.ixayda.iam.model.IdentityAdministratorAuthentication;
import com.ixayda.iam.model.IdentityUser;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.SecurityAuditEvent.Action;
import com.ixayda.iam.model.TotpAuthenticationContext;

import org.springframework.dao.DuplicateKeyException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.util.Assert;

/** Consumes fresh TOTP and creates exactly the requested pending identity in one transaction. */
@Service
public class IdentityUserCreations {

	private final IdentityUsers users;
	private final IdentityBrowserSessions sessions;
	private final IdentityAdministratorSessions administrators;
	private final IdentityTotps totps;
	private final TotpAuthenticationLimits limits;
	private final SecurityAudits audits;
	private final TransactionTemplate transaction;

	IdentityUserCreations(IdentityUsers users, IdentityBrowserSessions sessions, IdentityAdministratorSessions administrators,
			IdentityTotps totps, TotpAuthenticationLimits limits, SecurityAudits audits, PlatformTransactionManager manager) {
		this.users = users;
		this.sessions = sessions;
		this.administrators = administrators;
		this.totps = totps;
		this.limits = limits;
		this.audits = audits;
		this.transaction = new TransactionTemplate(manager);
	}

	/** All authentication evidence and transport attribution come from the trusted HTTP entry. */
	public Result create(UUID actorId, String sessionId, long credentialVersion, long authenticatedAt,
			IdentityAdministratorAuthentication management, String username, String displayName, String code,
			TotpAuthenticationContext context, Runnable persistSession) {
		Assert.notNull(actorId, "Authenticated user id is required");
		Assert.hasText(sessionId, "Authenticated session id is required");
		Assert.notNull(context, "Trusted authentication context is required");
		Assert.notNull(persistSession, "Session persistence is required");
		if (TransactionSynchronizationManager.isActualTransactionActive()) {
			throw new IllegalStateException("Administrator user creation requires an independent transaction");
		}
		String normalizedUsername;
		String normalizedDisplayName;
		try {
			normalizedUsername = IdentityUsers.normalizeUsername(username);
			normalizedDisplayName = IdentityUsers.normalizeDisplayName(displayName);
		}
		catch (IllegalArgumentException ex) { return rejected(Status.INVALID_INPUT); }
		try {
			return this.transaction.execute(status -> {
				// Shared factor budgets precede user and session locks, as in administrator MFA.
				var attempt = this.limits.lock(actorId, context);
				if (!attempt.allowed()) {
					this.audits.recordFailure(Action.TOTP_AUTH_THROTTLED, null,
							new SecurityAuditContext("anonymous", context.source(), context.correlationId()));
					return rejected(Status.THROTTLED);
				}
				var actor = this.users.lockForTotp(actorId);
				var expiry = this.sessions.lockOwnedSessionExpiry(actorId, sessionId);
				if (actor.filter(user -> user.status() == IdentityUser.Status.ACTIVE).isEmpty() || expiry.isEmpty()
						|| !this.sessions.isAuthenticationCurrent(actorId, authenticatedAt, credentialVersion)) {
					return rejected(Status.INVALID_SESSION);
				}
				var audit = new SecurityAuditContext("user:" + actorId, context.source(), context.correlationId());
				if (this.administrators.authorities(actorId, authenticatedAt, management).isEmpty()) {
					this.audits.recordFailure(Action.ADMIN_ACCESS_DENIED, actorId, audit);
					return rejected(Status.FORBIDDEN);
				}
				var verified = this.totps.verifyInTransaction(actorId, code, context);
				if (verified.isEmpty()) { return rejected(Status.REJECTED); }
				if (verified.orElseThrow().credentialVersion() != credentialVersion) {
					throw new IllegalStateException("Password authentication is no longer current");
				}
				IdentityUser user;
				try { user = this.users.create(normalizedUsername, normalizedDisplayName, audit); }
				catch (DuplicateKeyException ex) { throw new CreationConflict(ex); }
				// The HTTP adapter saves the official session before this transaction can commit.
				persistSession.run();
				// Session renewal must not erase the original idle deadline while writes wait.
				if (!this.sessions.isAuthenticationCurrent(actorId, authenticatedAt, credentialVersion)
						|| !this.sessions.isWithinSessionDeadline(authenticatedAt, expiry.orElseThrow())
						|| this.administrators.authorities(actorId, authenticatedAt, management).isEmpty()) {
					throw new IllegalStateException("Administrator authentication is no longer current");
				}
				return new Result(Status.CREATED, user);
			});
		}
		catch (CreationConflict ex) {
			// Inspect after rollback: a uniqueness race must not leave a transaction marked for rollback.
			if (this.users.findByUsername(normalizedUsername).isPresent()) { return rejected(Status.CONFLICT); }
			throw (DuplicateKeyException) ex.getCause();
		}
	}

	private static Result rejected(Status status) { return new Result(status, null); }

	public enum Status { CREATED, INVALID_INPUT, INVALID_SESSION, FORBIDDEN, REJECTED, THROTTLED, CONFLICT }

	public record Result(Status status, IdentityUser user) { }

	/** Only a conflict in the creation workflow may be considered a username collision after rollback. */
	private static final class CreationConflict extends RuntimeException {
		CreationConflict(DuplicateKeyException cause) { super(cause); }
	}

}
