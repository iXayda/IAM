package com.ixayda.iam.service;

import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;

import com.ixayda.iam.model.IdentityAdministratorContext;
import com.ixayda.iam.model.IdentityUser;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.SecurityAuditEvent.Action;

import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.util.Assert;

/** Shared transaction boundary for current administrator evidence and a fresh operation TOTP. */
@Service
class IdentityAdministratorOperations {

	private final IdentityUsers users;
	private final IdentityBrowserSessions sessions;
	private final IdentityAdministratorSessions administrators;
	private final IdentityTotps totps;
	private final TotpAuthenticationLimits limits;
	private final SecurityAudits audits;
	private final TransactionTemplate transaction;

	IdentityAdministratorOperations(IdentityUsers users, IdentityBrowserSessions sessions,
			IdentityAdministratorSessions administrators, IdentityTotps totps, TotpAuthenticationLimits limits,
			SecurityAudits audits, PlatformTransactionManager manager) {
		this.users = users;
		this.sessions = sessions;
		this.administrators = administrators;
		this.totps = totps;
		this.limits = limits;
		this.audits = audits;
		this.transaction = new TransactionTemplate(manager);
	}

	<T> Result<T> execute(IdentityAdministratorContext context, String code, Runnable persistSession,
			Function<SecurityAuditContext, T> operation) {
		return execute(context, null, code, persistSession, operation);
	}

	<T> Result<T> execute(IdentityAdministratorContext context, UUID targetUserId, String code, Runnable persistSession,
			Function<SecurityAuditContext, T> operation) {
		return execute(context, targetUserId, code, persistSession, operation, false);
	}

	/** Only the target's authentication epoch may change; self-targeting saves before the intentional invalidation. */
	<T> Result<T> executeRevokingSessions(IdentityAdministratorContext context, UUID targetUserId, String code, Runnable persistSession,
			Function<SecurityAuditContext, T> operation) {
		Assert.notNull(targetUserId, "Session revocation target is required");
		return execute(context, targetUserId, code, persistSession, operation, true);
	}

	private <T> Result<T> execute(IdentityAdministratorContext context, UUID targetUserId, String code, Runnable persistSession,
			Function<SecurityAuditContext, T> operation, boolean revokesSessions) {
		Assert.notNull(context, "Administrator context is required");
		Assert.notNull(persistSession, "Session persistence is required");
		Assert.notNull(operation, "Administrator operation is required");
		if (TransactionSynchronizationManager.isActualTransactionActive()) {
			throw new IllegalStateException("Administrator operations require an independent transaction");
		}
		return this.transaction.execute(status -> {
			var attribution = context.authentication();
			var attempt = this.limits.lock(context.actorId(), attribution);
			if (!attempt.allowed()) {
				this.audits.recordFailure(Action.TOTP_AUTH_THROTTLED, null,
						new SecurityAuditContext("anonymous", attribution.source(), attribution.correlationId()));
				return rejected(Status.THROTTLED);
			}
			if (lockUsers(context.actorId(), targetUserId).filter(user -> user.status() == IdentityUser.Status.ACTIVE).isEmpty()) {
				return rejected(Status.INVALID_SESSION);
			}
			var expiry = this.sessions.lockOwnedSessionExpiry(context.actorId(), context.sessionId());
			if (expiry.isEmpty() || !this.sessions.isAuthenticationCurrent(context.actorId(), context.authenticatedAt(), context.credentialVersion())) {
				return rejected(Status.INVALID_SESSION);
			}
			var audit = new SecurityAuditContext("user:" + context.actorId(), attribution.source(), attribution.correlationId());
			if (this.administrators.authorities(context.actorId(), context.authenticatedAt(), context.management()).isEmpty()) {
				this.audits.recordFailure(Action.ADMIN_ACCESS_DENIED, context.actorId(), audit);
				return rejected(Status.FORBIDDEN);
			}
			var verified = this.totps.verifyInTransaction(context.actorId(), code, attribution);
			if (verified.isEmpty()) { return rejected(Status.REJECTED); }
			if (verified.orElseThrow().credentialVersion() != context.credentialVersion()) {
				throw new IllegalStateException("Password authentication is no longer current");
			}
			boolean selfRevocation = revokesSessions && context.actorId().equals(targetUserId);
			if (selfRevocation) { persistSession.run(); }
			var result = operation.apply(audit);
			if (!selfRevocation) { persistSession.run(); }
			boolean current = selfRevocation
					? this.administrators.isCurrentAfterInvalidation(context.management(), Math.addExact(context.credentialVersion(), 1))
					: this.sessions.isAuthenticationCurrent(context.actorId(), context.authenticatedAt(), context.credentialVersion())
							&& !this.administrators.authorities(context.actorId(), context.authenticatedAt(), context.management()).isEmpty();
			if (!current || !this.sessions.isWithinSessionDeadline(context.authenticatedAt(), expiry.orElseThrow())) {
				throw new IllegalStateException("Administrator authentication is no longer current");
			}
			return new Result<>(Status.COMPLETED, result);
		});
	}

	/** Match user-state workflows: administrators targeting each other acquire users in UUID order. */
	private Optional<IdentityUser> lockUsers(UUID actorId, UUID targetId) {
		if (targetId == null || actorId.equals(targetId)) { return this.users.lockForStateChange(actorId); }
		if (actorId.compareTo(targetId) < 0) {
			var actor = this.users.lockForStateChange(actorId);
			this.users.lockForStateChange(targetId);
			return actor;
		}
		this.users.lockForStateChange(targetId);
		return this.users.lockForStateChange(actorId);
	}

	private static <T> Result<T> rejected(Status status) { return new Result<>(status, null); }
	enum Status { COMPLETED, INVALID_SESSION, FORBIDDEN, REJECTED, THROTTLED }

	record Result<T>(Status status, T value) { }

}
