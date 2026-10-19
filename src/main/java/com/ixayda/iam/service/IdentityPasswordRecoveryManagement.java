package com.ixayda.iam.service;

import java.util.Optional;
import java.util.UUID;

import com.ixayda.iam.model.IdentityAdministratorAuthentication;
import com.ixayda.iam.model.IdentityUser;
import com.ixayda.iam.model.IdentityPasswordRecovery;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.SecurityAuditEvent.Action;
import com.ixayda.iam.model.TotpAuthenticationContext;

import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.util.Assert;

/** Authorizes proof management and consumes fresh TOTP in the same transaction as the proof and audit. */
@Service
public class IdentityPasswordRecoveryManagement {

	private final IdentityUsers users;
	private final IdentityPasswordRecoveries recoveries;
	private final IdentityBrowserSessions sessions;
	private final IdentityAdministratorSessions administrators;
	private final IdentityTotps totps;
	private final TotpAuthenticationLimits limits;
	private final SecurityAudits audits;
	private final TransactionTemplate transaction;

	IdentityPasswordRecoveryManagement(IdentityUsers users, IdentityPasswordRecoveries recoveries, IdentityBrowserSessions sessions,
			IdentityAdministratorSessions administrators, IdentityTotps totps, TotpAuthenticationLimits limits,
			SecurityAudits audits, PlatformTransactionManager manager) {
		this.users = users;
		this.recoveries = recoveries;
		this.sessions = sessions;
		this.administrators = administrators;
		this.totps = totps;
		this.limits = limits;
		this.audits = audits;
		this.transaction = new TransactionTemplate(manager);
	}

	/** Authentication evidence and attribution must come from the trusted HTTP adapter. Returns only after commit. */
	public Result manage(UUID actorId, String sessionId, long credentialVersion, long authenticatedAt,
			IdentityAdministratorAuthentication management, UUID targetId, Operation operation, String code,
			TotpAuthenticationContext context, Runnable persistSession) {
		Assert.notNull(actorId, "Authenticated user id is required");
		Assert.hasText(sessionId, "Authenticated session id is required");
		Assert.notNull(targetId, "Target user id is required");
		Assert.notNull(operation, "Recovery management operation is required");
		Assert.notNull(context, "Trusted authentication context is required");
		Assert.notNull(persistSession, "Session persistence is required");
		if (TransactionSynchronizationManager.isActualTransactionActive()) {
			throw new IllegalStateException("Administrator password recovery management requires an independent transaction");
		}
		return this.transaction.execute(status -> {
			var attempt = this.limits.lock(actorId, context);
			if (!attempt.allowed()) {
				this.audits.recordFailure(Action.TOTP_AUTH_THROTTLED, null,
						new SecurityAuditContext("anonymous", context.source(), context.correlationId()));
				return result(Status.THROTTLED);
			}
			// Match state-change lock ordering even when a caller targets itself or another administrator.
			Optional<IdentityUser> actor;
			Optional<IdentityUser> target;
			if (actorId.equals(targetId)) {
				actor = this.users.lockForPasswordRecoveryManagement(actorId);
				target = actor;
			}
			else if (actorId.compareTo(targetId) < 0) {
				actor = this.users.lockForPasswordRecoveryManagement(actorId);
				target = this.users.lockForPasswordRecoveryManagement(targetId);
			}
			else {
				target = this.users.lockForPasswordRecoveryManagement(targetId);
				actor = this.users.lockForPasswordRecoveryManagement(actorId);
			}
			var expiry = this.sessions.lockOwnedSessionExpiry(actorId, sessionId);
			if (actor.filter(user -> user.status() == IdentityUser.Status.ACTIVE).isEmpty() || expiry.isEmpty()
					|| !this.sessions.isAuthenticationCurrent(actorId, authenticatedAt, credentialVersion)) {
				return result(Status.INVALID_SESSION);
			}
			var audit = new SecurityAuditContext("user:" + actorId, context.source(), context.correlationId());
			if (this.administrators.authorities(actorId, authenticatedAt, management).isEmpty()) {
				this.audits.recordFailure(Action.ADMIN_ACCESS_DENIED, actorId, audit);
				return result(Status.FORBIDDEN);
			}
			var verified = this.totps.verifyInTransaction(actorId, code, context);
			if (verified.isEmpty()) { return result(Status.REJECTED); }
			if (verified.orElseThrow().credentialVersion() != credentialVersion) {
				throw new IllegalStateException("Password authentication is no longer current");
			}
			persistSession.run();
			requireCurrent(actorId, authenticatedAt, credentialVersion, management, expiry.orElseThrow());
			Result result;
			if (target.isEmpty()) { result = result(Status.NOT_FOUND); }
			else if (operation == Operation.CANCEL) {
				this.recoveries.cancelOutstanding(targetId, audit);
				result = result(Status.CANCELLED);
			}
			else if (target.orElseThrow().status() != IdentityUser.Status.ACTIVE || this.users.passwordVersion(targetId).isEmpty()) {
				result = result(Status.CONFLICT);
			}
			else { result = new Result(Status.ISSUED, this.recoveries.issueInTransaction(targetId, audit)); }
			requireCurrent(actorId, authenticatedAt, credentialVersion, management, expiry.orElseThrow());
			return result;
		});
	}

	private void requireCurrent(UUID actorId, long authenticatedAt, long credentialVersion, IdentityAdministratorAuthentication management, long idleExpiry) {
		if (!this.sessions.isAuthenticationCurrent(actorId, authenticatedAt, credentialVersion)
				|| !this.sessions.isWithinSessionDeadline(authenticatedAt, idleExpiry)
				|| this.administrators.authorities(actorId, authenticatedAt, management).isEmpty()) {
			throw new IllegalStateException("Administrator authentication is no longer current");
		}
	}

	private static Result result(Status status) { return new Result(status, null); }

	public enum Operation { ISSUE, CANCEL }

	public enum Status { ISSUED, CANCELLED, INVALID_SESSION, FORBIDDEN, REJECTED, THROTTLED, NOT_FOUND, CONFLICT }

	public record Result(Status status, IdentityPasswordRecovery recovery) { }

}
