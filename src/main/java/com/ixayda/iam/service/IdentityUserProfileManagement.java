package com.ixayda.iam.service;

import java.util.Optional;
import java.util.UUID;

import com.ixayda.iam.model.IdentityAdministratorAuthentication;
import com.ixayda.iam.model.IdentityUser;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.SecurityAuditEvent.Action;
import com.ixayda.iam.model.TotpAuthenticationContext;

import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.util.Assert;

/** Commits an administrator profile change with current authority, ordered user locks and fresh TOTP. */
@Service
public class IdentityUserProfileManagement {

	private final IdentityUsers users;
	private final IdentityBrowserSessions sessions;
	private final IdentityAdministratorSessions administrators;
	private final IdentityTotps totps;
	private final TotpAuthenticationLimits limits;
	private final SecurityAudits audits;
	private final TransactionTemplate transaction;

	IdentityUserProfileManagement(IdentityUsers users, IdentityBrowserSessions sessions,
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

	/** Authentication evidence, operation target and attribution are supplied by the trusted HTTP adapter. */
	public Status updateDisplayName(UUID actorId, String sessionId, long credentialVersion, long authenticatedAt,
			IdentityAdministratorAuthentication management, UUID targetId, String displayName, String code,
			TotpAuthenticationContext context, Runnable persistSession) {
		Assert.notNull(actorId, "Authenticated user id is required");
		Assert.hasText(sessionId, "Authenticated session id is required");
		Assert.notNull(targetId, "Target user id is required");
		Assert.notNull(context, "Trusted authentication context is required");
		Assert.notNull(persistSession, "Session persistence is required");
		if (TransactionSynchronizationManager.isActualTransactionActive()) {
			throw new IllegalStateException("Administrator user profile changes require an independent transaction");
		}
		String normalized;
		try { normalized = IdentityUsers.normalizeDisplayName(displayName); }
		catch (IllegalArgumentException ex) { return Status.INVALID_INPUT; }
		return this.transaction.execute(status -> {
			var attempt = this.limits.lock(actorId, context);
			if (!attempt.allowed()) {
				this.audits.recordFailure(Action.TOTP_AUTH_THROTTLED, null,
						new SecurityAuditContext("anonymous", context.source(), context.correlationId()));
				return Status.THROTTLED;
			}
			// Two administrators may target each other; both paths acquire users before sessions and lifecycle locks.
			Optional<IdentityUser> actor;
			Optional<IdentityUser> target;
			if (actorId.equals(targetId)) {
				actor = this.users.lockForStateChange(actorId);
				target = actor;
			}
			else if (actorId.compareTo(targetId) < 0) {
				actor = this.users.lockForStateChange(actorId);
				target = this.users.lockForStateChange(targetId);
			}
			else {
				target = this.users.lockForStateChange(targetId);
				actor = this.users.lockForStateChange(actorId);
			}
			var expiry = this.sessions.lockOwnedSessionExpiry(actorId, sessionId);
			if (actor.filter(user -> user.status() == IdentityUser.Status.ACTIVE).isEmpty() || expiry.isEmpty()
					|| !this.sessions.isAuthenticationCurrent(actorId, authenticatedAt, credentialVersion)) {
				return Status.INVALID_SESSION;
			}
			var audit = new SecurityAuditContext("user:" + actorId, context.source(), context.correlationId());
			if (this.administrators.authorities(actorId, authenticatedAt, management).isEmpty()) {
				this.audits.recordFailure(Action.ADMIN_ACCESS_DENIED, actorId, audit);
				return Status.FORBIDDEN;
			}
			var verified = this.totps.verifyInTransaction(actorId, code, context);
			if (verified.isEmpty()) { return Status.REJECTED; }
			if (verified.orElseThrow().credentialVersion() != credentialVersion) {
				throw new IllegalStateException("Password authentication is no longer current");
			}
			Status result;
			if (target.isEmpty()) { result = Status.NOT_FOUND; }
			else if (target.orElseThrow().displayName().equals(normalized)) { result = Status.UNCHANGED; }
			else {
				this.users.updateDisplayName(targetId, normalized);
				this.audits.recordSuccess(Action.USER_PROFILE_UPDATED, targetId, audit);
				result = Status.UPDATED;
			}
			persistSession.run();
			requireCurrent(actorId, authenticatedAt, credentialVersion, management);
			if (!this.sessions.isWithinSessionDeadline(authenticatedAt, expiry.orElseThrow())) { throw new IllegalStateException("Administrator session expired during profile update"); }
			return result;
		});
	}

	private void requireCurrent(UUID actorId, long authenticatedAt, long credentialVersion, IdentityAdministratorAuthentication management) {
		if (!this.sessions.isAuthenticationCurrent(actorId, authenticatedAt, credentialVersion)
				|| this.administrators.authorities(actorId, authenticatedAt, management).isEmpty()) {
			throw new IllegalStateException("Administrator authentication is no longer current");
		}
	}

	public enum Status { UPDATED, UNCHANGED, INVALID_INPUT, INVALID_SESSION, FORBIDDEN, REJECTED, THROTTLED, NOT_FOUND }

}
