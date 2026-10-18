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

/** Authorizes a single account-state operation and consumes its TOTP in the state-change transaction. */
@Service
public class IdentityUserStateChanges {

	private final IdentityUsers users;
	private final IdentityUserStates states;
	private final IdentityBrowserSessions sessions;
	private final IdentityAdministratorSessions administrators;
	private final IdentityTotps totps;
	private final TotpAuthenticationLimits limits;
	private final SecurityAudits audits;
	private final TransactionTemplate transaction;

	IdentityUserStateChanges(IdentityUsers users, IdentityUserStates states, IdentityBrowserSessions sessions,
			IdentityAdministratorSessions administrators, IdentityTotps totps, TotpAuthenticationLimits limits,
			SecurityAudits audits, PlatformTransactionManager manager) {
		this.users = users;
		this.states = states;
		this.sessions = sessions;
		this.administrators = administrators;
		this.totps = totps;
		this.limits = limits;
		this.audits = audits;
		this.transaction = new TransactionTemplate(manager);
	}

	/** Authentication evidence, operation target and attribution are supplied by the trusted HTTP adapter. */
	public Status change(UUID actorId, String sessionId, long credentialVersion, long authenticatedAt,
			IdentityAdministratorAuthentication management, UUID targetId, Change change, String code,
			TotpAuthenticationContext context, Runnable persistSession) {
		Assert.notNull(actorId, "Authenticated user id is required");
		Assert.hasText(sessionId, "Authenticated session id is required");
		Assert.notNull(targetId, "Target user id is required");
		Assert.notNull(change, "Account state change is required");
		Assert.notNull(context, "Trusted authentication context is required");
		Assert.notNull(persistSession, "Session persistence is required");
		if (TransactionSynchronizationManager.isActualTransactionActive()) {
			throw new IllegalStateException("Administrator user state changes require an independent transaction");
		}
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
			// Save while the actor is still active. Self-disable then removes this saved session atomically.
			persistSession.run();
			requireCurrent(actorId, authenticatedAt, credentialVersion, management, expiry.orElseThrow());
			Status result;
			if (target.isEmpty()) { result = Status.NOT_FOUND; }
			else {
				var changed = change == Change.DISABLE ? this.states.disable(targetId, audit) : this.states.enable(targetId, audit);
				result = switch (changed) {
					case CHANGED -> Status.CHANGED;
					case UNCHANGED -> Status.UNCHANGED;
					case LAST_ADMINISTRATOR_PROTECTED -> Status.LAST_ADMINISTRATOR_PROTECTED;
				};
			}
			if (actorId.equals(targetId) && change == Change.DISABLE && result == Status.CHANGED) {
				// Intentional invalidation must not bypass the original password, idle or management deadlines.
				if (!this.sessions.isWithinSessionDeadline(authenticatedAt, expiry.orElseThrow()) || !this.administrators.withinLifetime(management)) {
					throw new IllegalStateException("Administrator authentication expired during self-disable");
				}
			}
			else { requireCurrent(actorId, authenticatedAt, credentialVersion, management, expiry.orElseThrow()); }
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

	public enum Change { ENABLE, DISABLE }

	public enum Status { CHANGED, UNCHANGED, INVALID_SESSION, FORBIDDEN, REJECTED, THROTTLED, NOT_FOUND, LAST_ADMINISTRATOR_PROTECTED }

}
