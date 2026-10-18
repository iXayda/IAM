package com.ixayda.iam.service;

import java.util.UUID;
import java.util.function.Function;

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

/** Commits TOTP consumption, session elevation and mandatory audit as one independent operation. */
@Service
public class IdentityAdministratorAuthentications {

	private final IdentityUsers users;
	private final IdentityBrowserSessions sessions;
	private final IdentityAdministratorSessions administrators;
	private final IdentityTotps totps;
	private final TotpAuthenticationLimits limits;
	private final SecurityAudits audits;
	private final TransactionTemplate transaction;

	IdentityAdministratorAuthentications(IdentityUsers users, IdentityBrowserSessions sessions, IdentityAdministratorSessions administrators,
			IdentityTotps totps, TotpAuthenticationLimits limits, SecurityAudits audits, PlatformTransactionManager manager) {
		this.users = users;
		this.sessions = sessions;
		this.administrators = administrators;
		this.totps = totps;
		this.limits = limits;
		this.audits = audits;
		this.transaction = new TransactionTemplate(manager);
	}

	/** The trusted HTTP adapter supplies session evidence and persists the rotated session before returning its new id. */
	public Result authenticate(UUID userId, String sessionId, long credentialVersion, long authenticatedAt, String code,
			TotpAuthenticationContext context, Function<IdentityAdministratorAuthentication, String> persist) {
		Assert.notNull(userId, "Authenticated user id is required");
		Assert.hasText(sessionId, "Authenticated session id is required");
		Assert.notNull(context, "Trusted authentication context is required");
		Assert.notNull(persist, "Session persistence is required");
		if (TransactionSynchronizationManager.isActualTransactionActive()) {
			throw new IllegalStateException("Administrator authentication requires an independent transaction");
		}
		return this.transaction.execute(status -> {
			// Match the shared TOTP lock order before locking the owning browser session.
			var attempt = this.limits.lock(userId, context);
			if (!attempt.allowed()) {
				this.audits.recordFailure(Action.TOTP_AUTH_THROTTLED, null,
						new SecurityAuditContext("anonymous", context.source(), context.correlationId()));
				return Result.THROTTLED;
			}
			if (this.users.lockById(userId).status() != IdentityUser.Status.ACTIVE) {
				return Result.INVALID_SESSION;
			}
			var expiry = this.sessions.lockOwnedSessionExpiry(userId, sessionId);
			if (expiry.isEmpty() || !this.sessions.isAuthenticationCurrent(userId, authenticatedAt, credentialVersion)) {
				return Result.INVALID_SESSION;
			}
			if (!this.administrators.isAdministrator(userId)) {
				this.audits.recordFailure(Action.ADMIN_MFA_REJECTED, userId,
						new SecurityAuditContext("user:" + userId, context.source(), context.correlationId()));
				return Result.REJECTED;
			}
			var verified = this.totps.verifyInTransaction(userId, code, context);
			if (verified.isEmpty()) { return Result.REJECTED; }
			var factor = verified.orElseThrow();
			if (factor.credentialVersion() != credentialVersion) {
				throw new IllegalStateException("Password authentication is no longer current");
			}
			var evidence = new IdentityAdministratorAuthentication(userId, factor.factorId(), credentialVersion, authenticatedAt, factor.verifiedAt());
			String rotatedId = persist.apply(evidence);
			if (sessionId.equals(rotatedId)) { throw new IllegalStateException("Administrator session id was not rotated"); }
			this.administrators.requireStored(sessionId, rotatedId, evidence);
			this.audits.recordSuccess(Action.ADMIN_MFA_AUTHENTICATED, userId,
					new SecurityAuditContext("user:" + userId, context.source(), context.correlationId()));
			if (!this.sessions.isWithinSessionDeadline(authenticatedAt, expiry.orElseThrow())) {
				throw new IllegalStateException("Administrator authentication is no longer current");
			}
			return Result.AUTHENTICATED;
		});
	}

	public enum Result { AUTHENTICATED, REJECTED, THROTTLED, INVALID_SESSION }

}
