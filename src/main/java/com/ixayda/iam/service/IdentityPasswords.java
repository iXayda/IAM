package com.ixayda.iam.service;

import java.util.UUID;

import com.ixayda.iam.credential.PasswordHasher;
import com.ixayda.iam.credential.PasswordRejectedException;
import com.ixayda.iam.model.IdentityUser;
import com.ixayda.iam.model.PasswordAuthenticationContext;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.SecurityAuditEvent.Action;

import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.util.Assert;

/** Password replacement, revocation and success audit commit together; ordinary denials commit their failure audit. */
@Service
public class IdentityPasswords {

	private final IdentityUsers users;

	private final PasswordHasher passwords;

	private final PasswordAuthenticationLimits limits;

	private final IdentityBrowserSessions sessions;

	private final IdentityAuthorizationRevocations revocations;

	private final SecurityAudits audits;

	private final TransactionTemplate transaction;

	IdentityPasswords(IdentityUsers users, PasswordHasher passwords, PasswordAuthenticationLimits limits,
			IdentityBrowserSessions sessions, IdentityAuthorizationRevocations revocations, SecurityAudits audits, PlatformTransactionManager manager) {
		this.users = users;
		this.passwords = passwords;
		this.limits = limits;
		this.sessions = sessions;
		this.revocations = revocations;
		this.audits = audits;
		this.transaction = new TransactionTemplate(manager);
	}

	/** Identity and session evidence must come from the authenticated entry, never request fields. */
	public Result change(UUID userId, String sessionId, long credentialVersion, long authenticatedAt,
			String currentPassword, String newPassword, PasswordAuthenticationContext context) {
		Assert.notNull(userId, "Authenticated user id is required");
		Assert.hasText(sessionId, "Authenticated session id is required");
		Assert.notNull(context, "Trusted authentication context is required");
		if (TransactionSynchronizationManager.isActualTransactionActive()) {
			throw new IllegalStateException("Password change requires an independent transaction");
		}
		return this.transaction.execute(status -> evaluate(userId, sessionId, credentialVersion, authenticatedAt,
				currentPassword, newPassword, context));
	}

	private Result evaluate(UUID userId, String sessionId, long credentialVersion, long authenticatedAt,
			String currentPassword, String newPassword, PasswordAuthenticationContext context) {
		IdentityUser known = this.users.findById(userId).orElseThrow();
		var audit = new SecurityAuditContext("user:" + userId, context.source(), context.correlationId());
		var attempt = this.limits.lock(known.username(), context);
		if (!attempt.allowed()) {
			this.audits.recordFailure(Action.PASSWORD_CHANGE_THROTTLED, userId, audit);
			return Result.THROTTLED;
		}
		IdentityUser user = this.users.lockById(userId);
		var expiry = this.sessions.lockOwnedSessionExpiry(userId, sessionId);
		if (user.status() != IdentityUser.Status.ACTIVE
				|| !this.sessions.isAuthenticationCurrent(userId, authenticatedAt, credentialVersion)
				|| expiry.isEmpty()) {
			this.audits.recordFailure(Action.PASSWORD_CHANGE_FAILED, userId, audit);
			return Result.INVALID_SESSION;
		}
		String storedHash = this.users.passwordHash(userId).orElseThrow();
		if (!this.passwords.matches(currentPassword, storedHash)) {
			this.limits.failed(attempt);
			this.audits.recordFailure(Action.PASSWORD_CHANGE_FAILED, userId, audit);
			return Result.INVALID_CREDENTIALS;
		}
		String replacement;
		try {
			if (this.passwords.matches(newPassword, storedHash)) {
				this.audits.recordFailure(Action.PASSWORD_CHANGE_FAILED, userId, audit);
				return Result.INVALID_PASSWORD;
			}
			replacement = this.passwords.hash(newPassword, user.username());
		}
		catch (PasswordRejectedException ex) {
			this.audits.recordFailure(Action.PASSWORD_CHANGE_FAILED, userId, audit);
			return Result.INVALID_PASSWORD;
		}
		// Hashing may have crossed a session deadline; recheck before performing the change.
		if (!this.sessions.isAuthenticationCurrent(userId, authenticatedAt, credentialVersion)
				|| !this.sessions.lockOwnedSession(userId, sessionId)) {
			this.audits.recordFailure(Action.PASSWORD_CHANGE_FAILED, userId, audit);
			return Result.INVALID_SESSION;
		}
		this.users.replacePassword(userId, replacement, credentialVersion);
		this.sessions.revokeAll(userId, audit);
		this.revocations.revokeForUser(userId, audit);
		this.limits.succeeded(attempt);
		this.audits.recordSuccess(Action.PASSWORD_CHANGED, userId, audit);
		// Revocation is intentional; preserve the original deadlines through all writes and audit.
		if (!this.sessions.isWithinSessionDeadline(authenticatedAt, expiry.orElseThrow())) {
			throw new IllegalStateException("Password session expired during password change");
		}
		return Result.CHANGED;
	}

	public enum Result {
		CHANGED, INVALID_CREDENTIALS, INVALID_PASSWORD, INVALID_SESSION, THROTTLED
	}

}
