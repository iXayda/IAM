package com.ixayda.iam.service;

import java.util.Optional;
import java.util.UUID;

import com.ixayda.iam.model.IdentityTotpReplacement;
import com.ixayda.iam.model.IdentityUser;
import com.ixayda.iam.model.MfaRecoveryCodeSet;
import com.ixayda.iam.model.PasswordAuthenticationContext;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.SecurityAuditEvent.Action;
import com.ixayda.iam.model.TotpAuthenticationContext;
import com.ixayda.iam.repository.IdentityTotpReplacementRepository;

import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.util.Assert;

/** Binds factor replacement to an owning password session without granting management access. */
@Service
public class IdentityTotpReplacementSessions {

	private final IdentityUsers users;
	private final IdentityBrowserSessions sessions;
	private final IdentityTotpReplacements replacements;
	private final IdentityTotpReplacementRepository repository;
	private final TotpAuthenticationLimits totpLimits;
	private final PasswordAuthenticationLimits passwordLimits;
	private final SecurityAudits audits;
	private final TransactionTemplate transaction;

	IdentityTotpReplacementSessions(IdentityUsers users, IdentityBrowserSessions sessions, IdentityTotpReplacements replacements,
			IdentityTotpReplacementRepository repository, TotpAuthenticationLimits totpLimits,
			PasswordAuthenticationLimits passwordLimits, SecurityAudits audits, PlatformTransactionManager manager) {
		this.users = users;
		this.sessions = sessions;
		this.replacements = replacements;
		this.repository = repository;
		this.totpLimits = totpLimits;
		this.passwordLimits = passwordLimits;
		this.audits = audits;
		this.transaction = new TransactionTemplate(manager);
	}

	public BeginResult begin(UUID userId, String sessionId, long version, long authenticatedAt, String currentPassword,
			String code, TotpAuthenticationContext context, Runnable persistSession) {
		validateInvocation(userId, sessionId, context);
		Assert.notNull(persistSession, "Session persistence is required");
		return this.transaction.execute(status -> {
			// Never acquire a new budget after a user/session lock: TOTP, password, user, then session.
			var attempt = this.totpLimits.lock(userId, context);
			if (!attempt.allowed()) {
				recordThrottle(context);
				return new BeginResult(Status.THROTTLED, null);
			}
			var known = this.users.findById(userId);
			if (known.isEmpty()) { return new BeginResult(Status.INVALID_SESSION, null); }
			var passwordContext = new PasswordAuthenticationContext(context.source(), context.clientAddress(), context.correlationId());
			var passwordAttempt = this.passwordLimits.lock(known.orElseThrow().username(), passwordContext);
			if (!passwordAttempt.allowed()) {
				this.audits.recordFailure(Action.PASSWORD_AUTH_THROTTLED, null, anonymous(context));
				this.totpLimits.failed(attempt);
				return new BeginResult(Status.THROTTLED, null);
			}
			var idleExpiry = lockSession(userId, sessionId, version, authenticatedAt);
			if (idleExpiry.isEmpty()) {
				return new BeginResult(Status.INVALID_SESSION, null);
			}
			var pending = this.replacements.beginInTransaction(userId, currentPassword, code, context);
			if (pending.isEmpty()) { return new BeginResult(Status.REJECTED, null); }
			requireCurrentSession(userId, sessionId, version, authenticatedAt);
			persistSession.run();
			requireCurrentSession(userId, sessionId, version, authenticatedAt);
			if (!this.sessions.isWithinSessionDeadline(authenticatedAt, idleExpiry.orElseThrow())) {
				throw new IllegalStateException("Password session expired during TOTP replacement persistence");
			}
			var replacement = pending.orElseThrow();
			if (this.repository.find(userId).filter(value -> value.replacementId().equals(replacement.replacementId())
					&& value.expiresAt().isAfter(value.now())).isEmpty()) {
				throw new IllegalStateException("TOTP replacement expired during persistence");
			}
			return new BeginResult(Status.COMPLETED, replacement);
		});
	}

	public CompletionResult complete(UUID userId, String sessionId, long version, long authenticatedAt, UUID replacementId,
			String token, String code, TotpAuthenticationContext context) {
		validateInvocation(userId, sessionId, context);
		return this.transaction.execute(status -> {
			var attempt = this.totpLimits.lock(userId, context);
			if (!attempt.allowed()) {
				recordThrottle(context);
				return new CompletionResult(Status.THROTTLED, null);
			}
			var idleExpiry = lockSession(userId, sessionId, version, authenticatedAt);
			if (idleExpiry.isEmpty()) { return new CompletionResult(Status.INVALID_SESSION, null); }
			var pendingExpiry = this.repository.find(userId).filter(value -> value.replacementId().equals(replacementId))
					.map(IdentityTotpReplacementRepository.Replacement::expiresAt);
			var issued = this.replacements.completeInTransaction(userId, replacementId, token, code, context);
			if (issued.isEmpty()) { return new CompletionResult(Status.REJECTED, null); }
			// Successful replacement has removed every session and advanced the password version.
			// Recheck the captured deadlines, rather than trying to save or reload the revoked session.
			long deadline = Math.min(idleExpiry.orElseThrow(), pendingExpiry.orElseThrow().toEpochMilli());
			if (!this.sessions.isWithinSessionDeadline(authenticatedAt, deadline)) {
				throw new IllegalStateException("Password session or proof expired during TOTP replacement");
			}
			return new CompletionResult(Status.COMPLETED, issued.orElseThrow());
		});
	}

	private Optional<Long> lockSession(UUID userId, String sessionId, long version, long authenticatedAt) {
		if (this.users.lockForTotp(userId).filter(user -> user.status() == IdentityUser.Status.ACTIVE).isEmpty()
				|| !this.sessions.isAuthenticationCurrent(userId, authenticatedAt, version)) { return Optional.empty(); }
		var expiry = this.sessions.lockOwnedSessionExpiry(userId, sessionId);
		return this.sessions.isAuthenticationCurrent(userId, authenticatedAt, version) ? expiry : Optional.empty();
	}

	private void requireCurrentSession(UUID userId, String sessionId, long version, long authenticatedAt) {
		if (lockSession(userId, sessionId, version, authenticatedAt).isEmpty()) {
			throw new IllegalStateException("Password session expired during TOTP replacement");
		}
	}

	private void recordThrottle(TotpAuthenticationContext context) {
		this.audits.recordFailure(Action.TOTP_REPLACEMENT_THROTTLED, null, anonymous(context));
	}

	private static SecurityAuditContext anonymous(TotpAuthenticationContext context) {
		return new SecurityAuditContext("anonymous", context.source(), context.correlationId());
	}

	private static void validateInvocation(UUID userId, String sessionId, TotpAuthenticationContext context) {
		Assert.notNull(userId, "Authenticated user id is required");
		Assert.hasText(sessionId, "Authenticated session id is required");
		Assert.notNull(context, "Trusted authentication context is required");
		if (TransactionSynchronizationManager.isActualTransactionActive()) {
			throw new IllegalStateException("TOTP replacement requires an independent transaction");
		}
	}

	public enum Status { COMPLETED, REJECTED, THROTTLED, INVALID_SESSION }
	public record BeginResult(Status status, IdentityTotpReplacement replacement) { }
	public record CompletionResult(Status status, MfaRecoveryCodeSet codeSet) { }

}
