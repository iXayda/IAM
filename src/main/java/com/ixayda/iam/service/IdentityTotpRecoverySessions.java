package com.ixayda.iam.service;

import java.util.Optional;
import java.util.UUID;

import com.ixayda.iam.model.IdentityTotpRecovery;
import com.ixayda.iam.model.IdentityUser;
import com.ixayda.iam.model.MfaRecoveryCodeContext;
import com.ixayda.iam.model.MfaRecoveryCodeSet;
import com.ixayda.iam.model.PasswordAuthenticationContext;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.SecurityAuditEvent.Action;
import com.ixayda.iam.model.TotpAuthenticationContext;
import com.ixayda.iam.repository.IdentityTotpRecoveryRepository;

import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.util.Assert;

/** Binds factor recovery to an owning password session without granting management access. */
@Service
public class IdentityTotpRecoverySessions {

	private final IdentityUsers users;
	private final IdentityBrowserSessions sessions;
	private final IdentityTotpRecoveries recoveries;
	private final IdentityTotpRecoveryRepository repository;
	private final MfaRecoveryCodeLimits recoveryLimits;
	private final TotpAuthenticationLimits totpLimits;
	private final PasswordAuthenticationLimits passwordLimits;
	private final SecurityAudits audits;
	private final TransactionTemplate transaction;

	IdentityTotpRecoverySessions(IdentityUsers users, IdentityBrowserSessions sessions, IdentityTotpRecoveries recoveries,
			IdentityTotpRecoveryRepository repository, MfaRecoveryCodeLimits recoveryLimits, TotpAuthenticationLimits totpLimits,
			PasswordAuthenticationLimits passwordLimits, SecurityAudits audits, PlatformTransactionManager manager) {
		this.users = users;
		this.sessions = sessions;
		this.recoveries = recoveries;
		this.repository = repository;
		this.recoveryLimits = recoveryLimits;
		this.totpLimits = totpLimits;
		this.passwordLimits = passwordLimits;
		this.audits = audits;
		this.transaction = new TransactionTemplate(manager);
	}

	public BeginResult begin(UUID userId, String sessionId, long version, long authenticatedAt, String currentPassword,
			String recoveryCode, MfaRecoveryCodeContext context, Runnable persistSession) {
		validateInvocation(userId, sessionId);
		Assert.notNull(context, "Trusted recovery-code context is required");
		Assert.notNull(persistSession, "Session persistence is required");
		return this.transaction.execute(status -> {
			// Never acquire a new budget after a user/session lock: recovery, password, user, then session.
			var attempt = this.recoveryLimits.lock(userId, context);
			if (!attempt.allowed()) {
				this.audits.recordFailure(Action.MFA_RECOVERY_CODE_THROTTLED, null, anonymous(context));
				return new BeginResult(Status.THROTTLED, null);
			}
			var known = this.users.findById(userId);
			if (known.isEmpty()) { return new BeginResult(Status.INVALID_SESSION, null); }
			var passwordContext = new PasswordAuthenticationContext(context.source(), context.clientAddress(), context.correlationId());
			var passwordAttempt = this.passwordLimits.lock(known.orElseThrow().username(), passwordContext);
			if (!passwordAttempt.allowed()) {
				this.audits.recordFailure(Action.PASSWORD_AUTH_THROTTLED, null, anonymous(context));
				this.recoveryLimits.failed(attempt);
				return new BeginResult(Status.THROTTLED, null);
			}
			var idleExpiry = lockSession(userId, sessionId, version, authenticatedAt);
			if (idleExpiry.isEmpty()) {
				return new BeginResult(Status.INVALID_SESSION, null);
			}
			var pending = this.recoveries.beginInTransaction(userId, currentPassword, recoveryCode, context);
			if (pending.isEmpty()) { return new BeginResult(Status.REJECTED, null); }
			requireCurrentSession(userId, sessionId, version, authenticatedAt);
			persistSession.run();
			requireCurrentSession(userId, sessionId, version, authenticatedAt);
			if (!this.sessions.isWithinSessionDeadline(authenticatedAt, idleExpiry.orElseThrow())) {
				throw new IllegalStateException("Password session expired during TOTP recovery persistence");
			}
			var recovery = pending.orElseThrow();
			if (this.repository.find(userId).filter(value -> value.recoveryId().equals(recovery.recoveryId())
					&& value.recoveryCodesCurrent() && value.expiresAt().isAfter(value.now())).isEmpty()) {
				throw new IllegalStateException("TOTP recovery expired during persistence");
			}
			return new BeginResult(Status.COMPLETED, recovery);
		});
	}

	public CompletionResult complete(UUID userId, String sessionId, long version, long authenticatedAt, UUID recoveryId,
			String token, String code, TotpAuthenticationContext context) {
		validateInvocation(userId, sessionId);
		Assert.notNull(context, "Trusted authentication context is required");
		return this.transaction.execute(status -> {
			var attempt = this.totpLimits.lock(userId, context);
			if (!attempt.allowed()) {
				this.audits.recordFailure(Action.TOTP_RECOVERY_THROTTLED, null,
						new SecurityAuditContext("anonymous", context.source(), context.correlationId()));
				return new CompletionResult(Status.THROTTLED, null);
			}
			var idleExpiry = lockSession(userId, sessionId, version, authenticatedAt);
			if (idleExpiry.isEmpty()) { return new CompletionResult(Status.INVALID_SESSION, null); }
			var pendingExpiry = this.repository.find(userId).filter(value -> value.recoveryId().equals(recoveryId))
					.map(IdentityTotpRecoveryRepository.Recovery::expiresAt);
			var issued = this.recoveries.completeInTransaction(userId, recoveryId, token, code, context);
			if (issued.isEmpty()) { return new CompletionResult(Status.REJECTED, null); }
			// Recovery has removed every session and advanced the password version; retain the original deadlines.
			long deadline = Math.min(idleExpiry.orElseThrow(), pendingExpiry.orElseThrow().toEpochMilli());
			if (!this.sessions.isWithinSessionDeadline(authenticatedAt, deadline)) {
				throw new IllegalStateException("Password session or proof expired during TOTP recovery");
			}
			return new CompletionResult(Status.COMPLETED, issued.orElseThrow());
		});
	}

	private Optional<Long> lockSession(UUID userId, String sessionId, long version, long authenticatedAt) {
		if (this.users.lockForMfaRecovery(userId).filter(user -> user.status() == IdentityUser.Status.ACTIVE).isEmpty()
				|| !this.sessions.isAuthenticationCurrent(userId, authenticatedAt, version)) { return Optional.empty(); }
		var expiry = this.sessions.lockOwnedSessionExpiry(userId, sessionId);
		return this.sessions.isAuthenticationCurrent(userId, authenticatedAt, version) ? expiry : Optional.empty();
	}

	private void requireCurrentSession(UUID userId, String sessionId, long version, long authenticatedAt) {
		if (lockSession(userId, sessionId, version, authenticatedAt).isEmpty()) {
			throw new IllegalStateException("Password session expired during TOTP recovery");
		}
	}

	private static SecurityAuditContext anonymous(MfaRecoveryCodeContext context) {
		return new SecurityAuditContext("anonymous", context.source(), context.correlationId());
	}

	private static void validateInvocation(UUID userId, String sessionId) {
		Assert.notNull(userId, "Authenticated user id is required");
		Assert.hasText(sessionId, "Authenticated session id is required");
		if (TransactionSynchronizationManager.isActualTransactionActive()) {
			throw new IllegalStateException("TOTP recovery requires an independent transaction");
		}
	}

	public enum Status { COMPLETED, REJECTED, THROTTLED, INVALID_SESSION }
	public record BeginResult(Status status, IdentityTotpRecovery recovery) { }
	public record CompletionResult(Status status, MfaRecoveryCodeSet codeSet) { }

}
