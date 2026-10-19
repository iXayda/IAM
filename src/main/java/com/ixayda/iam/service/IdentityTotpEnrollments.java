package com.ixayda.iam.service;

import java.util.Optional;
import java.util.UUID;
import java.util.function.Consumer;

import com.ixayda.iam.model.IdentityTotpEnrollment;
import com.ixayda.iam.model.IdentityUser;
import com.ixayda.iam.model.MfaRecoveryCodeSet;
import com.ixayda.iam.model.PasswordAuthenticationContext;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.SecurityAuditEvent.Action;
import com.ixayda.iam.model.TotpAuthenticationContext;
import com.ixayda.iam.repository.IdentityTotpRepository;

import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.util.Assert;

/** Reauthenticates initial enrollment and commits factor changes with their session binding atomically. */
@Service
public class IdentityTotpEnrollments {

	private final IdentityUsers users;
	private final IdentityBrowserSessions sessions;
	private final IdentityAuthentications authentications;
	private final PasswordAuthenticationLimits passwordLimits;
	private final IdentityTotps totps;
	private final IdentityTotpRepository factors;
	private final IdentityMfaRecoveryCodes recoveryCodes;
	private final TotpAuthenticationLimits limits;
	private final SecurityAudits audits;
	private final TransactionTemplate transaction;

	IdentityTotpEnrollments(IdentityUsers users, IdentityBrowserSessions sessions, IdentityAuthentications authentications,
			PasswordAuthenticationLimits passwordLimits, IdentityTotps totps,
			IdentityTotpRepository factors, IdentityMfaRecoveryCodes recoveryCodes, TotpAuthenticationLimits limits,
			SecurityAudits audits, PlatformTransactionManager manager) {
		this.users = users;
		this.sessions = sessions;
		this.authentications = authentications;
		this.passwordLimits = passwordLimits;
		this.totps = totps;
		this.factors = factors;
		this.recoveryCodes = recoveryCodes;
		this.limits = limits;
		this.audits = audits;
		this.transaction = new TransactionTemplate(manager);
	}

	public EnrollmentResult begin(UUID userId, String sessionId, long credentialVersion, long authenticatedAt,
			String currentPassword, PasswordAuthenticationContext context, Consumer<UUID> persistEnrollment) {
		validateInvocation(userId, sessionId, persistEnrollment);
		Assert.notNull(context, "Trusted authentication context is required");
		return this.transaction.execute(status -> {
			var known = this.users.findById(userId);
			if (known.isEmpty()) { return new EnrollmentResult(Status.INVALID_SESSION, null); }
			// Prelock shared password budgets before user/session rows; authentication reuses these locks.
			var attempt = this.passwordLimits.lock(known.orElseThrow().username(), context);
			if (!attempt.allowed()) {
				this.audits.recordFailure(Action.PASSWORD_AUTH_THROTTLED, null,
						new SecurityAuditContext("anonymous", context.source(), context.correlationId()));
				return new EnrollmentResult(Status.THROTTLED, null);
			}
			var expiry = lockSession(userId, sessionId, credentialVersion, authenticatedAt);
			if (expiry.isEmpty()) {
				return new EnrollmentResult(Status.INVALID_SESSION, null);
			}
			if (this.totps.hasActiveFactor(userId)) { return new EnrollmentResult(Status.REJECTED, null); }
			var verified = this.authentications.authenticateInTransaction(known.orElseThrow().username(), currentPassword, context);
			if (verified.isEmpty()) { return new EnrollmentResult(Status.REJECTED, null); }
			if (!verified.orElseThrow().userId().equals(userId)
					|| verified.orElseThrow().credentialVersion() != credentialVersion) {
				throw new IllegalStateException("Password authentication is no longer current");
			}
			// Password verification and its mandatory audit can cross the original session deadline.
			requireCurrentSession(userId, sessionId, credentialVersion, authenticatedAt, expiry.orElseThrow());
			var audit = new SecurityAuditContext("user:" + userId, context.source(), context.correlationId());
			var enrollment = this.totps.beginEnrollmentInTransaction(userId, audit);
			persistEnrollment.accept(enrollment.factorId());
			requireCurrentSession(userId, sessionId, credentialVersion, authenticatedAt, expiry.orElseThrow());
			requireUnexpiredFactor(userId, enrollment.factorId(), false);
			return new EnrollmentResult(Status.COMPLETED, enrollment);
		});
	}

	public ConfirmationResult confirm(UUID userId, String sessionId, long credentialVersion, long authenticatedAt,
			UUID boundFactorId, UUID factorId, String code, TotpAuthenticationContext context, Consumer<UUID> persistEnrollment) {
		validateInvocation(userId, sessionId, persistEnrollment);
		Assert.notNull(context, "Trusted authentication context is required");
		return this.transaction.execute(status -> {
			// All verification workflows take shared source/account budgets before user and session locks.
			var attempt = this.limits.lock(userId, context);
			var anonymous = new SecurityAuditContext("anonymous", context.source(), context.correlationId());
			if (!attempt.allowed()) {
				this.audits.recordFailure(Action.TOTP_ENROLLMENT_THROTTLED, null, anonymous);
				return new ConfirmationResult(Status.THROTTLED, null);
			}
			var expiry = lockSession(userId, sessionId, credentialVersion, authenticatedAt);
			if (expiry.isEmpty()) {
				return new ConfirmationResult(Status.INVALID_SESSION, null);
			}
			if (factorId == null || !factorId.equals(boundFactorId)) {
				this.limits.failed(attempt);
				this.audits.recordFailure(Action.TOTP_ENROLLMENT_FAILED, userId, anonymous);
				return new ConfirmationResult(Status.REJECTED, null);
			}
			var verified = this.totps.confirmEnrollmentInTransaction(userId, factorId, code, context);
			if (verified.isEmpty()) { return new ConfirmationResult(Status.REJECTED, null); }
			if (verified.orElseThrow().credentialVersion() != credentialVersion) {
				throw new IllegalStateException("Password authentication is no longer current");
			}
			var issued = this.recoveryCodes.issueForVerifiedFactor(userId, factorId,
					new SecurityAuditContext("user:" + userId, context.source(), context.correlationId()));
			persistEnrollment.accept(null);
			requireCurrentSession(userId, sessionId, credentialVersion, authenticatedAt, expiry.orElseThrow());
			requireUnexpiredFactor(userId, factorId, true);
			return new ConfirmationResult(Status.COMPLETED, issued);
		});
	}

	public Status cancel(UUID userId, String sessionId, long credentialVersion, long authenticatedAt,
			UUID boundFactorId, UUID factorId, SecurityAuditContext audit, Consumer<UUID> persistEnrollment) {
		validateInvocation(userId, sessionId, persistEnrollment);
		Assert.notNull(audit, "Trusted audit context is required");
		return this.transaction.execute(status -> {
			var expiry = lockSession(userId, sessionId, credentialVersion, authenticatedAt);
			if (expiry.isEmpty()) { return Status.INVALID_SESSION; }
			if (factorId == null || !factorId.equals(boundFactorId)
					|| !this.totps.cancelEnrollmentInTransaction(userId, factorId, audit)) { return Status.REJECTED; }
			persistEnrollment.accept(null);
			requireCurrentSession(userId, sessionId, credentialVersion, authenticatedAt, expiry.orElseThrow());
			return Status.COMPLETED;
		});
	}

	private Optional<Long> lockSession(UUID userId, String sessionId, long version, long authenticatedAt) {
		if (this.users.lockForTotp(userId).filter(user -> user.status() == IdentityUser.Status.ACTIVE).isEmpty()) { return Optional.empty(); }
		var expiry = this.sessions.lockOwnedSessionExpiry(userId, sessionId);
		return this.sessions.isAuthenticationCurrent(userId, authenticatedAt, version) ? expiry : Optional.empty();
	}

	private void requireCurrentSession(UUID userId, String sessionId, long version, long authenticatedAt, long idleExpiry) {
		if (!this.sessions.isAuthenticationCurrent(userId, authenticatedAt, version)
				|| !this.sessions.isWithinSessionDeadline(authenticatedAt, idleExpiry)
				|| !this.sessions.lockOwnedSession(userId, sessionId)) {
			throw new IllegalStateException("Password session expired during TOTP enrollment");
		}
	}

	private void requireUnexpiredFactor(UUID userId, UUID factorId, boolean active) {
		if (this.factors.find(userId).filter(factor -> factor.factorId().equals(factorId)
				&& factor.active() == active && factor.unexpired()).isEmpty()) {
			throw new IllegalStateException("TOTP enrollment expired during persistence");
		}
	}

	private static void validateInvocation(UUID userId, String sessionId, Consumer<UUID> persistEnrollment) {
		Assert.notNull(userId, "Authenticated user id is required");
		Assert.hasText(sessionId, "Authenticated session id is required");
		Assert.notNull(persistEnrollment, "Session persistence is required");
		if (TransactionSynchronizationManager.isActualTransactionActive()) {
			throw new IllegalStateException("TOTP enrollment requires an independent transaction");
		}
	}

	public enum Status { COMPLETED, REJECTED, THROTTLED, INVALID_SESSION }
	public record EnrollmentResult(Status status, IdentityTotpEnrollment enrollment) { }
	public record ConfirmationResult(Status status, MfaRecoveryCodeSet codeSet) { }

}
