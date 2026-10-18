package com.ixayda.iam.service;

import java.util.UUID;

import com.ixayda.iam.credential.PasswordHasher;
import com.ixayda.iam.credential.PasswordRecoveryTokens;
import com.ixayda.iam.credential.PasswordRejectedException;
import com.ixayda.iam.model.IdentityPasswordRecovery;
import com.ixayda.iam.model.IdentityUser;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.SecurityAuditEvent.Action;
import com.ixayda.iam.repository.IdentityPasswordRecoveryRepository;

import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.util.Assert;

/** Internal workflows; trusted callers authorize issuance/cancellation and arrange verified delivery. */
@Service
public class IdentityPasswordRecoveries {

	private final IdentityUsers users;

	private final IdentityPasswordRecoveryRepository repository;

	private final PasswordRecoveryTokens tokens;

	private final PasswordHasher passwords;

	private final IdentityBrowserSessions sessions;

	private final SecurityAudits audits;

	private final TransactionTemplate transaction;

	IdentityPasswordRecoveries(IdentityUsers users, IdentityPasswordRecoveryRepository repository,
			PasswordRecoveryTokens tokens, PasswordHasher passwords, IdentityBrowserSessions sessions,
			SecurityAudits audits, PlatformTransactionManager manager) {
		this.users = users;
		this.repository = repository;
		this.tokens = tokens;
		this.passwords = passwords;
		this.sessions = sessions;
		this.audits = audits;
		this.transaction = new TransactionTemplate(manager);
	}

	/** Return the one-time plaintext only after issuance and audit commit successfully. */
	public IdentityPasswordRecovery issue(UUID userId, SecurityAuditContext audit) {
		validateInvocation(userId);
		Assert.notNull(audit, "Trusted audit context is required");
		return this.transaction.execute(status -> {
			if (this.users.lockById(userId).status() != IdentityUser.Status.ACTIVE) {
				throw new IllegalStateException("Password recovery requires an active user with a password");
			}
			long version = this.users.passwordVersion(userId).orElseThrow(
					() -> new IllegalStateException("Password recovery requires an active user with a password"));
			String token = this.tokens.generate();
			var expires = this.repository.issue(userId, this.tokens.digest(token), version);
			this.audits.recordSuccess(Action.PASSWORD_RECOVERY_ISSUED, userId, audit);
			return new IdentityPasswordRecovery(userId, token, expires);
		});
	}

	public void cancel(UUID userId, SecurityAuditContext audit) {
		validateInvocation(userId);
		Assert.notNull(audit, "Trusted audit context is required");
		this.transaction.executeWithoutResult(status -> {
			this.users.lockById(userId);
			this.repository.cancel(userId);
			this.audits.recordSuccess(Action.PASSWORD_RECOVERY_CANCELLED, userId, audit);
		});
	}

	/** The proof establishes identity; callers supply the trusted entry source, never a claimed actor. */
	public Result complete(UUID userId, String token, String newPassword, String source, UUID correlationId) {
		validateInvocation(userId);
		var anonymous = new SecurityAuditContext("anonymous", source, correlationId);
		Result result = this.transaction.execute(status -> evaluate(userId, token, newPassword, anonymous, status));
		if (result != Result.COMPLETED) {
			// A late expiry rolls back the replacement first; persist denial before returning even in that case.
			this.transaction.executeWithoutResult(status -> this.audits.recordFailure(Action.PASSWORD_RECOVERY_FAILED,
					this.users.findById(userId).map(IdentityUser::id).orElse(null), result == Result.INVALID_PASSWORD
							? new SecurityAuditContext("user:" + userId, source, correlationId) : anonymous));
		}
		return result;
	}

	private Result evaluate(UUID userId, String token, String newPassword, SecurityAuditContext anonymous, TransactionStatus status) {
		String digest;
		try {
			digest = this.tokens.digest(token);
		}
		catch (IllegalArgumentException ex) {
			return Result.INVALID_PROOF;
		}
		var user = this.users.lockForPasswordRecovery(userId);
		var version = this.users.passwordVersion(userId);
		if (user.isEmpty() || version.isEmpty() || !this.repository.isUsable(userId, digest, version.orElseThrow())) {
			return Result.INVALID_PROOF;
		}
		String replacement;
		try {
			if (this.passwords.matches(newPassword, this.users.passwordHash(userId).orElseThrow())) {
				return Result.INVALID_PASSWORD;
			}
			replacement = this.passwords.hash(newPassword, user.orElseThrow().username());
		}
		catch (PasswordRejectedException ex) {
			return Result.INVALID_PASSWORD;
		}
		this.users.replacePassword(userId, replacement, version.orElseThrow());
		if (!this.repository.consume(userId, digest, version.orElseThrow())) {
			status.setRollbackOnly();
			return Result.INVALID_PROOF;
		}
		var audit = new SecurityAuditContext("user:" + userId, anonymous.source(), anonymous.correlationId());
		this.sessions.revokeAllForCredentialReplacement(userId, audit);
		this.audits.recordSuccess(Action.PASSWORD_RECOVERY_COMPLETED, userId, audit);
		return Result.COMPLETED;
	}

	private static void validateInvocation(UUID userId) {
		Assert.notNull(userId, "User id is required");
		if (TransactionSynchronizationManager.isActualTransactionActive()) {
			throw new IllegalStateException("Password recovery requires an independent transaction");
		}
	}

	public enum Result {
		COMPLETED, INVALID_PROOF, INVALID_PASSWORD
	}

}
