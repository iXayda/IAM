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
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
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

	private final IdentityAuthorizationRevocations revocations;

	private final SecurityAudits audits;

	private final TransactionTemplate transaction;

	IdentityPasswordRecoveries(IdentityUsers users, IdentityPasswordRecoveryRepository repository,
			PasswordRecoveryTokens tokens, PasswordHasher passwords, IdentityBrowserSessions sessions, IdentityAuthorizationRevocations revocations,
			SecurityAudits audits, PlatformTransactionManager manager) {
		this.users = users;
		this.repository = repository;
		this.tokens = tokens;
		this.passwords = passwords;
		this.sessions = sessions;
		this.revocations = revocations;
		this.audits = audits;
		this.transaction = new TransactionTemplate(manager);
	}

	/** Return the one-time plaintext only after issuance and audit commit successfully. */
	public IdentityPasswordRecovery issue(UUID userId, SecurityAuditContext audit) {
		validateInvocation(userId);
		Assert.notNull(audit, "Trusted audit context is required");
		return this.transaction.execute(status -> issueInTransaction(userId, audit));
	}

	/** The authorized management workflow owns the transaction and delivers only after commit. */
	@Transactional(propagation = Propagation.MANDATORY)
	IdentityPasswordRecovery issueInTransaction(UUID userId, SecurityAuditContext audit) {
		Assert.notNull(userId, "User id is required");
		Assert.notNull(audit, "Trusted audit context is required");
		if (this.users.lockById(userId).status() != IdentityUser.Status.ACTIVE) {
			throw new IllegalStateException("Password recovery requires an active user with a password");
		}
		long version = this.users.passwordVersion(userId).orElseThrow(
				() -> new IllegalStateException("Password recovery requires an active user with a password"));
		String token = this.tokens.generate();
		var expires = this.repository.issue(userId, this.tokens.digest(token), version);
		this.audits.recordSuccess(Action.PASSWORD_RECOVERY_ISSUED, userId, audit);
		return new IdentityPasswordRecovery(userId, token, expires);
	}

	public void cancel(UUID userId, SecurityAuditContext audit) {
		validateInvocation(userId);
		Assert.notNull(audit, "Trusted audit context is required");
		this.transaction.executeWithoutResult(status -> {
			this.users.lockById(userId);
			if (!this.repository.cancel(userId)) {
				throw new IllegalStateException("No outstanding password recovery");
			}
			this.audits.recordSuccess(Action.PASSWORD_RECOVERY_CANCELLED, userId, audit);
		});
	}

	/** The lifecycle workflow already holds the owning user's lock. */
	@Transactional(propagation = Propagation.MANDATORY)
	void cancelOutstanding(UUID userId, SecurityAuditContext audit) {
		if (this.repository.cancel(userId)) {
			this.audits.recordSuccess(Action.PASSWORD_RECOVERY_CANCELLED, userId, audit);
		}
	}

	/** The proof establishes identity; callers supply the trusted entry source, never a claimed actor. */
	public Result complete(UUID userId, String token, String newPassword, String source, UUID correlationId) {
		validateInvocation(userId);
		var anonymous = new SecurityAuditContext("anonymous", source, correlationId);
		Result result;
		try { result = this.transaction.execute(status -> completeInTransaction(userId, token, newPassword, anonymous)); }
		catch (InvalidProofException ex) { result = Result.INVALID_PROOF; }
		if (result != Result.COMPLETED) {
			Result denial = result;
			// A late expiry rolls back the replacement first; persist denial before returning even in that case.
			this.transaction.executeWithoutResult(status -> this.audits.recordFailure(Action.PASSWORD_RECOVERY_FAILED,
					this.users.findById(userId).map(IdentityUser::id).orElse(null), denial == Result.INVALID_PASSWORD
							? new SecurityAuditContext("user:" + userId, source, correlationId) : anonymous));
		}
		return result;
	}

	/** The caller owns the budget and transaction; ordinary denials do not write an audit here. */
	@Transactional(propagation = Propagation.MANDATORY)
	Result completeInTransaction(UUID userId, String token, String newPassword, SecurityAuditContext anonymous) {
		Assert.notNull(userId, "User id is required");
		Assert.notNull(anonymous, "Trusted recovery context is required");
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
			throw new InvalidProofException();
		}
		var audit = new SecurityAuditContext("user:" + userId, anonymous.source(), anonymous.correlationId());
		this.sessions.revokeAll(userId, audit);
		this.revocations.revokeForUser(userId, audit);
		this.audits.recordSuccess(Action.PASSWORD_RECOVERY_COMPLETED, userId, audit);
		if (!this.repository.isFreshlyConsumed(userId, digest)) { throw new InvalidProofException(); }
		return Result.COMPLETED;
	}

	private static void validateInvocation(UUID userId) {
		Assert.notNull(userId, "User id is required");
		if (TransactionSynchronizationManager.isActualTransactionActive()) {
			throw new IllegalStateException("Password recovery requires an independent transaction");
		}
	}

	/** A deadline crossed after mutation: roll back before recording the denial independently. */
	static final class InvalidProofException extends IllegalArgumentException {
		InvalidProofException() { super("Invalid password recovery credential"); }
	}

	public enum Result {
		COMPLETED, INVALID_PROOF, INVALID_PASSWORD
	}

}
