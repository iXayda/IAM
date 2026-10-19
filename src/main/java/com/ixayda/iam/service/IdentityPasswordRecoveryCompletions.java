package com.ixayda.iam.service;

import java.util.UUID;

import com.ixayda.iam.credential.PasswordRecoveryTokens;
import com.ixayda.iam.model.IdentityUser;
import com.ixayda.iam.model.PasswordRecoveryContext;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.SecurityAuditEvent.Action;
import com.ixayda.iam.repository.IdentityPasswordRecoveryRepository;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.util.Assert;

/** Public proof consumption: independent budgets, uniform denials and committed outcomes. */
@Service
public class IdentityPasswordRecoveryCompletions {

	private final IdentityUsers users;
	private final IdentityPasswordRecoveries recoveries;
	private final IdentityPasswordRecoveryRepository repository;
	private final PasswordRecoveryTokens tokens;
	private final PasswordRecoveryLimits limits;
	private final SecurityAudits audits;
	private final TransactionTemplate transaction;

	IdentityPasswordRecoveryCompletions(IdentityUsers users, IdentityPasswordRecoveries recoveries, IdentityPasswordRecoveryRepository repository,
			PasswordRecoveryTokens tokens, PasswordRecoveryLimits limits, SecurityAudits audits,
			PlatformTransactionManager manager) {
		this.users = users;
		this.recoveries = recoveries;
		this.repository = repository;
		this.tokens = tokens;
		this.limits = limits;
		this.audits = audits;
		this.transaction = new TransactionTemplate(manager);
	}

	/** The transport establishes source and correlation; only a valid proof establishes the user. */
	public Result complete(String userId, String token, String newPassword, PasswordRecoveryContext context) {
		Assert.notNull(context, "Trusted recovery context is required");
		if (TransactionSynchronizationManager.isActualTransactionActive()) {
			throw new IllegalStateException("Password recovery completion requires an independent transaction");
		}
		UUID id = parseUserId(userId);
		try { return this.transaction.execute(status -> evaluate(id, token, newPassword, context)); }
		catch (IdentityPasswordRecoveries.InvalidProofException ex) {
			// The first transaction has rolled back its password, consumption, session revocation and success audit.
			return this.transaction.execute(status -> {
				var attempt = this.limits.lock(account(id), context);
				if (!attempt.allowed()) { return throttled(context); }
				return rejected(id, Result.INVALID_PROOF, attempt, context);
			});
		}
	}

	private Result evaluate(UUID id, String token, String newPassword, PasswordRecoveryContext context) {
		var attempt = this.limits.lock(account(id), context);
		if (!attempt.allowed()) { return throttled(context); }
		String digest;
		try { digest = this.tokens.digest(token); }
		catch (IllegalArgumentException ex) { return rejected(id, Result.INVALID_PROOF, attempt, context); }
		if (id == null) { return rejected(null, Result.INVALID_PROOF, attempt, context); }
		var result = this.recoveries.completeInTransaction(id, token, newPassword,
				new SecurityAuditContext("anonymous", context.source(), context.correlationId()));
		if (result != IdentityPasswordRecoveries.Result.COMPLETED) {
			return rejected(id, result == IdentityPasswordRecoveries.Result.INVALID_PASSWORD
					? Result.INVALID_PASSWORD : Result.INVALID_PROOF, attempt, context);
		}
		this.limits.succeeded(attempt);
		if (!this.repository.isFreshlyConsumed(id, digest)) { throw new IdentityPasswordRecoveries.InvalidProofException(); }
		return Result.COMPLETED;
	}

	private Result rejected(UUID id, Result result, PasswordRecoveryLimits.Attempt attempt, PasswordRecoveryContext context) {
		this.limits.failed(attempt);
		var audit = new SecurityAuditContext(result == Result.INVALID_PASSWORD ? "user:" + id : "anonymous", context.source(), context.correlationId());
		this.audits.recordFailure(Action.PASSWORD_RECOVERY_FAILED, id == null ? null : this.users.findById(id).map(IdentityUser::id).orElse(null), audit);
		return result;
	}

	private Result throttled(PasswordRecoveryContext context) {
		this.audits.recordFailure(Action.PASSWORD_RECOVERY_THROTTLED, null,
				new SecurityAuditContext("anonymous", context.source(), context.correlationId()));
		return Result.THROTTLED;
	}

	private static String account(UUID id) { return id == null ? "invalid-user-id" : id.toString(); }

	private static UUID parseUserId(String value) {
		if (value == null) { return null; }
		try {
			UUID id = UUID.fromString(value);
			return id.toString().equalsIgnoreCase(value) ? id : null;
		}
		catch (IllegalArgumentException ex) { return null; }
	}

	@Scheduled(fixedDelayString = "${iam.password-recovery.cleanup-ms:60000}", initialDelayString = "${iam.password-recovery.cleanup-ms:60000}")
	public void cleanUpExpiredLimits() {
		this.transaction.executeWithoutResult(status -> this.limits.cleanUpExpired());
	}

	public enum Result { COMPLETED, INVALID_PROOF, INVALID_PASSWORD, THROTTLED }

}
