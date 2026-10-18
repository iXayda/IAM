package com.ixayda.iam.service;

import java.util.UUID;

import com.ixayda.iam.credential.AccountSetupTokens;
import com.ixayda.iam.credential.PasswordPolicy;
import com.ixayda.iam.credential.PasswordRejectedException;
import com.ixayda.iam.model.AccountSetupContext;
import com.ixayda.iam.model.IdentityUser;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.SecurityAuditEvent.Action;
import com.ixayda.iam.repository.IdentityUserSetupRepository;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.util.Assert;

/** Public proof consumption: independent budgets, uniform denials and committed outcomes. */
@Service
public class IdentityUserSetupCompletions {

	private final IdentityUsers users;
	private final IdentityUserSetups setups;
	private final IdentityUserSetupRepository repository;
	private final AccountSetupTokens tokens;
	private final PasswordPolicy policy;
	private final AccountSetupLimits limits;
	private final SecurityAudits audits;
	private final TransactionTemplate transaction;

	IdentityUserSetupCompletions(IdentityUsers users, IdentityUserSetups setups, IdentityUserSetupRepository repository,
			AccountSetupTokens tokens, PasswordPolicy policy, AccountSetupLimits limits, SecurityAudits audits,
			PlatformTransactionManager manager) {
		this.users = users;
		this.setups = setups;
		this.repository = repository;
		this.tokens = tokens;
		this.policy = policy;
		this.limits = limits;
		this.audits = audits;
		this.transaction = new TransactionTemplate(manager);
	}

	/** The transport establishes source and correlation; only a valid proof establishes the user. */
	public Result complete(String userId, String token, String password, AccountSetupContext context) {
		Assert.notNull(context, "Trusted setup context is required");
		if (TransactionSynchronizationManager.isActualTransactionActive()) {
			throw new IllegalStateException("Account setup completion requires an independent transaction");
		}
		UUID id = parseUserId(userId);
		try { return this.transaction.execute(status -> evaluate(id, token, password, context)); }
		catch (IdentityUserSetups.InvalidProofException ex) {
			// The first transaction has rolled back its password, activation, consumption and success audit.
			return this.transaction.execute(status -> {
				var attempt = this.limits.lock(account(id), context);
				if (!attempt.allowed()) { return throttled(context); }
				return rejected(id, Result.INVALID_PROOF, attempt, context);
			});
		}
	}

	private Result evaluate(UUID id, String token, String password, AccountSetupContext context) {
		var attempt = this.limits.lock(account(id), context);
		if (!attempt.allowed()) { return throttled(context); }
		String digest;
		try { digest = this.tokens.digest(token); }
		catch (IllegalArgumentException ex) { return rejected(id, Result.INVALID_PROOF, attempt, context); }
		if (id == null) { return rejected(null, Result.INVALID_PROOF, attempt, context); }
		var user = this.users.lockForSetupCompletion(id);
		if (user.filter(value -> value.status() == IdentityUser.Status.PENDING).isEmpty()
				|| this.users.passwordVersion(id).isPresent() || !this.repository.isUsable(id, digest)) {
			return rejected(id, Result.INVALID_PROOF, attempt, context);
		}
		try { this.policy.normalizeAndValidate(password, user.orElseThrow().username()); }
		catch (PasswordRejectedException ex) { return rejected(id, Result.INVALID_PASSWORD, attempt, context); }
		// Policy rejection commits without entering the transactional internal writer. Hashing occurs only there.
		this.setups.complete(id, token, password, context.source(), context.correlationId());
		this.limits.succeeded(attempt);
		if (!this.repository.isFreshlyConsumed(id, digest)) { throw new IdentityUserSetups.InvalidProofException(); }
		return Result.COMPLETED;
	}

	private Result rejected(UUID id, Result result, AccountSetupLimits.Attempt attempt, AccountSetupContext context) {
		this.limits.failed(attempt);
		var audit = new SecurityAuditContext(result == Result.INVALID_PASSWORD ? "user:" + id : "anonymous", context.source(), context.correlationId());
		this.audits.recordFailure(Action.ACCOUNT_SETUP_FAILED, id == null ? null : this.users.findById(id).map(IdentityUser::id).orElse(null), audit);
		return result;
	}

	private Result throttled(AccountSetupContext context) {
		this.audits.recordFailure(Action.ACCOUNT_SETUP_THROTTLED, null,
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

	@Scheduled(fixedDelayString = "${iam.account-setup.cleanup-ms:60000}", initialDelayString = "${iam.account-setup.cleanup-ms:60000}")
	public void cleanUpExpiredLimits() {
		this.transaction.executeWithoutResult(status -> this.limits.cleanUpExpired());
	}

	public enum Result { COMPLETED, INVALID_PROOF, INVALID_PASSWORD, THROTTLED }

}
