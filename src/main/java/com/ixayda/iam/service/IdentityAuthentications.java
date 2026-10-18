package com.ixayda.iam.service;

import java.util.Locale;
import java.util.Optional;
import java.util.UUID;

import com.ixayda.iam.credential.PasswordHasher;
import com.ixayda.iam.model.IdentityUser;
import com.ixayda.iam.model.PasswordAuthenticationContext;
import com.ixayda.iam.model.PasswordAuthenticationResult;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.SecurityAuditEvent.Action;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.util.Assert;

/** Transactional password decisions; the authentication adapter rejects ambient transactions. */
@Service
public class IdentityAuthentications {

	private final IdentityUsers users;

	private final PasswordHasher passwords;

	private final PasswordAuthenticationLimits limits;

	private final SecurityAudits audits;

	private final String placeholderHash;

	private final TransactionTemplate transaction;

	IdentityAuthentications(IdentityUsers users, PasswordHasher passwords, PasswordAuthenticationLimits limits,
			SecurityAudits audits, PlatformTransactionManager transactionManager) {
		this.users = users;
		this.passwords = passwords;
		this.limits = limits;
		this.audits = audits;
		this.transaction = new TransactionTemplate(transactionManager);
		this.placeholderHash = passwords.hash(UUID.randomUUID().toString(), "iam-authentication-placeholder");
	}

	/** Ordinary denial is a result so failure counters and failure audit commit before the adapter throws. */
	public Optional<PasswordAuthenticationResult> authenticate(String username, String password, PasswordAuthenticationContext context) {
		Assert.notNull(context, "Trusted authentication context is required");
		if (TransactionSynchronizationManager.isActualTransactionActive()) {
			throw new IllegalStateException("Password authentication requires an independent transaction");
		}
		return this.transaction.execute(status -> evaluate(username, password, context));
	}

	/** Joins trusted recovery issuance; the workflow acquires recovery budgets before password/user locks. */
	@Transactional(propagation = Propagation.MANDATORY)
	Optional<PasswordAuthenticationResult> authenticateInTransaction(String username, String password, PasswordAuthenticationContext context) {
		Assert.notNull(context, "Trusted authentication context is required");
		return evaluate(username, password, context);
	}

	@Scheduled(fixedDelayString = "${iam.password-authentication.cleanup-ms:60000}", initialDelayString = "${iam.password-authentication.cleanup-ms:60000}")
	public void cleanUpExpiredLimits() {
		this.transaction.executeWithoutResult(status -> this.limits.cleanUpExpired());
	}

	private Optional<PasswordAuthenticationResult> evaluate(String username, String password, PasswordAuthenticationContext context) {
		String account = normalizeAccount(username);
		var attempt = this.limits.lock(account, context);
		SecurityAuditContext anonymous = new SecurityAuditContext("anonymous", context.source(), context.correlationId());
		// Short-circuit a blocked source before creating, resetting, or locking an account bucket.
		if (!attempt.allowed()) {
			this.audits.recordFailure(Action.PASSWORD_AUTH_THROTTLED, null, anonymous);
			return Optional.empty();
		}
		Optional<IdentityUser> user = account.equals("<invalid>") ? Optional.empty() : this.users.lockForPasswordAuthentication(account);
		Optional<String> storedHash = user.flatMap(value -> this.users.passwordHash(value.id()));
		boolean matches = this.passwords.matches(password, storedHash.orElse(this.placeholderHash));
		if (matches && storedHash.isPresent() && user.orElseThrow().status() == IdentityUser.Status.ACTIVE) {
			IdentityUser authenticated = user.orElseThrow();
			this.limits.succeeded(attempt);
			this.audits.recordSuccess(Action.PASSWORD_AUTHENTICATED, authenticated.id(),
					new SecurityAuditContext("user:" + authenticated.id(), context.source(), context.correlationId()));
			return Optional.of(new PasswordAuthenticationResult(authenticated.id(),
					this.users.passwordVersion(authenticated.id()).orElseThrow(), context.correlationId()));
		}
		this.limits.failed(attempt);
		this.audits.recordFailure(Action.PASSWORD_AUTH_FAILED, user.map(IdentityUser::id).orElse(null), anonymous);
		return Optional.empty();
	}

	private static String normalizeAccount(String username) {
		return username != null && username.length() >= 3 && username.length() <= 64
				&& username.matches("[a-zA-Z0-9._-]{3,64}") ? username.toLowerCase(Locale.ROOT) : "<invalid>";
	}

}
