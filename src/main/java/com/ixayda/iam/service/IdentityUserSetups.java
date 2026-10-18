package com.ixayda.iam.service;

import java.util.UUID;

import com.ixayda.iam.credential.AccountSetupTokens;
import com.ixayda.iam.model.IdentityUserSetup;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.SecurityAuditEvent.Action;
import com.ixayda.iam.repository.IdentityUserSetupRepository;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.Assert;

/** Internal workflows; callers must authorize issuance/cancellation and arrange trusted delivery. */
@Service
public class IdentityUserSetups {

	private final IdentityUsers users;

	private final IdentityUserSetupRepository repository;

	private final AccountSetupTokens tokens;

	private final SecurityAudits audits;

	IdentityUserSetups(IdentityUsers users, IdentityUserSetupRepository repository, AccountSetupTokens tokens,
			SecurityAudits audits) {
		this.users = users;
		this.repository = repository;
		this.tokens = tokens;
		this.audits = audits;
	}

	/** Reissuing replaces any previous proof; the plaintext is returned only by this operation. */
	@Transactional
	public IdentityUserSetup issue(UUID userId, SecurityAuditContext audit) {
		Assert.notNull(userId, "User id is required");
		Assert.notNull(audit, "Audit context is required");
		this.users.lockForSetup(userId);
		String token = this.tokens.generate();
		var expiresAt = this.repository.issue(userId, this.tokens.digest(token));
		this.audits.recordSuccess(Action.ACCOUNT_SETUP_ISSUED, userId, audit);
		return new IdentityUserSetup(userId, token, expiresAt);
	}

	@Transactional
	public void cancel(UUID userId, SecurityAuditContext audit) {
		Assert.notNull(userId, "User id is required");
		Assert.notNull(audit, "Audit context is required");
		this.users.lockById(userId);
		if (!this.repository.cancel(userId)) {
			throw new IllegalStateException("No outstanding account setup");
		}
		this.audits.recordSuccess(Action.ACCOUNT_SETUP_CANCELLED, userId, audit);
	}

	/** The lifecycle workflow already holds the owning user's lock. */
	@Transactional(propagation = Propagation.MANDATORY)
	void cancelOutstanding(UUID userId, SecurityAuditContext audit) {
		if (this.repository.cancel(userId)) {
			this.audits.recordSuccess(Action.ACCOUNT_SETUP_CANCELLED, userId, audit);
		}
	}

	/** Source and correlation id belong to the trusted entry; the proof establishes the actor. */
	@Transactional
	public void complete(UUID userId, String token, String password, String source, UUID correlationId) {
		Assert.notNull(userId, "User id is required");
		SecurityAuditContext audit = new SecurityAuditContext("user:" + userId, source, correlationId);
		String digest = this.tokens.digest(token);
		this.users.lockForSetup(userId);
		if (!this.repository.isUsable(userId, digest)) {
			throw new InvalidProofException();
		}
		this.users.setInitialPassword(userId, password, audit);
		// Recheck real time after password hashing; a failed consume rolls back the password and audit.
		if (!this.repository.consume(userId, digest)) {
			throw new InvalidProofException();
		}
		this.users.activateAfterSetup(userId);
		this.audits.recordSuccess(Action.ACCOUNT_SETUP_COMPLETED, userId, audit);
	}

	/** A late proof rejection must roll back all writes before the HTTP workflow records its denial. */
	static final class InvalidProofException extends IllegalArgumentException {
		InvalidProofException() { super("Invalid account setup credential"); }
	}

}
