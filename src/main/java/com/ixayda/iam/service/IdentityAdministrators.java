package com.ixayda.iam.service;

import java.util.Optional;
import java.util.UUID;

import com.ixayda.iam.credential.TotpSecrets;
import com.ixayda.iam.model.IdentityAdministrator;
import com.ixayda.iam.model.IdentityAdministratorSetup;
import com.ixayda.iam.model.IdentityTotpEnrollment;
import com.ixayda.iam.model.IdentityUser;
import com.ixayda.iam.model.MfaRecoveryCodeSet;
import com.ixayda.iam.model.PasswordAuthenticationContext;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.SecurityAuditEvent.Action;
import com.ixayda.iam.model.TotpAuthenticationContext;
import com.ixayda.iam.repository.IdentityAdministratorRepository;

import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.util.Assert;

/** Trusted deployment initialization and management-identity invariants, separate from application roles. */
@Service
public class IdentityAdministrators {

	private final IdentityAdministratorRepository repository;
	private final IdentityUsers users;
	private final IdentityUserSetups setups;
	private final IdentityAuthentications authentications;
	private final IdentityTotps totps;
	private final TotpAuthenticationLimits limits;
	private final TotpSecrets secrets;
	private final IdentityMfaRecoveryCodes recoveryCodes;
	private final IdentityBrowserSessions sessions;
	private final SecurityAudits audits;
	private final TransactionTemplate transaction;

	IdentityAdministrators(IdentityAdministratorRepository repository, IdentityUsers users, IdentityUserSetups setups, IdentityAuthentications authentications,
			IdentityTotps totps, TotpAuthenticationLimits limits, TotpSecrets secrets, IdentityMfaRecoveryCodes recoveryCodes,
			IdentityBrowserSessions sessions, SecurityAudits audits, PlatformTransactionManager manager) {
		this.repository = repository;
		this.users = users;
		this.setups = setups;
		this.authentications = authentications;
		this.totps = totps;
		this.limits = limits;
		this.secrets = secrets;
		this.recoveryCodes = recoveryCodes;
		this.sessions = sessions;
		this.audits = audits;
		this.transaction = new TransactionTemplate(manager);
	}

	/** Eligibility alone does not authorize a request; a management entry must require current MFA. */
	public Optional<IdentityAdministrator> findByUserId(UUID userId) {
		Assert.notNull(userId, "User id is required");
		return this.repository.find(userId);
	}

	/** Deployment-only discovery; never reopens a completed or inconsistent initialization. */
	public Optional<UUID> candidateId() {
		requireIndependentTransaction();
		return this.transaction.execute(status -> {
			var lifecycle = this.repository.lockLifecycle();
			if (lifecycle.completed() || this.repository.hasAdministrators()) {
				throw new IllegalStateException("Administrator initialization is closed");
			}
			return Optional.ofNullable(lifecycle.candidateUserId());
		});
	}

	/** The account owner sets their password in an authorized deployment session; no proof leaves this transaction. */
	public UUID createCandidate(String username, String displayName, String password, SecurityAuditContext audit) {
		Assert.notNull(audit, "Trusted audit context is required");
		requireIndependentTransaction();
		this.secrets.requireConfigured();
		return this.transaction.execute(status -> {
			// A newly inserted, uncommitted user is owned by this transaction before the lifecycle is locked.
			var user = this.users.create(username, displayName, audit);
			var lifecycle = this.repository.lockLifecycle();
			if (lifecycle.completed() || lifecycle.candidateUserId() != null || this.repository.hasAdministrators()) {
				throw new IllegalStateException("Administrator candidate preparation is closed");
			}
			var proof = this.setups.issue(user.id(), audit);
			this.setups.complete(user.id(), proof.token(), password, audit.source(), audit.correlationId());
			this.repository.reserveCandidate(user.id(), lifecycle.revision());
			this.audits.recordSuccess(Action.ADMIN_BOOTSTRAP_PREPARED, user.id(), audit);
			return user.id();
		});
	}

	/** Reentry verifies the current password; only unconfirmed enrollment material may be replaced. */
	public Optional<IdentityAdministratorSetup> prepareCandidate(UUID userId, String password, TotpAuthenticationContext context) {
		Assert.notNull(userId, "User id is required");
		Assert.notNull(context, "Trusted authentication context is required");
		requireIndependentTransaction();
		this.secrets.requireConfigured();
		return this.transaction.execute(status -> {
			if (!authenticate(userId, password, context)) { return Optional.empty(); }
			var lifecycle = this.repository.lockLifecycle();
			if (!isOpenFor(lifecycle, userId)) {
				this.audits.recordFailure(Action.ADMIN_BOOTSTRAP_REJECTED, userId, anonymous(context));
				return Optional.empty();
			}
			if (lifecycle.candidateUserId() == null) {
				this.repository.reserveCandidate(userId, lifecycle.revision());
				this.audits.recordSuccess(Action.ADMIN_BOOTSTRAP_PREPARED, userId,
						new SecurityAuditContext("user:" + userId, context.source(), context.correlationId()));
			}
			var enrollment = this.totps.hasActiveFactor(userId) ? Optional.<IdentityTotpEnrollment>empty()
					: Optional.of(this.totps.beginEnrollmentInTransaction(userId,
							new SecurityAuditContext("user:" + userId, context.source(), context.correlationId())));
			return Optional.of(new IdentityAdministratorSetup(userId, enrollment));
		});
	}

	/** Explicit trusted deployment operation. Fresh credentials, grant, closure, and codes commit together. */
	public Optional<MfaRecoveryCodeSet> bootstrap(UUID userId, String password, String code, TotpAuthenticationContext context) {
		return bootstrap(userId, null, password, code, context);
	}

	/** A pending factor is activated in the grant transaction; an absent enrollment id requires an already active factor. */
	public Optional<MfaRecoveryCodeSet> bootstrap(UUID userId, UUID enrollmentId, String password, String code,
			TotpAuthenticationContext context) {
		Assert.notNull(userId, "User id is required");
		Assert.notNull(context, "Trusted authentication context is required");
		requireIndependentTransaction();
		this.secrets.requireConfigured();
		return this.transaction.execute(status -> {
			if (!authenticate(userId, password, context)) { return Optional.empty(); }
			var lifecycle = this.repository.lockLifecycle();
			if (!isOpenFor(lifecycle, userId) || (enrollmentId != null && !userId.equals(lifecycle.candidateUserId()))) {
				this.audits.recordFailure(Action.ADMIN_BOOTSTRAP_REJECTED, userId, anonymous(context));
				return Optional.empty();
			}
			var verified = enrollmentId == null ? this.totps.verifyInTransaction(userId, code, context)
					: this.totps.confirmEnrollmentInTransaction(userId, enrollmentId, code, context);
			if (verified.isEmpty()) { return Optional.empty(); }
			var decision = verified.orElseThrow();
			this.repository.completeBootstrap(userId, lifecycle.revision());
			this.users.invalidateAuthentications(userId, decision.credentialVersion());
			var audit = new SecurityAuditContext("user:" + userId, context.source(), context.correlationId());
			this.sessions.revokeAll(userId, audit);
			var codes = this.recoveryCodes.issueForVerifiedFactor(userId, decision.factorId(), audit);
			this.audits.recordSuccess(Action.ADMIN_BOOTSTRAP_COMPLETED, userId, audit);
			return Optional.of(codes);
		});
	}

	private boolean authenticate(UUID userId, String password, TotpAuthenticationContext context) {
		var attempt = this.limits.lock(userId, context);
		if (!attempt.allowed()) {
			this.audits.recordFailure(Action.ADMIN_BOOTSTRAP_THROTTLED, null, anonymous(context));
			return false;
		}
		String username = this.users.findById(userId).map(IdentityUser::username).orElse(null);
		var authenticated = this.authentications.authenticateInTransaction(username, password,
				new PasswordAuthenticationContext(context.source(), context.clientAddress(), context.correlationId()));
		if (authenticated.isEmpty() || !authenticated.orElseThrow().userId().equals(userId)) {
			this.limits.failed(attempt);
			return false;
		}
		return true;
	}

	private boolean isOpenFor(IdentityAdministratorRepository.Lifecycle lifecycle, UUID userId) {
		return !lifecycle.completed() && !this.repository.hasAdministrators()
				&& (lifecycle.candidateUserId() == null || userId.equals(lifecycle.candidateUserId()));
	}

	private static void requireIndependentTransaction() {
		if (TransactionSynchronizationManager.isActualTransactionActive()) {
			throw new IllegalStateException("Administrator initialization requires an independent transaction");
		}
	}

	/** Caller already holds the target user lock; count every other structurally usable administrator. */
	@Transactional(propagation = Propagation.MANDATORY)
	boolean allowDisable(UUID userId, SecurityAuditContext audit) {
		var lifecycle = this.repository.lockLifecycle();
		// Lock before the membership read: an older snapshot must not miss a just-committed bootstrap grant.
		if (this.repository.find(userId).isEmpty()) { return true; }
		if (!this.repository.hasOtherUsableAdministrator(userId)) {
			this.audits.recordFailure(Action.LAST_ADMINISTRATOR_PROTECTED, userId, audit);
			return false;
		}
		this.repository.advanceRevision(lifecycle.revision());
		return true;
	}

	private static SecurityAuditContext anonymous(TotpAuthenticationContext context) {
		return new SecurityAuditContext("anonymous", context.source(), context.correlationId());
	}

}
