package com.ixayda.iam.service;

import java.net.InetAddress;
import java.util.Optional;
import java.util.UUID;

import com.ixayda.iam.model.IdentityTotpEnrollment;
import com.ixayda.iam.model.MfaRecoveryCodeSet;
import com.ixayda.iam.model.PasswordAuthenticationContext;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.SecurityAuditEvent.Action;
import com.ixayda.iam.model.SecurityAuditTarget;
import com.ixayda.iam.model.TotpAuthenticationContext;
import com.ixayda.iam.repository.IdentityAdministratorRepository;
import com.ixayda.iam.repository.IdentityRestoreAdministratorRepository;
import com.ixayda.iam.repository.IdentityRestoreRepository;

import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;

/** Owner-only, externally authorized recovery of one existing identity; never reopens installation bootstrap or admits Web traffic. */
@Service
public class IdentityRestoreAdministrators {

	private final IdentityRestoreRepository restores;
	private final IdentityRestoreAdministratorRepository repository;
	private final IdentityAdministratorRepository administrators;
	private final IdentityUsers users;
	private final IdentityUserStates states;
	private final IdentityUserSetups setups;
	private final IdentityTotps totps;
	private final IdentityAuthentications authentications;
	private final TotpAuthenticationLimits limits;
	private final IdentityMfaRecoveryCodes recoveryCodes;
	private final SecurityAudits audits;
	private final TransactionTemplate transaction;

	IdentityRestoreAdministrators(IdentityRestoreRepository restores, IdentityRestoreAdministratorRepository repository,
			IdentityAdministratorRepository administrators, IdentityUsers users, IdentityUserStates states, IdentityUserSetups setups,
			IdentityTotps totps, IdentityAuthentications authentications, TotpAuthenticationLimits limits,
			IdentityMfaRecoveryCodes recoveryCodes, SecurityAudits audits, PlatformTransactionManager manager) {
		this.restores = restores; this.repository = repository; this.administrators = administrators; this.users = users;
		this.states = states; this.setups = setups; this.totps = totps; this.authentications = authentications; this.limits = limits;
		this.recoveryCodes = recoveryCodes; this.audits = audits; this.transaction = new TransactionTemplate(manager);
		this.transaction.setIsolationLevel(TransactionDefinition.ISOLATION_READ_COMMITTED);
	}

	/** Repeating preparation for the same still-unqualified subject replaces pending credentials after renewed external authorization. */
	public IdentityTotpEnrollment prepare(String database, UUID restoreId, UUID userId, String password, SecurityAuditContext audit) {
		validate(restoreId, userId, audit);
		return this.transaction.execute(tx -> {
			requirePendingRestore(database, restoreId);
			var candidate = this.repository.find(restoreId);
			if (candidate.isPresent() && (!candidate.orElseThrow().userId().equals(userId) || candidate.orElseThrow().completedAt() != null)) {
				throw new IllegalStateException("Restore administrator is already reserved or completed");
			}
			if (this.administrators.hasAdministrators()) { throw new IllegalStateException("A restored administrator already exists"); }
			this.users.lockById(userId);
			this.states.disable(userId, audit);
			this.repository.clearCandidateCredentials(userId);
			this.states.enable(userId, audit);
			var proof = this.setups.issue(userId, audit);
			this.setups.complete(userId, proof.token(), password, audit.source(), audit.correlationId());
			var enrollment = this.totps.beginEnrollmentInTransaction(userId, audit);
			this.repository.prepare(restoreId, userId, enrollment.factorId());
			this.audits.recordTargetSuccess(Action.RESTORE_ADMIN_PREPARED, userId, target(restoreId), audit);
			return enrollment;
		});
	}

	/** Password, fresh factor activation, membership and newly generated recovery codes commit together. */
	public Optional<MfaRecoveryCodeSet> complete(String database, UUID restoreId, UUID userId, UUID factorId,
			String password, String code, SecurityAuditContext audit) {
		validate(restoreId, userId, audit);
		if (factorId == null) { throw new IllegalArgumentException("Restore enrollment is required"); }
		return this.transaction.execute(tx -> {
			requirePendingRestore(database, restoreId);
			var candidate = this.repository.find(restoreId).filter(row -> row.userId().equals(userId) && row.factorId().equals(factorId) && row.completedAt() == null)
					.orElseThrow(() -> new IllegalStateException("Restore administrator preparation is not current"));
			if (this.administrators.hasAdministrators()) { throw new IllegalStateException("A restored administrator already exists"); }
			var context = new TotpAuthenticationContext(audit.source(), InetAddress.getLoopbackAddress(), audit.correlationId());
			var attempt = this.limits.lock(userId, context);
			if (!attempt.allowed()) { this.audits.recordFailure(Action.RESTORE_ADMIN_THROTTLED, userId, audit); return Optional.empty(); }
			String username = this.users.findById(userId).orElseThrow().username();
			var authenticated = this.authentications.authenticateInTransaction(username, password,
					new PasswordAuthenticationContext(audit.source(), context.clientAddress(), audit.correlationId()));
			if (authenticated.isEmpty() || !authenticated.orElseThrow().userId().equals(userId)) {
				this.limits.failed(attempt); this.audits.recordFailure(Action.RESTORE_ADMIN_REJECTED, userId, audit); return Optional.empty();
			}
			var verification = this.totps.confirmEnrollmentInTransaction(userId, factorId, code, context);
			if (verification.isEmpty()) { this.audits.recordFailure(Action.RESTORE_ADMIN_REJECTED, userId, audit); return Optional.empty(); }
			this.repository.complete(candidate);
			this.users.invalidateAuthentications(userId, verification.orElseThrow().credentialVersion());
			var codes = this.recoveryCodes.issueForVerifiedFactor(userId, factorId, audit);
			this.audits.recordTargetSuccess(Action.RESTORE_ADMIN_COMPLETED, userId, target(restoreId), audit);
			return Optional.of(codes);
		});
	}

	private void requirePendingRestore(String database, UUID restoreId) {
		this.restores.requireOfflineOwner(database); this.restores.lockForQuarantine();
		if (this.restores.isAvailable() || !this.restores.current().map(row -> row.id().equals(restoreId)).orElse(false)
				|| !this.administrators.lockLifecycle().restoreClosed()) { throw new IllegalStateException("Confirmed restore is not quarantined"); }
	}

	private static void validate(UUID restoreId, UUID userId, SecurityAuditContext audit) {
		if (restoreId == null || userId == null || audit == null
				|| !audit.actor().matches("deployment:[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}")
				|| !audit.source().matches("deployment:restore-admin:[a-zA-Z0-9][a-zA-Z0-9._-]{0,31}")) {
			throw new IllegalArgumentException("Verified restore, subject and deployment authorization are required");
		}
		if (TransactionSynchronizationManager.isActualTransactionActive()) { throw new IllegalStateException("Restore administrator recovery requires an independent transaction"); }
	}

	private static SecurityAuditTarget target(UUID restoreId) { return new SecurityAuditTarget(SecurityAuditTarget.Type.DATABASE_RESTORE, restoreId); }
}
