package com.ixayda.iam.service;

import java.net.InetAddress;
import java.util.Optional;
import java.util.UUID;

import com.ixayda.iam.model.IdentityRestoreRelease;
import com.ixayda.iam.model.PasswordAuthenticationContext;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.SecurityAuditEvent.Action;
import com.ixayda.iam.model.SecurityAuditTarget;
import com.ixayda.iam.model.TotpAuthenticationContext;
import com.ixayda.iam.repository.IdentityAdministratorRepository;
import com.ixayda.iam.repository.IdentityRestoreAdministratorRepository;
import com.ixayda.iam.repository.IdentityRestoreReleaseRepository;
import com.ixayda.iam.repository.IdentityRestoreRepository;

import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;

/** Offline release admits a newly verified administrator while keeping all other restored trust disabled. */
@Service
@Lazy
public class IdentityRestoreReleases {

	private final IdentityRestoreRepository restores;
	private final IdentityRestoreReleaseRepository repository;
	private final IdentityRestoreAdministratorRepository candidates;
	private final IdentityAdministratorRepository administrators;
	private final IdentityUsers users;
	private final IdentityAuthentications authentications;
	private final IdentityTotps totps;
	private final TotpAuthenticationLimits limits;
	private final IdentitySigningKeys keys;
	private final IdentityAuthorizations authorizations;
	private final SecurityAudits audits;
	private final TransactionTemplate transaction;

	IdentityRestoreReleases(IdentityRestoreRepository restores, IdentityRestoreReleaseRepository repository,
			IdentityRestoreAdministratorRepository candidates, IdentityAdministratorRepository administrators,
			IdentityUsers users, IdentityAuthentications authentications, IdentityTotps totps, TotpAuthenticationLimits limits,
			IdentitySigningKeys keys, IdentityAuthorizations authorizations, SecurityAudits audits, PlatformTransactionManager manager) {
		this.restores = restores; this.repository = repository; this.candidates = candidates; this.administrators = administrators;
		this.users = users; this.authentications = authentications; this.totps = totps; this.limits = limits;
		this.keys = keys; this.authorizations = authorizations; this.audits = audits;
		this.transaction = new TransactionTemplate(manager); this.transaction.setIsolationLevel(TransactionDefinition.ISOLATION_READ_COMMITTED);
	}

	/** Terminal caller verifies current personnel/configuration and coordinated RP containment outside the restored database. */
	public Optional<IdentityRestoreRelease> release(String database, UUID restoreId, UUID userId, UUID signingKeyId,
			String password, String code, SecurityAuditContext audit) {
		validate(restoreId, userId, signingKeyId, audit);
		this.authorizations.requireConfigured();
		return this.transaction.execute(tx -> {
			this.restores.requireOfflineOwner(database); this.restores.lockForQuarantine();
			var restore = this.restores.current().filter(row -> row.id().equals(restoreId)).orElseThrow(() -> new IllegalStateException("Confirmed restore is not current"));
			if (this.restores.isAvailable() || this.repository.find(restoreId).isPresent() || !this.administrators.lockLifecycle().restoreClosed()) {
				throw new IllegalStateException("Restore is not quarantined");
			}
			var candidate = this.candidates.find(restoreId).filter(row -> row.userId().equals(userId) && row.completedAt() != null)
					.orElseThrow(() -> new IllegalStateException("A newly verified restore administrator is required"));
			var key = this.keys.lockForIssuance().key();
			if (!key.id().equals(signingKeyId) || key.createdAt().isBefore(restore.quarantinedAt())) {
				throw new IllegalStateException("A confirmed new signing identity is required");
			}
			this.restores.verifyReleaseConditions(userId, candidate.factorId(), signingKeyId);
			var authentication = new TotpAuthenticationContext(audit.source(), InetAddress.getLoopbackAddress(), audit.correlationId());
			var attempt = this.limits.lock(userId, authentication);
			if (!attempt.allowed()) { this.audits.recordFailure(Action.RESTORE_RELEASE_THROTTLED, userId, audit); return Optional.empty(); }
			var username = this.users.findById(userId).orElseThrow().username();
			var passwordResult = this.authentications.authenticateInTransaction(username, password,
					new PasswordAuthenticationContext(audit.source(), authentication.clientAddress(), audit.correlationId()));
			if (passwordResult.isEmpty() || !passwordResult.orElseThrow().userId().equals(userId)) {
				this.limits.failed(attempt); this.audits.recordFailure(Action.RESTORE_RELEASE_REJECTED, userId, audit); return Optional.empty();
			}
			var factor = this.totps.verifyInTransaction(userId, code, authentication);
			if (factor.isEmpty() || !factor.orElseThrow().factorId().equals(candidate.factorId())) {
				this.audits.recordFailure(Action.RESTORE_RELEASE_REJECTED, userId, audit); return Optional.empty();
			}
			var release = this.repository.record(restoreId, userId, candidate.factorId(), signingKeyId);
			if (!this.restores.isAvailable()) { throw new IllegalStateException("Restore release is incomplete"); }
			this.audits.recordTargetSuccess(Action.DATABASE_RESTORE_RELEASED, userId,
					new SecurityAuditTarget(SecurityAuditTarget.Type.DATABASE_RESTORE, restoreId), audit);
			return Optional.of(release);
		});
	}

	private static void validate(UUID restoreId, UUID userId, UUID signingKeyId, SecurityAuditContext audit) {
		if (restoreId == null || userId == null || signingKeyId == null || audit == null
				|| !audit.actor().matches("deployment:[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}")
				|| !audit.source().matches("deployment:restore-release:[a-zA-Z0-9][a-zA-Z0-9._-]{0,31}")) {
			throw new IllegalArgumentException("Confirmed restore, administrator, signing key and deployment authorization are required");
		}
		if (TransactionSynchronizationManager.isActualTransactionActive()) { throw new IllegalStateException("Restore release requires an independent transaction"); }
	}
}
