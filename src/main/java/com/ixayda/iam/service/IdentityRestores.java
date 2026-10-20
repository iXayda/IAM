package com.ixayda.iam.service;

import java.util.UUID;

import com.ixayda.iam.credential.ClientSecrets;
import com.ixayda.iam.model.IdentityRestore;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.SecurityAuditEvent.Action;
import com.ixayda.iam.model.SecurityAuditTarget;
import com.ixayda.iam.repository.IdentityRestoreRepository;

import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;

/** Offline containment for an untrusted historical security state. No restored identity is automatically trusted. */
@Service
public class IdentityRestores {

	private final IdentityRestoreRepository repository;
	private final ClientSecrets secrets;
	private final SecurityAudits audits;
	private final TransactionTemplate transaction;

	IdentityRestores(IdentityRestoreRepository repository, ClientSecrets secrets, SecurityAudits audits, PlatformTransactionManager manager) {
		this.repository = repository; this.secrets = secrets; this.audits = audits;
		this.transaction = new TransactionTemplate(manager);
		this.transaction.setIsolationLevel(TransactionDefinition.ISOLATION_READ_COMMITTED);
	}

	public String databaseName() { return this.repository.databaseName(); }

	/** Called before Web admission and by readiness; absent or inconsistent state fails closed. */
	public void requireAvailable() {
		if (!this.repository.isAvailable()) { throw new IllegalStateException("Restored database remains quarantined"); }
	}

	/** Caller stops the service, verifies the archive and authorizes the destructive containment in an offline terminal. */
	public IdentityRestore quarantine(String expectedDatabase, String archiveSha256, SecurityAuditContext audit) {
		if (expectedDatabase == null || archiveSha256 == null || !archiveSha256.matches("[0-9a-f]{64}") || audit == null
				|| !audit.actor().startsWith("deployment:") || !audit.source().startsWith("deployment:restore:")) {
			throw new IllegalArgumentException("Confirmed database, archive checksum and deployment attribution are required");
		}
		if (TransactionSynchronizationManager.isActualTransactionActive()) { throw new IllegalStateException("Restore quarantine requires an independent transaction"); }
		return this.transaction.execute(tx -> {
			this.repository.requireOfflineOwner(expectedDatabase);
			this.repository.lockForQuarantine();
			var current = this.repository.current();
			if (current.isPresent()) {
				if (!current.orElseThrow().archiveSha256().equals(archiveSha256)) { throw new IllegalStateException("A different restore is already quarantined"); }
				this.repository.verifyQuarantine();
				return current.orElseThrow();
			}
			var restore = this.repository.recordSnapshot(UUID.randomUUID(), archiveSha256);
			this.repository.invalidateCredentialsAndSessions();
			this.repository.disableSubjectsAndCatalog();
			for (String clientId : this.repository.clientIds()) {
				// The replacement has no recipient. A later authorized rotation must deliver a different secret.
				this.repository.eraseClientAccess(clientId, this.secrets.hash(this.secrets.generate()));
			}
			this.repository.compromiseHistoricalKeys();
			this.repository.activateQuarantine(restore.id());
			this.repository.verifyQuarantine();
			this.audits.recordTargetSuccess(Action.DATABASE_RESTORE_QUARANTINED,
					new SecurityAuditTarget(SecurityAuditTarget.Type.DATABASE_RESTORE, restore.id()), audit);
			return restore;
		});
	}
}
