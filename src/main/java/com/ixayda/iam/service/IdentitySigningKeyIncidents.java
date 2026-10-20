package com.ixayda.iam.service;

import java.util.UUID;

import com.ixayda.iam.model.IdentitySigningKeyMetadata.Status;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.SecurityAuditEvent.Action;
import com.ixayda.iam.model.SecurityAuditTarget;
import com.ixayda.iam.repository.IdentityAuthorizationBindingRepository;
import com.ixayda.iam.repository.IdentitySigningKeyRepository;

import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.util.Assert;

/** Maintenance-only containment; exclusive signing gate, sorted subjects, then sorted native grants. */
@Service
@Lazy
public class IdentitySigningKeyIncidents {

	private final IdentitySigningKeyRepository keys;
	private final IdentityAuthorizationBindingRepository bindings;
	private final IdentityUsers users;
	private final IdentityAuthorizations authorizations;
	private final IdentityAuthorizationRevocations revocations;
	private final SecurityAudits audits;
	private final TransactionTemplate transaction;

	IdentitySigningKeyIncidents(IdentitySigningKeyRepository keys, IdentityAuthorizationBindingRepository bindings, IdentityUsers users,
			IdentityAuthorizations authorizations, IdentityAuthorizationRevocations revocations, SecurityAudits audits, PlatformTransactionManager manager) {
		this.keys = keys; this.bindings = bindings; this.users = users; this.authorizations = authorizations; this.revocations = revocations; this.audits = audits;
		this.transaction = new TransactionTemplate(manager); this.transaction.setIsolationLevel(TransactionDefinition.ISOLATION_READ_COMMITTED);
	}

	/** OS access, maintenance DB privileges and an organizational authorization record establish the caller's authority. */
	public int compromise(UUID id, SecurityAuditContext audit) {
		Assert.notNull(id, "Signing key id is required"); Assert.notNull(audit, "Trusted audit context is required");
		if (TransactionSynchronizationManager.isActualTransactionActive()) { throw new IllegalStateException("Signing key containment requires an independent transaction"); }
		return this.transaction.execute(tx -> {
			var lifecycle = this.keys.lockLifecycle();
			if (lifecycle.initialKeyId() == null) { throw new IllegalStateException("Signing key is not initialized"); }
			var metadata = this.keys.metadata();
			if (lifecycle.activeKeyId() != null) {
				if (metadata.stream().noneMatch(key -> key.id().equals(lifecycle.activeKeyId()) && key.status() == Status.ACTIVE && key.createdAt().equals(lifecycle.activeKeyCreatedAt()))) {
					throw new IllegalStateException("Signing lifecycle is inconsistent");
				}
			}
			else if (lifecycle.suspensionKeyId() == null || metadata.stream().anyMatch(key -> key.status() == Status.ACTIVE)
					|| metadata.stream().noneMatch(key -> key.id().equals(lifecycle.suspensionKeyId()) && key.status() == Status.COMPROMISED)) {
				throw new IllegalStateException("Signing lifecycle is inconsistent");
			}
			this.keys.compromise(id, lifecycle);
			// No issuer can add signing provenance while the exclusive lifecycle gate is held.
			for (UUID user : this.bindings.findAllUserIds()) { this.users.lockForStateChange(user).orElseThrow(() -> new IllegalStateException("Authorization subject is missing")); }
			int revoked = 0;
			for (UUID authorizationId : this.bindings.findAllIds()) {
				var current = this.authorizations.lockForUse(authorizationId).orElseThrow(() -> new IllegalStateException("Bound authorization is missing"));
				if (IdentityAuthorizationSigningHistory.mayHaveUsed(current.authorization(), id) && this.revocations.revoke(authorizationId, audit)) { revoked = Math.addExact(revoked, 1); }
			}
			this.audits.recordTargetSuccess(Action.SIGNING_KEY_COMPROMISED, null, new SecurityAuditTarget(SecurityAuditTarget.Type.SIGNING_KEY, id), audit);
			return revoked;
		});
	}
}
