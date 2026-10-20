package com.ixayda.iam.service;

import java.util.List;
import java.util.UUID;
import java.util.function.Function;

import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.SecurityAuditEvent.Action;
import com.ixayda.iam.model.SecurityAuditTarget;
import com.ixayda.iam.repository.IdentityAuthorizationBindingRepository;
import com.ixayda.iam.repository.IdentityAuthorizationBindingRepository.RevocationCandidate;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.util.Assert;

/** Trusted lifecycle primitive; the authorized caller holds subject/catalog locks before native state. */
@Service
@Transactional(propagation = Propagation.MANDATORY)
public class IdentityAuthorizationRevocations {

	private final IdentityAuthorizationBindingRepository repository;
	private final IdentityAuthorizationBindings bindings;
	private final IdentityAuthorizations authorizations;
	private final IdentityRefreshTokens refresh;
	private final SecurityAudits audits;

	IdentityAuthorizationRevocations(IdentityAuthorizationBindingRepository repository, IdentityAuthorizationBindings bindings,
			IdentityAuthorizations authorizations, IdentityRefreshTokens refresh, SecurityAudits audits) {
		this.repository = repository; this.bindings = bindings; this.authorizations = authorizations; this.refresh = refresh; this.audits = audits;
	}

	/** No earlier locks are acquired here; single-grant ownership must be established by the calling workflow. */
	public boolean revoke(UUID id, SecurityAuditContext audit) {
		validate(id, audit);
		return revokeLocked(id, audit);
	}

	public int revokeForUser(UUID userId, SecurityAuditContext audit) {
		validate(userId, audit);
		return revokeAll(after -> this.repository.revocationPageForUser(userId, after), audit);
	}

	public int revokeForClient(UUID clientId, SecurityAuditContext audit) {
		validate(clientId, audit);
		return revokeAll(after -> this.repository.revocationPageForClient(clientId, after), audit);
	}

	/** Selection follows original resource ownership even after a client changes its current resource. */
	public int revokeForResource(UUID resourceId, SecurityAuditContext audit) {
		validate(resourceId, audit);
		return revokeAll(after -> this.repository.revocationPageForResource(resourceId, after), audit);
	}

	/** Current assignees are included even when an inactive role was absent from their original effective projection. */
	public int revokeForRole(UUID roleId, SecurityAuditContext audit) {
		validate(roleId, audit);
		return revokeAll(after -> this.repository.revocationPageForRole(roleId, after), audit);
	}

	/** Assignment epochs change for the entire pair, including grants which did not previously carry the changed role. */
	public int revokeForUserResource(UUID userId, UUID resourceId, SecurityAuditContext audit) {
		validate(userId, audit); Assert.notNull(resourceId, "Resource id is required");
		return revokeAll(after -> this.repository.revocationPageForUserResource(userId, resourceId, after), audit);
	}

	private int revokeAll(Function<UUID, List<RevocationCandidate>> selectPage, SecurityAuditContext audit) {
		int changed = 0;
		UUID after = null;
		while (true) {
			var page = selectPage.apply(after);
			if (page.isEmpty()) { return changed; }
			for (var candidate : page) {
				if (!this.authorizations.isAuthenticatedRevocation(candidate) && revokeLocked(candidate.id(), audit)) { changed = Math.addExact(changed, 1); }
			}
			after = page.getLast().id();
		}
	}

	private boolean revokeLocked(UUID id, SecurityAuditContext audit) {
		var locked = this.authorizations.lockForUse(id);
		if (locked.isEmpty()) {
			if (this.repository.findById(id).isPresent()) { throw new IllegalStateException("Bound authorization is missing"); }
			return false;
		}
		var original = this.bindings.findByAuthorization(locked.orElseThrow().authorization())
				.orElseThrow(() -> new IllegalStateException("Original authorization bounds are missing"));
		var saved = this.refresh.revoke(locked.orElseThrow());
		if (IdentityAuthorizations.isRevoked(locked.orElseThrow().authorization())) { return false; }
		if (!IdentityAuthorizations.isRevoked(saved.authorization()) || this.bindings.findByAuthorization(saved.authorization()).filter(original::equals).isEmpty()) {
			throw new IllegalStateException("Authorization revocation was not stored");
		}
		this.audits.recordTargetSuccess(Action.AUTHORIZATION_REVOKED, original.session().access().userId(),
				new SecurityAuditTarget(SecurityAuditTarget.Type.AUTHORIZATION, id), audit);
		return true;
	}

	private void validate(UUID id, SecurityAuditContext audit) {
		Assert.notNull(id, "Lifecycle target is required"); Assert.notNull(audit, "Trusted audit context is required");
		if (!TransactionSynchronizationManager.isActualTransactionActive() || TransactionSynchronizationManager.isCurrentTransactionReadOnly()
				|| !this.repository.isWritableReadCommittedTransaction()) {
			throw new IllegalStateException("Authorization revocation requires a writable read committed transaction");
		}
	}

}
