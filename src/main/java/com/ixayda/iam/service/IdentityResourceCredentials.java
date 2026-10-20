package com.ixayda.iam.service;

import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.UUID;

import com.ixayda.iam.credential.ClientSecrets;
import com.ixayda.iam.model.IdentityResource;
import com.ixayda.iam.model.IdentityResourceCredential;
import com.ixayda.iam.model.IdentityResourceSecret;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.SecurityAuditEvent.Action;
import com.ixayda.iam.model.SecurityAuditTarget;
import com.ixayda.iam.repository.IdentityResourceCredentialRepository;

import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.util.Assert;

/** Trusted lifecycle and authentication for one-resource validation identities, separate from application clients. */
@Service
public class IdentityResourceCredentials {

	private final IdentityResourceCredentialRepository repository;
	private final IdentityResources resources;
	private final ClientSecrets secrets;
	private final SecurityAudits audits;

	IdentityResourceCredentials(IdentityResourceCredentialRepository repository, IdentityResources resources, ClientSecrets secrets, SecurityAudits audits) {
		this.repository = repository;
		this.resources = resources;
		this.secrets = secrets;
		this.audits = audits;
	}

	public Optional<IdentityResourceCredential> findByResourceId(UUID id) {
		Assert.notNull(id, "Resource id is required");
		return this.repository.findByResourceId(id).map(IdentityResourceCredentialRepository.StoredCredential::credential);
	}

	/** Expected version zero creates; later versions replace the secret and explicitly enable the new credential. */
	@Transactional
	public IdentityResourceSecret rotateSecret(UUID id, long expectedVersion, SecurityAuditContext audit) {
		Assert.notNull(audit, "Audit context is required");
		var resource = lockResource(id, expectedVersion);
		if (resource.status() != IdentityResource.Status.ACTIVE) { throw new ResourceCredentialNotAllowedException(); }
		var previous = this.repository.findByResourceId(id);
		requireVersion(previous.orElse(null), expectedVersion);
		String secret = this.secrets.generate();
		String hash = this.secrets.hash(secret);
		var credential = previous.isEmpty() ? this.repository.create(id, hash)
				: this.repository.update(previous.orElseThrow(), hash, IdentityResourceCredential.Status.ACTIVE);
		record(previous.isEmpty() ? Action.RESOURCE_CREDENTIAL_ISSUED : Action.RESOURCE_CREDENTIAL_ROTATED, id, audit);
		return new IdentityResourceSecret(credential, secret);
	}

	@Transactional
	public IdentityResourceCredential disable(UUID id, long expectedVersion, SecurityAuditContext audit) {
		Assert.notNull(audit, "Audit context is required");
		if (expectedVersion < 1) { throw new IllegalArgumentException("Credential version must be positive"); }
		lockResource(id, expectedVersion);
		var previous = this.repository.findByResourceId(id).orElseThrow(() -> new NoSuchElementException("Resource credential not found"));
		requireVersion(previous, expectedVersion);
		if (previous.credential().status() == IdentityResourceCredential.Status.DISABLED) { return previous.credential(); }
		var changed = this.repository.update(previous, previous.secretHash(), IdentityResourceCredential.Status.DISABLED);
		record(Action.RESOURCE_CREDENTIAL_DISABLED, id, audit);
		return changed;
	}

	/** An initial authentication snapshot is never enough to publish a validation response. */
	public Optional<Snapshot> authenticate(String resourceId, String secret) {
		UUID id = canonicalId(resourceId);
		if (id == null) { return Optional.empty(); }
		return active(id).filter(snapshot -> this.secrets.verifier().matches(secret, snapshot.verifiedHash()));
	}

	/** Signing, user and catalog locks precede this recheck; retain the parent lock until response state commits. */
	@Transactional(propagation = Propagation.MANDATORY)
	public Optional<Snapshot> lockForValidation(Snapshot expected) {
		Assert.notNull(expected, "Resource credential snapshot is required");
		requireTransaction();
		if (this.resources.lockForValidation(expected.resource().id()).isEmpty()) { return Optional.empty(); }
		return active(expected.resource().id()).filter(expected::equals);
	}

	private Optional<Snapshot> active(UUID id) {
		return this.repository.findActiveByResourceId(id).map(stored -> {
			if (!this.secrets.isSupportedHash(stored.stored().secretHash())) { throw new IllegalStateException("Resource credential hash is invalid"); }
			return new Snapshot(stored.resource(), stored.stored().credential(), stored.stored().secretHash());
		});
	}

	private IdentityResource lockResource(UUID id, long version) {
		Assert.notNull(id, "Resource id is required");
		if (version < 0) { throw new IllegalArgumentException("Credential version must not be negative"); }
		requireTransaction();
		return this.resources.lockById(id).orElseThrow(() -> new NoSuchElementException("Resource not found"));
	}

	private void requireTransaction() {
		if (!TransactionSynchronizationManager.isActualTransactionActive() || TransactionSynchronizationManager.isCurrentTransactionReadOnly()
				|| !this.repository.isWritableReadCommittedTransaction()) { throw new IllegalStateException("Resource credential use requires a writable read committed transaction"); }
	}

	private static void requireVersion(IdentityResourceCredentialRepository.StoredCredential previous, long expected) {
		if ((previous == null ? 0 : previous.credential().version()) != expected) { throw new OptimisticLockingFailureException("Resource credential version is stale"); }
	}

	private void record(Action action, UUID id, SecurityAuditContext audit) { this.audits.recordTargetSuccess(action, new SecurityAuditTarget(SecurityAuditTarget.Type.RESOURCE, id), audit); }

	private static UUID canonicalId(String value) {
		if (value == null || value.length() != 36) { return null; }
		try { var id = UUID.fromString(value); return id.toString().equals(value) ? id : null; }
		catch (IllegalArgumentException ex) { return null; }
	}

	public record Snapshot(IdentityResource resource, IdentityResourceCredential credential, String verifiedHash) {
		@Override
		public String toString() { return "ResourceCredentialSnapshot[REDACTED]"; }
	}

	public static final class ResourceCredentialNotAllowedException extends IllegalStateException {
		ResourceCredentialNotAllowedException() { super("A new resource credential requires an active resource"); }
	}

}
