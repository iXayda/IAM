package com.ixayda.iam.service;

import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import com.ixayda.iam.credential.SigningKeySecrets;
import com.ixayda.iam.model.IdentitySigningKey;
import com.ixayda.iam.model.IdentitySigningKeyMetadata;
import com.ixayda.iam.model.IdentitySigningMaterial;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.SecurityAuditEvent.Action;
import com.ixayda.iam.model.SecurityAuditTarget;
import com.ixayda.iam.repository.IdentitySigningKeyRepository;
import com.ixayda.iam.repository.IdentitySigningKeyRepository.StoredKey;

import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.util.Assert;

@Service
@Lazy
public class IdentitySigningKeys {

	private final IdentitySigningKeyRepository repository;
	private final SigningKeySecrets secrets;
	private final SecurityAudits audits;
	private final TransactionTemplate transaction;

	IdentitySigningKeys(IdentitySigningKeyRepository repository, SigningKeySecrets secrets, SecurityAudits audits, PlatformTransactionManager manager) {
		this.repository = repository;
		this.secrets = secrets;
		this.audits = audits;
		this.transaction = new TransactionTemplate(manager);
	}

	/** Web startup calls this before admitting traffic. Existing state is validated, never replaced. */
	public Optional<IdentitySigningKey> initialize() {
		return initialize("system:startup");
	}

	/** Offline installation uses maintenance credentials before the restricted Web identity starts. */
	public IdentitySigningKey initializeForInstallation() {
		this.secrets.requireConfigured();
		return initialize("system:installation").orElseThrow(() -> new IllegalStateException("Signing protection is required"));
	}

	private Optional<IdentitySigningKey> initialize(String actor) {
		requireIndependentTransaction();
		return this.transaction.execute(status -> {
			var lifecycle = this.repository.lockLifecycle();
			var stored = this.repository.findStoredKey();
			if (lifecycle.initialKeyId() == null) {
				if (this.repository.hasStoredKeys()) { throw new IllegalStateException("Signing initialization state is inconsistent"); }
				if (!this.secrets.isConfigured()) { return Optional.empty(); }
				UUID id = UUID.randomUUID();
				var generated = this.secrets.generate();
				this.repository.insert(id, generated.getPublic().getEncoded(), this.secrets.encrypt(id, generated.getPrivate()), this.secrets.protectionKeyId());
				this.repository.completeInitialization(id);
				// The first key and its initialization operation share the same correlation UUID.
				this.audits.recordSuccess(Action.SIGNING_KEY_INITIALIZED, null,
						new SecurityAuditContext(actor, "deployment:signing", id));
				stored = this.repository.findStoredKey();
				lifecycle = this.repository.lockLifecycle();
			}
			var existing = stored.orElseThrow(() -> new IllegalStateException("Initialized signing key is missing"));
			requireConsistentState(lifecycle, existing);
			return Optional.of(restore(existing).key());
		});
	}

	/** Public reads work independently of private-key decryption. No private columns are selected. */
	public Optional<IdentitySigningKey> findPublicKey() {
		return this.repository.findPublicKey().map(stored -> new IdentitySigningKey(stored.id(), stored.algorithm(),
				this.secrets.readPublicKey(stored.publicKey()), stored.createdAt()));
	}

	public List<IdentitySigningKey> verificationKeys() {
		return this.repository.findVerificationKeys().stream().map(stored -> new IdentitySigningKey(stored.id(), stored.algorithm(),
				this.secrets.readPublicKey(stored.publicKey()), stored.createdAt())).toList();
	}

	public List<IdentitySigningKeyMetadata> metadata() { return this.repository.metadata(); }

	/** Deployment-only operation; OS access and maintenance database credentials authorize the trusted caller. */
	public IdentitySigningKey rotate(UUID expectedCurrent, SecurityAuditContext audit) {
		Assert.notNull(expectedCurrent, "Current signing key id is required");
		Assert.notNull(audit, "Trusted audit context is required");
		requireIndependentTransaction();
		this.secrets.requireConfigured();
		return this.transaction.execute(tx -> {
			var lifecycle = this.repository.lockLifecycle();
			var material = loadLockedMaterial(lifecycle);
			if (!material.key().id().equals(expectedCurrent)) { throw new IllegalStateException("Current signing key changed"); }
			this.repository.retire(expectedCurrent);
			UUID next = UUID.randomUUID(); var generated = this.secrets.generate();
			this.repository.insert(next, generated.getPublic().getEncoded(), this.secrets.encrypt(next, generated.getPrivate()), this.secrets.protectionKeyId());
			this.repository.activate(expectedCurrent, next, lifecycle.revision());
			var current = loadLockedMaterial(this.repository.lockLifecycle()).key();
			this.audits.recordTargetSuccess(Action.SIGNING_KEY_RETIRED, null, new SecurityAuditTarget(SecurityAuditTarget.Type.SIGNING_KEY, expectedCurrent), audit);
			this.audits.recordTargetSuccess(Action.SIGNING_KEY_ROTATED, null, new SecurityAuditTarget(SecurityAuditTarget.Type.SIGNING_KEY, next), audit);
			return current;
		});
	}

	/** Explicit replacement after containment; never decrypts or reactivates a compromised key. */
	public IdentitySigningKey recover(UUID expectedCompromised, SecurityAuditContext audit) {
		Assert.notNull(expectedCompromised, "Compromised signing key id is required"); Assert.notNull(audit, "Trusted audit context is required");
		requireIndependentTransaction(); this.secrets.requireConfigured();
		return this.transaction.execute(tx -> {
			var lifecycle = this.repository.lockLifecycle();
			if (lifecycle.initialKeyId() == null || lifecycle.activeKeyId() != null || !expectedCompromised.equals(lifecycle.suspensionKeyId())
					|| this.repository.metadata().stream().noneMatch(key -> key.id().equals(expectedCompromised) && key.status() == IdentitySigningKeyMetadata.Status.COMPROMISED)) {
				throw new IllegalStateException("Signing key recovery does not match a suspended lifecycle");
			}
			UUID next = UUID.randomUUID(); var generated = this.secrets.generate();
			this.repository.insert(next, generated.getPublic().getEncoded(), this.secrets.encrypt(next, generated.getPrivate()), this.secrets.protectionKeyId());
			this.repository.recover(expectedCompromised, next, lifecycle);
			var current = loadLockedMaterial(this.repository.lockLifecycle()).key();
			this.audits.recordTargetSuccess(Action.SIGNING_KEY_REPLACED, null, new SecurityAuditTarget(SecurityAuditTarget.Type.SIGNING_KEY, expectedCompromised), audit);
			this.audits.recordTargetSuccess(Action.SIGNING_KEY_RECOVERED, null, new SecurityAuditTarget(SecurityAuditTarget.Type.SIGNING_KEY, next), audit);
			return current;
		});
	}

	/** Only trusted signing code receives private material, after the read transaction has committed. */
	public IdentitySigningMaterial signingMaterial() {
		requireIndependentTransaction();
		this.secrets.requireConfigured();
		return this.transaction.execute(status -> loadLockedMaterial(this.repository.lockLifecycle()));
	}

	/** Acquire first, before user/resource/role/client/session/authorization locks; retain through issuance and audit commit. */
	public IdentitySigningMaterial lockForIssuance() {
		if (!TransactionSynchronizationManager.isActualTransactionActive() || TransactionSynchronizationManager.isCurrentTransactionReadOnly()) {
			throw new IllegalStateException("Token signing requires an active write transaction");
		}
		this.secrets.requireConfigured();
		return loadLockedMaterial(this.repository.lockForIssuance());
	}

	/** Acquire first for online use; validation selects public columns and never decrypts signing material. */
	public Optional<IdentitySigningKey> lockForValidation(UUID id) {
		if (id == null) { throw new IllegalArgumentException("Signing key id is required"); }
		if (!TransactionSynchronizationManager.isActualTransactionActive() || TransactionSynchronizationManager.isCurrentTransactionReadOnly()) {
			throw new IllegalStateException("Online validation requires an active write transaction");
		}
		var lifecycle = this.repository.lockForIssuance();
		var key = findPublicKey();
		if (lifecycle.initialKeyId() == null) {
			if (this.repository.hasStoredKeys()) { throw new IllegalStateException("Signing initialization state is inconsistent"); }
			return Optional.empty();
		}
		if (lifecycle.activeKeyId() == null) {
			if (key.isPresent() || lifecycle.suspensionKeyId() == null || this.repository.metadata().stream()
					.noneMatch(value -> value.id().equals(lifecycle.suspensionKeyId()) && value.status() == IdentitySigningKeyMetadata.Status.COMPROMISED)) {
				throw new IllegalStateException("Signing suspension state is inconsistent");
			}
		}
		else {
			var current = key.orElseThrow(() -> new IllegalStateException("Initialized signing key is missing"));
			if (!current.id().equals(lifecycle.activeKeyId()) || !current.createdAt().equals(lifecycle.activeKeyCreatedAt())) {
				throw new IllegalStateException("Signing initialization state is inconsistent");
			}
		}
		return this.repository.findVerificationKey(id).map(stored -> new IdentitySigningKey(stored.id(), stored.algorithm(),
				this.secrets.readPublicKey(stored.publicKey()), stored.createdAt()));
	}

	private IdentitySigningMaterial loadLockedMaterial(IdentitySigningKeyRepository.Lifecycle lifecycle) {
		var stored = this.repository.findStoredKey().orElseThrow(() -> new IllegalStateException("Signing key is not initialized"));
		requireConsistentState(lifecycle, stored);
		return restore(stored);
	}

	private IdentitySigningMaterial restore(StoredKey stored) {
		var restored = this.secrets.restore(stored.id(), stored.algorithm(), stored.publicKey(), stored.protectionKeyId(), stored.encryptedPrivateKey());
		return new IdentitySigningMaterial(new IdentitySigningKey(stored.id(), stored.algorithm(),
				(RSAPublicKey) restored.getPublic(), stored.createdAt()), restored.getPrivate());
	}

	private static void requireConsistentState(IdentitySigningKeyRepository.Lifecycle lifecycle, StoredKey stored) {
		if (lifecycle.initialKeyId() == null || !stored.id().equals(lifecycle.activeKeyId()) || !stored.createdAt().equals(lifecycle.activeKeyCreatedAt())
				|| lifecycle.revision() < 1 || lifecycle.initialKeyId().equals(stored.id()) && !stored.createdAt().equals(lifecycle.initializedAt())) {
			throw new IllegalStateException("Signing initialization state is inconsistent");
		}
	}

	private static void requireIndependentTransaction() {
		if (TransactionSynchronizationManager.isActualTransactionActive()) {
			throw new IllegalStateException("Signing key access requires an independent transaction");
		}
	}

}
