package com.ixayda.iam.service;

import java.security.interfaces.RSAPublicKey;
import java.util.Optional;
import java.util.UUID;

import com.ixayda.iam.credential.SigningKeySecrets;
import com.ixayda.iam.model.IdentitySigningKey;
import com.ixayda.iam.model.IdentitySigningMaterial;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.SecurityAuditEvent.Action;
import com.ixayda.iam.repository.IdentitySigningKeyRepository;
import com.ixayda.iam.repository.IdentitySigningKeyRepository.StoredKey;

import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;

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
		requireIndependentTransaction();
		return this.transaction.execute(status -> {
			var lifecycle = this.repository.lockLifecycle();
			var stored = this.repository.findStoredKey();
			if (lifecycle.initialKeyId() == null) {
				if (stored.isPresent()) { throw new IllegalStateException("Signing initialization state is inconsistent"); }
				if (!this.secrets.isConfigured()) { return Optional.empty(); }
				UUID id = UUID.randomUUID();
				var generated = this.secrets.generate();
				this.repository.insert(id, generated.getPublic().getEncoded(), this.secrets.encrypt(id, generated.getPrivate()), this.secrets.protectionKeyId());
				this.repository.completeInitialization(id);
				// The first key and its initialization operation share the same correlation UUID.
				this.audits.recordSuccess(Action.SIGNING_KEY_INITIALIZED, null,
						new SecurityAuditContext("system:startup", "deployment:signing", id));
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

	/** Only trusted signing code receives private material, after the read transaction has committed. */
	public IdentitySigningMaterial signingMaterial() {
		requireIndependentTransaction();
		this.secrets.requireConfigured();
		return this.transaction.execute(status -> {
			var lifecycle = this.repository.lockLifecycle();
			var stored = this.repository.findStoredKey().orElseThrow(() -> new IllegalStateException("Signing key is not initialized"));
			requireConsistentState(lifecycle, stored);
			return restore(stored);
		});
	}

	private IdentitySigningMaterial restore(StoredKey stored) {
		var restored = this.secrets.restore(stored.id(), stored.algorithm(), stored.publicKey(), stored.protectionKeyId(), stored.encryptedPrivateKey());
		return new IdentitySigningMaterial(new IdentitySigningKey(stored.id(), stored.algorithm(),
				(RSAPublicKey) restored.getPublic(), stored.createdAt()), restored.getPrivate());
	}

	private static void requireConsistentState(IdentitySigningKeyRepository.Lifecycle lifecycle, StoredKey stored) {
		if (!stored.id().equals(lifecycle.initialKeyId()) || !stored.createdAt().equals(lifecycle.initializedAt())) {
			throw new IllegalStateException("Signing initialization state is inconsistent");
		}
	}

	private static void requireIndependentTransaction() {
		if (TransactionSynchronizationManager.isActualTransactionActive()) {
			throw new IllegalStateException("Signing key access requires an independent transaction");
		}
	}

}
