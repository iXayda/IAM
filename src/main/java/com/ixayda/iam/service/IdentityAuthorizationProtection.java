package com.ixayda.iam.service;

import com.ixayda.iam.credential.AuthorizationSecrets;
import com.ixayda.iam.repository.IdentityAuthorizationProtectionRepository;

import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;

/** Pins both encryption and lookup keys; online startup never chooses or replaces a deployment key. */
@Service
public class IdentityAuthorizationProtection {

	private final IdentityAuthorizationProtectionRepository repository;
	private final AuthorizationSecrets secrets;
	private final TransactionTemplate transaction;

	IdentityAuthorizationProtection(IdentityAuthorizationProtectionRepository repository, AuthorizationSecrets secrets, PlatformTransactionManager manager) {
		this.repository = repository;
		this.secrets = secrets; this.transaction = new TransactionTemplate(manager);
	}

	public void requireCurrent() {
		String expected = this.repository.keyId().orElseThrow(() -> new IllegalStateException("Authorization protection must be initialized offline"));
		if (!this.secrets.keyId().equals(expected)) { throw new IllegalStateException("Authorization protection does not match this deployment"); }
	}

	/** First registration precedes protocol use; subsequent calls only verify the installation identity. */
	public String initializeForInstallation() {
		if (TransactionSynchronizationManager.isActualTransactionActive()) { throw new IllegalStateException("Authorization protection installation requires an independent transaction"); }
		String key = this.secrets.keyId();
		return this.transaction.execute(status -> {
			this.repository.lockForInstallation();
			if (this.repository.keyId().isPresent()) { requireCurrent(); return key; }
			this.repository.initialize(key); requireCurrent(); return key;
		});
	}
}
