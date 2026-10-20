package com.ixayda.iam.service;

import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import com.ixayda.iam.credential.AuthorizationSecrets;
import com.ixayda.iam.repository.IdentityAuthorizationRepository;
import com.ixayda.iam.repository.IdentityAuthorizationRepository.StoredAuthorization;

import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2DeviceCode;
import org.springframework.security.oauth2.core.OAuth2UserCode;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.util.Assert;

/** Trusted protocol persistence; the protocol workflow owns authorization, deadlines and mandatory audit. */
@Service
public class IdentityAuthorizations {

	private final IdentityAuthorizationRepository repository;
	private final AuthorizationSecrets secrets;

	IdentityAuthorizations(IdentityAuthorizationRepository repository, AuthorizationSecrets secrets) { this.repository = repository; this.secrets = secrets; }

	public Optional<Snapshot> findById(UUID id) {
		Assert.notNull(id, "Authorization id is required");
		this.secrets.requireConfigured();
		return this.repository.findById(id).map(IdentityAuthorizations::snapshot);
	}

	public Optional<Snapshot> findByToken(String token, String type) {
		if (token == null || token.isEmpty() || token.length() > 16_384) { return Optional.empty(); }
		if (type != null && !Set.of("state", "code", "access_token", "id_token", "refresh_token").contains(type)) { return Optional.empty(); }
		String digest;
		try { digest = this.secrets.digest(token); }
		catch (IllegalArgumentException ex) { return Optional.empty(); }
		return this.repository.findByDigest(digest, type).map(IdentityAuthorizations::snapshot);
	}

	/** The trusted workflow acquires key, subject, catalog and source-session locks before this native-state lock. */
	@Transactional(propagation = Propagation.MANDATORY)
	public Optional<Snapshot> lockForUse(UUID id) {
		Assert.notNull(id, "Authorization id is required"); this.secrets.requireConfigured();
		if (!TransactionSynchronizationManager.isActualTransactionActive() || TransactionSynchronizationManager.isCurrentTransactionReadOnly()
				|| !this.repository.isWritableReadCommittedTransaction()) { throw new IllegalStateException("Protocol use requires a writable read committed transaction"); }
		return this.repository.lockById(id).map(IdentityAuthorizations::snapshot);
	}

	@Transactional
	public Snapshot save(OAuth2Authorization authorization, long expectedVersion) {
		Assert.notNull(authorization, "Authorization is required");
		this.secrets.requireConfigured();
		UUID id = canonicalId(authorization.getId());
		canonicalId(authorization.getPrincipalName()); canonicalId(authorization.getRegisteredClientId());
		if (expectedVersion < 0 || !AuthorizationGrantType.AUTHORIZATION_CODE.equals(authorization.getAuthorizationGrantType())
				|| authorization.getToken(OAuth2UserCode.class) != null || authorization.getToken(OAuth2DeviceCode.class) != null) { throw new IllegalArgumentException("Unsupported authorization record"); }
		var existing = this.repository.lockById(id);
		if (existing.map(StoredAuthorization::version).orElse(0L) != expectedVersion) { throw new OptimisticLockingFailureException("Authorization version is stale"); }
		if (existing.isPresent() && (!existing.orElseThrow().authorization().getPrincipalName().equals(authorization.getPrincipalName())
				|| !existing.orElseThrow().authorization().getRegisteredClientId().equals(authorization.getRegisteredClientId()))) { throw new IllegalArgumentException("Authorization subjects are immutable"); }
		return snapshot(this.repository.save(authorization, expectedVersion));
	}

	@Transactional
	public void remove(UUID id, long expectedVersion) {
		Assert.notNull(id, "Authorization id is required");
		this.secrets.requireConfigured();
		if (expectedVersion < 1) { throw new IllegalArgumentException("Authorization version must be positive"); }
		var existing = this.repository.lockById(id).orElseThrow(() -> new NoSuchElementException("Authorization not found"));
		if (existing.version() != expectedVersion) { throw new OptimisticLockingFailureException("Authorization version is stale"); }
		this.repository.remove(existing);
	}

	private static Snapshot snapshot(StoredAuthorization stored) { return new Snapshot(stored.authorization(), stored.version()); }

	public record Snapshot(OAuth2Authorization authorization, long version) {
		@Override
		public String toString() { return "AuthorizationSnapshot[version=" + version + ", REDACTED]"; }
	}

	private static UUID canonicalId(String value) {
		UUID id = UUID.fromString(value);
		if (!id.toString().equals(value)) { throw new IllegalArgumentException("A canonical UUID is required"); }
		return id;
	}

}
