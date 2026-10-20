package com.ixayda.iam.service;

import java.util.Optional;
import java.util.UUID;

import com.ixayda.iam.credential.ClientSecrets;
import com.ixayda.iam.model.IdentityClient;
import com.ixayda.iam.model.IdentityResource;
import com.ixayda.iam.repository.IdentityClientRepository;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.util.Assert;

/** Trusted protocol reads and revalidation; grant workflows own authorization and mandatory audit. */
@Service
public class IdentityProtocolClients {

	private final IdentityClientRepository repository;
	private final ClientSecrets secrets;

	IdentityProtocolClients(IdentityClientRepository repository, ClientSecrets secrets) { this.repository = repository; this.secrets = secrets; }

	public Optional<Snapshot> findActiveById(String value) {
		UUID id = canonicalId(value);
		if (id == null) { return Optional.empty(); }
		return this.repository.findActiveProtocolClient(id).map(stored -> {
			var client = stored.client();
			var registration = stored.registration();
			if (!this.secrets.isSupportedHash(registration.getClientSecret())
					|| !IdentityClients.normalize(client.configuration()).equals(client.configuration())
					|| !IdentityClients.buildRegistration(client.id(), client.configuration(), registration.getClientSecret(), client.createdAt()).equals(registration)) {
				throw new IllegalStateException("Protocol client configuration is invalid");
			}
			return new Snapshot(registration, client, stored.resource());
		});
	}

	/** Lock signing keys and subjects first, then bind this authentication snapshot in the issuance transaction. */
	public Optional<Snapshot> lockForIssuance(Snapshot expected) {
		Assert.notNull(expected, "Protocol client snapshot is required");
		if (!TransactionSynchronizationManager.isActualTransactionActive() || TransactionSynchronizationManager.isCurrentTransactionReadOnly()
				|| !this.repository.isWritableReadCommittedTransaction()) { throw new IllegalStateException("Protocol client use requires a writable read committed transaction"); }
		if (!this.repository.lockProtocolResource(expected.resource().id())) { return Optional.empty(); }
		// Detect a transfer before taking the client lock under a parent that is no longer current.
		if (findActiveById(expected.registration().getId()).filter(expected::equals).isEmpty()) { return Optional.empty(); }
		if (!this.repository.lockProtocolRoles(expected.resource().id(), expected.client().configuration().allowedRoleIds())) { return Optional.empty(); }
		if (!this.repository.lockProtocolClient(expected.client().id())) { return Optional.empty(); }
		return findActiveById(expected.registration().getId()).filter(expected::equals);
	}

	public PasswordEncoder secretVerifier() { return this.secrets.verifier(); }

	public record Snapshot(RegisteredClient registration, IdentityClient client, IdentityResource resource) {
		@Override
		public String toString() { return "ProtocolClientSnapshot[REDACTED]"; }
	}

	private static UUID canonicalId(String value) {
		if (value == null || value.length() != 36) { return null; }
		try { var id = UUID.fromString(value); return id.toString().equals(value) ? id : null; }
		catch (IllegalArgumentException ex) { return null; }
	}

}
