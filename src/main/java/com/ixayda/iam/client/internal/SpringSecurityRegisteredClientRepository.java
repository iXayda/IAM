package com.ixayda.iam.client.internal;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Objects;

import com.ixayda.iam.client.ClientId;
import com.ixayda.iam.client.ClientIdentifier;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

@Repository
@Transactional(readOnly = true)
class SpringSecurityRegisteredClientRepository implements RegisteredClientRepository {

	private final JdbcOAuthClientRepository repository;

	private final RegisteredClientMapper mapper;

	SpringSecurityRegisteredClientRepository(JdbcOAuthClientRepository repository, RegisteredClientMapper mapper) {
		this.repository = repository;
		this.mapper = mapper;
	}

	@Override
	@Transactional
	public void save(RegisteredClient registeredClient) {
		Objects.requireNonNull(registeredClient, "Registered client must not be null");
		ClientId clientId = parseClientId(registeredClient.getId());
		if (clientId == null) {
			throw unsupportedRegistration();
		}
		StoredOAuthClient stored = this.repository.findActiveById(clientId).orElseThrow(this::unsupportedRegistration);
		RegisteredClient current = this.mapper.toRegisteredClient(stored);
		String currentEncoding = current.getClientSecret();
		String replacementEncoding = registeredClient.getClientSecret();
		if (currentEncoding == null || replacementEncoding == null) {
			throw new IllegalArgumentException("Only confidential client secret encoding upgrades are supported");
		}
		Object fingerprintSetting = registeredClient.getClientSettings()
			.getSettings()
			.get(RegisteredClientMapper.SECRET_ENCODING_FINGERPRINT_SETTING);
		if (!(fingerprintSetting instanceof String expectedFingerprint)) {
			throw new IllegalArgumentException("Client secret encoding fingerprint is required for an upgrade");
		}
		String currentFingerprint = RegisteredClientMapper.secretEncodingFingerprint(currentEncoding);
		if (!MessageDigest.isEqual(expectedFingerprint.getBytes(StandardCharsets.US_ASCII),
				currentFingerprint.getBytes(StandardCharsets.US_ASCII))) {
			return;
		}

		RegisteredClient candidateWithCurrentEncoding = RegisteredClient.from(registeredClient)
			.clientSecret(currentEncoding)
			.build();
		if (!candidateWithCurrentEncoding.equals(current)) {
			throw new IllegalArgumentException("Only the client secret encoding may be upgraded");
		}
		this.repository.upgradeEncodedSecret(clientId, currentEncoding, replacementEncoding);
	}

	@Override
	public RegisteredClient findById(String id) {
		ClientId clientId = parseClientId(id);
		return clientId == null ? null
				: this.repository.findActiveById(clientId).map(this.mapper::toRegisteredClient).orElse(null);
	}

	@Override
	public RegisteredClient findByClientId(String clientId) {
		ClientIdentifier identifier = parseClientIdentifier(clientId);
		return identifier == null ? null
				: this.repository.findActiveByIdentifier(identifier).map(this.mapper::toRegisteredClient).orElse(null);
	}

	private static ClientId parseClientId(String value) {
		try {
			return ClientId.from(value);
		}
		catch (IllegalArgumentException | NullPointerException ex) {
			return null;
		}
	}

	private static ClientIdentifier parseClientIdentifier(String value) {
		try {
			return new ClientIdentifier(value);
		}
		catch (IllegalArgumentException | NullPointerException ex) {
			return null;
		}
	}

	private UnsupportedOperationException unsupportedRegistration() {
		return new UnsupportedOperationException("Registered clients must be created through ClientOperations");
	}

}
