package com.ixayda.iam.client;

import java.util.Objects;
import java.util.Optional;

public final class ClientRegistration implements AutoCloseable {

	private final OAuthClient client;

	private final IssuedClientSecret clientSecret;

	public ClientRegistration(OAuthClient client, IssuedClientSecret clientSecret) {
		this.client = Objects.requireNonNull(client, "Registered client must not be null");
		if (client.hasSecret() != (clientSecret != null)) {
			throw new IllegalArgumentException("Registered client secret must match the client type");
		}
		this.clientSecret = clientSecret;
	}

	public OAuthClient client() {
		return this.client;
	}

	public Optional<IssuedClientSecret> clientSecret() {
		return Optional.ofNullable(this.clientSecret);
	}

	@Override
	public void close() {
		if (this.clientSecret != null) {
			this.clientSecret.close();
		}
	}

	@Override
	public String toString() {
		return "ClientRegistration[client=" + this.client + ", clientSecretPresent=" + (this.clientSecret != null) + "]";
	}

}
