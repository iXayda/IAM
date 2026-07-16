package com.ixayda.iam.client.internal;

import java.util.Objects;

import com.ixayda.iam.client.OAuthClient;

record StoredOAuthClient(OAuthClient client, String encodedSecret) {

	StoredOAuthClient {
		Objects.requireNonNull(client, "Stored OAuth client must not be null");
		if (client.hasSecret() != (encodedSecret != null)) {
			throw new IllegalArgumentException("Stored client secret must match the client type");
		}
		if (encodedSecret != null && (encodedSecret.length() < 32 || encodedSecret.length() > 1024
				|| encodedSecret.regionMatches(true, 0, "{noop}", 0, 6))) {
			throw new IllegalArgumentException("Stored client secret must be a supported one-way encoding");
		}
	}

	@Override
	public String toString() {
		return "StoredOAuthClient[client=" + this.client + ", encodedSecretPresent=" + (this.encodedSecret != null) + "]";
	}

}
