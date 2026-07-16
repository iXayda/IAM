package com.ixayda.iam.authorization.internal;

import java.util.List;
import java.util.Objects;

import com.nimbusds.jose.jwk.RSAKey;

final class AuthorizationSigningKeyRing {

	private final RSAKey activeSigningKey;

	private final List<RSAKey> publishedKeys;

	AuthorizationSigningKeyRing(RSAKey activeSigningKey, List<RSAKey> publishedKeys) {
		this.activeSigningKey = Objects.requireNonNull(activeSigningKey, "Active signing key must not be null");
		this.publishedKeys = List.copyOf(publishedKeys);
		if (!this.activeSigningKey.isPrivate()) {
			throw new IllegalArgumentException("The active signing key must contain private material");
		}
		long activePublicKeys = this.publishedKeys.stream()
			.filter(key -> this.activeSigningKey.getKeyID().equals(key.getKeyID()))
			.count();
		if (activePublicKeys != 1 || this.publishedKeys.stream().anyMatch(RSAKey::isPrivate)) {
			throw new IllegalArgumentException(
					"Published signing keys must contain exactly one public copy of the active key");
		}
	}

	RSAKey activeSigningKey() {
		return this.activeSigningKey;
	}

	List<RSAKey> publishedKeys() {
		return this.publishedKeys;
	}

	@Override
	public String toString() {
		return "AuthorizationSigningKeyRing[activeKid=" + this.activeSigningKey.getKeyID()
				+ ", publishedKeyCount=" + this.publishedKeys.size() + ", privateMaterial=redacted]";
	}

}
