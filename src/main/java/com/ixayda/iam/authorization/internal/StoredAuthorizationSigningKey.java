package com.ixayda.iam.authorization.internal;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

record StoredAuthorizationSigningKey(UUID signingKeyId, String kid, byte[] publicModulus, int publicExponent,
		Status status, AuthorizationSigningKeyAttestation.MetadataAttestation attestation,
		AuthorizationSigningKeyCipher.ProtectedPrivateKey privateKey, Instant createdAt,
		Instant publishedAt, Instant activateAfter, Instant activatedAt, Instant retiredAt, Instant publishUntil,
		Instant privateKeyDestroyedAt, long version, Instant updatedAt) {

	StoredAuthorizationSigningKey {
		Objects.requireNonNull(signingKeyId, "Signing key ID must not be null");
		Objects.requireNonNull(kid, "Signing key kid must not be null");
		publicModulus = Objects.requireNonNull(publicModulus, "Signing key modulus must not be null").clone();
		Objects.requireNonNull(status, "Signing key status must not be null");
		Objects.requireNonNull(createdAt, "Signing key creation time must not be null");
		Objects.requireNonNull(publishedAt, "Signing key publication time must not be null");
		Objects.requireNonNull(activateAfter, "Signing key activation threshold must not be null");
		Objects.requireNonNull(updatedAt, "Signing key update time must not be null");
	}

	@Override
	public byte[] publicModulus() {
		return this.publicModulus.clone();
	}

	StoredAuthorizationSigningKey withAttestation(
			AuthorizationSigningKeyAttestation.MetadataAttestation newAttestation) {
		return new StoredAuthorizationSigningKey(this.signingKeyId, this.kid, this.publicModulus,
				this.publicExponent, this.status, Objects.requireNonNull(newAttestation), this.privateKey,
				this.createdAt, this.publishedAt, this.activateAfter, this.activatedAt, this.retiredAt,
				this.publishUntil, this.privateKeyDestroyedAt, this.version, this.updatedAt);
	}

	enum Status {

		STAGED("staged"), ACTIVE("active"), RETIRED("retired");

		private final String databaseValue;

		Status(String databaseValue) {
			this.databaseValue = databaseValue;
		}

		String databaseValue() {
			return this.databaseValue;
		}

		static Status fromDatabase(String value) {
			for (Status status : values()) {
				if (status.databaseValue.equals(value)) {
					return status;
				}
			}
			throw new IllegalArgumentException("Unsupported authorization signing key status: " + value);
		}

	}

}
