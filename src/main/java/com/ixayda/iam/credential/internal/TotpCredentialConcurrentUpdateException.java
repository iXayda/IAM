package com.ixayda.iam.credential.internal;

import com.ixayda.iam.credential.TotpCredentialId;

final class TotpCredentialConcurrentUpdateException extends RuntimeException {

	private final TotpCredentialId credentialId;

	private final long expectedVersion;

	TotpCredentialConcurrentUpdateException(TotpCredentialId credentialId, long expectedVersion) {
		super("TOTP credential changed concurrently");
		this.credentialId = credentialId;
		this.expectedVersion = expectedVersion;
	}

	TotpCredentialId credentialId() {
		return this.credentialId;
	}

	long expectedVersion() {
		return this.expectedVersion;
	}

}
