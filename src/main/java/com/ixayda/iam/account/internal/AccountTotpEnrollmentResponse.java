package com.ixayda.iam.account.internal;

import java.time.Instant;
import java.util.Objects;

final class AccountTotpEnrollmentResponse {

	private final String credentialId;

	private final Instant expiresAt;

	private final String secret;

	private final String provisioningUri;

	AccountTotpEnrollmentResponse(String credentialId, Instant expiresAt, String secret, String provisioningUri) {
		this.credentialId = Objects.requireNonNull(credentialId, "TOTP credential ID must not be null");
		this.expiresAt = Objects.requireNonNull(expiresAt, "TOTP enrollment expiry must not be null");
		this.secret = Objects.requireNonNull(secret, "TOTP enrollment secret must not be null");
		this.provisioningUri = Objects.requireNonNull(provisioningUri, "TOTP provisioning URI must not be null");
	}

	public String getCredentialId() {
		return this.credentialId;
	}

	public Instant getExpiresAt() {
		return this.expiresAt;
	}

	public String getSecret() {
		return this.secret;
	}

	public String getProvisioningUri() {
		return this.provisioningUri;
	}

	public String getAlgorithm() {
		return "SHA1";
	}

	public int getDigits() {
		return 6;
	}

	public int getPeriodSeconds() {
		return 30;
	}

	@Override
	public String toString() {
		return "AccountTotpEnrollmentResponse[credentialId=" + this.credentialId + ", expiresAt=" + this.expiresAt
				+ ", secret=redacted, provisioningUri=redacted]";
	}

}
