package com.ixayda.iam.credential.internal;

import com.ixayda.iam.credential.TotpCredentialId;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;

final class TotpCredentialAlreadyExistsException extends RuntimeException {

	private final TenantId tenantId;

	private final UserId userId;

	private final TotpCredentialId credentialId;

	TotpCredentialAlreadyExistsException(TenantId tenantId, UserId userId, TotpCredentialId credentialId) {
		super("TOTP credential already exists");
		this.tenantId = tenantId;
		this.userId = userId;
		this.credentialId = credentialId;
	}

	TenantId tenantId() {
		return this.tenantId;
	}

	UserId userId() {
		return this.userId;
	}

	TotpCredentialId credentialId() {
		return this.credentialId;
	}

}
