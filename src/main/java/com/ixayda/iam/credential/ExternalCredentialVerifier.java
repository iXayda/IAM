package com.ixayda.iam.credential;

import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.LoginKey;

public interface ExternalCredentialVerifier {

	ExternalCredentialProviderId providerId();

	/**
	 * Verifies a password against this provider. Unknown identities, inactive external
	 * accounts, and invalid passwords return {@code REJECTED}; provider transport or
	 * service failures return {@code UNAVAILABLE}. A verified subject belongs to the
	 * requested tenant and this verifier's provider namespace. Callers must use that
	 * tuple for explicit identity mapping and must not auto-link accounts by login value.
	 * The caller retains ownership of {@code password}; implementations must neither
	 * retain nor destroy it. Configuration errors must prevent provider startup instead
	 * of being reported as a rejected credential.
	 */
	ExternalCredentialVerification verify(TenantId tenantId, LoginKey loginKey, PasswordAttempt password);

}
