package com.ixayda.iam.credential.internal;

import java.util.Objects;

import com.ixayda.iam.credential.TotpCredential;
import com.ixayda.iam.credential.TotpCredentialStatus;

record StoredTotpCredential(TotpCredential credential, TotpSecretCipher.ProtectedTotpSecret protectedSecret) {

	StoredTotpCredential {
		Objects.requireNonNull(credential, "TOTP credential must not be null");
		if (credential.status() == TotpCredentialStatus.REVOKED && protectedSecret != null) {
			throw new IllegalArgumentException("Revoked TOTP credentials must not retain protected secret material");
		}
		if (credential.status() != TotpCredentialStatus.REVOKED && protectedSecret == null) {
			throw new IllegalArgumentException("Usable TOTP credentials require protected secret material");
		}
	}

}
