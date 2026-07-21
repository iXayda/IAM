package com.ixayda.iam.credential;

import java.time.Instant;
import java.util.Objects;

import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;

public record CredentialSecurityEvent(TenantId tenantId, UserId userId, Type type,
		TotpCredentialId totpCredentialId, Instant occurredAt) {

	public CredentialSecurityEvent {
		Objects.requireNonNull(tenantId, "Credential security event tenant ID must not be null");
		Objects.requireNonNull(userId, "Credential security event user ID must not be null");
		Objects.requireNonNull(type, "Credential security event type must not be null");
		Objects.requireNonNull(occurredAt, "Credential security event time must not be null");
		if (type.isTotp() != (totpCredentialId != null)) {
			throw new IllegalArgumentException("Credential security event TOTP credential ID is invalid");
		}
	}

	public enum Type {

		TOTP_ACTIVATED,

		TOTP_REVOKED,

		RECOVERY_CODES_REPLACED,

		RECOVERY_CODE_CONSUMED;

		boolean isTotp() {
			return this == TOTP_ACTIVATED || this == TOTP_REVOKED;
		}

	}

}
