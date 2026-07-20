package com.ixayda.iam.credential.internal;

import java.time.Instant;
import java.util.Objects;

import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;

record StoredRecoveryCode(TenantId tenantId, UserId userId, String selector, String encodedCode,
		Instant createdAt, Instant consumedAt) {

	StoredRecoveryCode {
		Objects.requireNonNull(tenantId, "Recovery code tenant ID must not be null");
		Objects.requireNonNull(userId, "Recovery code user ID must not be null");
		Objects.requireNonNull(selector, "Recovery code selector must not be null");
		Objects.requireNonNull(encodedCode, "Encoded recovery code must not be null");
		Objects.requireNonNull(createdAt, "Recovery code creation time must not be null");
		if (selector.length() != 5 || encodedCode.length() < 32 || encodedCode.length() > 1024
				|| consumedAt != null && consumedAt.isBefore(createdAt)) {
			throw new IllegalArgumentException("Invalid stored recovery code metadata");
		}
	}

	StoredRecoveryCode consume(Instant consumedAt) {
		Objects.requireNonNull(consumedAt, "Recovery code consumption time must not be null");
		if (this.consumedAt != null) {
			throw new IllegalStateException("Recovery code has already been consumed");
		}
		Instant transitionAt = consumedAt.isBefore(this.createdAt) ? this.createdAt : consumedAt;
		return new StoredRecoveryCode(this.tenantId, this.userId, this.selector, this.encodedCode,
				this.createdAt, transitionAt);
	}

}
