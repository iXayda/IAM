package com.ixayda.iam.auth;

import java.time.Instant;
import java.util.EnumSet;
import java.util.Objects;
import java.util.Set;

import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;

public record MfaChallenge(MfaChallengeToken token, TenantId tenantId, UserId userId,
		Instant passwordVerifiedAt, Instant expiresAt, Set<MfaFactor> factors) {

	public MfaChallenge {
		Objects.requireNonNull(token, "MFA challenge token must not be null");
		Objects.requireNonNull(tenantId, "MFA challenge tenant ID must not be null");
		Objects.requireNonNull(userId, "MFA challenge user ID must not be null");
		Objects.requireNonNull(passwordVerifiedAt, "Password verification time must not be null");
		Objects.requireNonNull(expiresAt, "MFA challenge expiration time must not be null");
		Objects.requireNonNull(factors, "MFA challenge factors must not be null");
		if (passwordVerifiedAt.isBefore(Instant.EPOCH) || !expiresAt.isAfter(passwordVerifiedAt)) {
			throw new IllegalArgumentException("MFA challenge timestamps are invalid");
		}
		if (factors.isEmpty()) {
			throw new IllegalArgumentException("MFA challenge must offer at least one factor");
		}
		factors = Set.copyOf(EnumSet.copyOf(factors));
	}

	public boolean supports(MfaFactor factor) {
		return this.factors.contains(Objects.requireNonNull(factor, "MFA factor must not be null"));
	}

	@Override
	public String toString() {
		return "MfaChallenge[token=redacted, tenantId=" + this.tenantId + ", userId=redacted, expiresAt="
				+ this.expiresAt + ", factors=" + this.factors + "]";
	}

}
