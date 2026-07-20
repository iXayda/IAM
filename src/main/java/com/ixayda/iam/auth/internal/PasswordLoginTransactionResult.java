package com.ixayda.iam.auth.internal;

import java.time.Instant;
import java.util.EnumSet;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import com.ixayda.iam.auth.MfaFactor;
import com.ixayda.iam.session.UserSession;
import com.ixayda.iam.user.UserId;

final class PasswordLoginTransactionResult {

	private static final PasswordLoginTransactionResult REJECTED =
			new PasswordLoginTransactionResult(null, null, null, Set.of());

	private final UserSession session;

	private final UserId userId;

	private final Instant passwordVerifiedAt;

	private final Set<MfaFactor> factors;

	private PasswordLoginTransactionResult(UserSession session, UserId userId, Instant passwordVerifiedAt,
			Set<MfaFactor> factors) {
		this.session = session;
		this.userId = userId;
		this.passwordVerifiedAt = passwordVerifiedAt;
		this.factors = factors;
	}

	static PasswordLoginTransactionResult authenticated(UserSession session) {
		return new PasswordLoginTransactionResult(
				Objects.requireNonNull(session, "Authenticated session must not be null"), null, null, Set.of());
	}

	static PasswordLoginTransactionResult mfaRequired(UserId userId, Instant passwordVerifiedAt,
			Set<MfaFactor> factors) {
		Objects.requireNonNull(userId, "MFA user ID must not be null");
		Objects.requireNonNull(passwordVerifiedAt, "Password verification time must not be null");
		Objects.requireNonNull(factors, "MFA factors must not be null");
		if (factors.isEmpty()) {
			throw new IllegalArgumentException("MFA transaction result must contain at least one factor");
		}
		return new PasswordLoginTransactionResult(null, userId, passwordVerifiedAt,
				Set.copyOf(EnumSet.copyOf(factors)));
	}

	static PasswordLoginTransactionResult rejected() {
		return REJECTED;
	}

	boolean authenticated() {
		return this.session != null;
	}

	boolean mfaRequired() {
		return this.userId != null;
	}

	Optional<UserSession> session() {
		return Optional.ofNullable(this.session);
	}

	Optional<UserId> userId() {
		return Optional.ofNullable(this.userId);
	}

	Optional<Instant> passwordVerifiedAt() {
		return Optional.ofNullable(this.passwordVerifiedAt);
	}

	Set<MfaFactor> factors() {
		return this.factors;
	}

}
