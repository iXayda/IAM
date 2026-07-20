package com.ixayda.iam.auth.internal;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.DateTimeException;
import java.time.Instant;
import java.util.Base64;
import java.util.Objects;
import java.util.Set;

import com.ixayda.iam.auth.MfaChallenge;
import com.ixayda.iam.auth.MfaChallengeConsumeStatus;
import com.ixayda.iam.auth.MfaChallengeIssue;
import com.ixayda.iam.auth.MfaChallengeOperations;
import com.ixayda.iam.auth.MfaChallengeToken;
import com.ixayda.iam.auth.MfaFactor;
import com.ixayda.iam.ratelimit.LoginAttemptSource;
import com.ixayda.iam.securitystate.SecurityStateConsumeStatus;
import com.ixayda.iam.securitystate.SecurityStateIssue;
import com.ixayda.iam.securitystate.SecurityStateKey;
import com.ixayda.iam.securitystate.SecurityStateOperations;
import com.ixayda.iam.securitystate.SecurityStateToken;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;
import org.springframework.stereotype.Service;

@Service
class DefaultMfaChallengeOperations implements MfaChallengeOperations {

	private static final String PURPOSE = "mfa.login";

	private static final String BINDING_VERSION = "v1";

	private final SecurityStateOperations states;

	private final MfaChallengeProperties properties;

	private final AuthenticationTimeSource timeSource;

	DefaultMfaChallengeOperations(SecurityStateOperations states, MfaChallengeProperties properties,
			AuthenticationTimeSource timeSource) {
		this.states = states;
		this.properties = properties;
		this.timeSource = timeSource;
	}

	@Override
	public MfaChallengeIssue issue(TenantId tenantId, UserId userId, LoginAttemptSource source,
			Instant passwordVerifiedAt, Set<MfaFactor> factors) {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		Objects.requireNonNull(userId, "User ID must not be null");
		Objects.requireNonNull(source, "Login attempt source must not be null");
		Objects.requireNonNull(passwordVerifiedAt, "Password verification time must not be null");
		Objects.requireNonNull(factors, "MFA factors must not be null");
		if (factors.isEmpty()) {
			throw new IllegalArgumentException("At least one MFA factor must be offered");
		}
		Instant issuedAt = this.timeSource.now();
		if (passwordVerifiedAt.isBefore(Instant.EPOCH) || passwordVerifiedAt.isAfter(issuedAt)
				|| passwordVerifiedAt.isBefore(issuedAt.minus(this.properties.challengeTtl()))) {
			throw new IllegalArgumentException("Password verification time is outside the MFA challenge window");
		}
		Instant expiresAt;
		try {
			expiresAt = issuedAt.plus(this.properties.challengeTtl());
		}
		catch (DateTimeException | ArithmeticException ex) {
			throw new IllegalArgumentException("MFA challenge expiration time is outside the supported range", ex);
		}
		Set<MfaFactor> immutableFactors = Set.copyOf(factors);
		SecurityStateIssue issue = this.states.issue(
				key(tenantId, userId, passwordVerifiedAt, expiresAt, immutableFactors, source),
				this.properties.challengeTtl());
		if (!issue.issued()) {
			return MfaChallengeIssue.unavailable();
		}
		MfaChallengeToken token = MfaChallengeToken.from(issue.token().orElseThrow().value());
		return MfaChallengeIssue.issued(new MfaChallenge(token, tenantId, userId, passwordVerifiedAt, expiresAt,
				immutableFactors));
	}

	@Override
	public MfaChallengeConsumeStatus consume(MfaChallenge challenge, LoginAttemptSource source) {
		Objects.requireNonNull(challenge, "MFA challenge must not be null");
		Objects.requireNonNull(source, "Login attempt source must not be null");
		SecurityStateConsumeStatus status = this.states.consume(
				key(challenge.tenantId(), challenge.userId(), challenge.passwordVerifiedAt(), challenge.expiresAt(),
						challenge.factors(), source),
				SecurityStateToken.from(challenge.token().value()));
		return switch (status) {
			case CONSUMED -> MfaChallengeConsumeStatus.CONSUMED;
			case REJECTED -> MfaChallengeConsumeStatus.REJECTED;
			case UNAVAILABLE -> MfaChallengeConsumeStatus.UNAVAILABLE;
		};
	}

	private static SecurityStateKey key(TenantId tenantId, UserId userId, Instant passwordVerifiedAt,
			Instant expiresAt, Set<MfaFactor> factors, LoginAttemptSource source) {
		String binding = String.join(":", BINDING_VERSION, userId.value().toString(), instant(passwordVerifiedAt),
				instant(expiresAt), Integer.toString(factorMask(factors)), sourceDigest(source));
		return new SecurityStateKey(tenantId, PURPOSE, binding);
	}

	private static int factorMask(Set<MfaFactor> factors) {
		int mask = 0;
		for (MfaFactor factor : factors) {
			mask |= 1 << Objects.requireNonNull(factor, "MFA factor must not be null").ordinal();
		}
		return mask;
	}

	private static String instant(Instant value) {
		return value.getEpochSecond() + "." + value.getNano();
	}

	private static String sourceDigest(LoginAttemptSource source) {
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			byte[] encoded = digest.digest(source.value().getBytes(StandardCharsets.US_ASCII));
			return Base64.getUrlEncoder().withoutPadding().encodeToString(encoded);
		}
		catch (NoSuchAlgorithmException ex) {
			throw new IllegalStateException("SHA-256 is not available", ex);
		}
	}

}
