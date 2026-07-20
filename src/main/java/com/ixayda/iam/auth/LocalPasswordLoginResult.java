package com.ixayda.iam.auth;

import java.time.Duration;
import java.util.Objects;
import java.util.Optional;

import com.ixayda.iam.session.UserSession;

public final class LocalPasswordLoginResult {

	private static final LocalPasswordLoginResult REJECTED =
			new LocalPasswordLoginResult(LocalPasswordLoginStatus.REJECTED, null, null, null);

	private static final LocalPasswordLoginResult UNAVAILABLE =
			new LocalPasswordLoginResult(LocalPasswordLoginStatus.UNAVAILABLE, null, null, null);

	private final LocalPasswordLoginStatus status;

	private final UserSession session;

	private final MfaChallenge challenge;

	private final Duration retryAfter;

	private LocalPasswordLoginResult(LocalPasswordLoginStatus status, UserSession session, MfaChallenge challenge,
			Duration retryAfter) {
		this.status = status;
		this.session = session;
		this.challenge = challenge;
		this.retryAfter = retryAfter;
	}

	public static LocalPasswordLoginResult success(UserSession session) {
		return new LocalPasswordLoginResult(LocalPasswordLoginStatus.AUTHENTICATED,
				Objects.requireNonNull(session, "User session must not be null"), null, null);
	}

	public static LocalPasswordLoginResult mfaRequired(MfaChallenge challenge) {
		return new LocalPasswordLoginResult(LocalPasswordLoginStatus.MFA_REQUIRED, null,
				Objects.requireNonNull(challenge, "MFA challenge must not be null"), null);
	}

	public static LocalPasswordLoginResult rejected() {
		return REJECTED;
	}

	public static LocalPasswordLoginResult throttled(Duration retryAfter) {
		Objects.requireNonNull(retryAfter, "Retry-after duration must not be null");
		if (retryAfter.isZero() || retryAfter.isNegative()) {
			throw new IllegalArgumentException("Retry-after duration must be positive");
		}
		return new LocalPasswordLoginResult(LocalPasswordLoginStatus.THROTTLED, null, null, retryAfter);
	}

	public static LocalPasswordLoginResult unavailable() {
		return UNAVAILABLE;
	}

	public LocalPasswordLoginStatus status() {
		return this.status;
	}

	public boolean authenticated() {
		return this.status == LocalPasswordLoginStatus.AUTHENTICATED;
	}

	public boolean mfaRequired() {
		return this.status == LocalPasswordLoginStatus.MFA_REQUIRED;
	}

	public Optional<UserSession> session() {
		return Optional.ofNullable(this.session);
	}

	public Optional<MfaChallenge> challenge() {
		return Optional.ofNullable(this.challenge);
	}

	public Optional<Duration> retryAfter() {
		return Optional.ofNullable(this.retryAfter);
	}

	@Override
	public String toString() {
		return "LocalPasswordLoginResult[status=" + this.status + "]";
	}

}
