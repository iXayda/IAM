package com.ixayda.iam.auth;

import java.util.Objects;
import java.util.Optional;

import com.ixayda.iam.session.UserSession;

public final class MfaLoginResult {

	private static final MfaLoginResult REJECTED = new MfaLoginResult(MfaLoginStatus.REJECTED, null);

	private static final MfaLoginResult UNAVAILABLE = new MfaLoginResult(MfaLoginStatus.UNAVAILABLE, null);

	private final MfaLoginStatus status;

	private final UserSession session;

	private MfaLoginResult(MfaLoginStatus status, UserSession session) {
		this.status = status;
		this.session = session;
	}

	public static MfaLoginResult authenticated(UserSession session) {
		return new MfaLoginResult(MfaLoginStatus.AUTHENTICATED,
				Objects.requireNonNull(session, "Authenticated session must not be null"));
	}

	public static MfaLoginResult rejected() {
		return REJECTED;
	}

	public static MfaLoginResult unavailable() {
		return UNAVAILABLE;
	}

	public MfaLoginStatus status() {
		return this.status;
	}

	public boolean authenticated() {
		return this.status == MfaLoginStatus.AUTHENTICATED;
	}

	public Optional<UserSession> session() {
		return Optional.ofNullable(this.session);
	}

}
