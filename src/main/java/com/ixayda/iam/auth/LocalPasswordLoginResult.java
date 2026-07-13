package com.ixayda.iam.auth;

import java.util.Objects;
import java.util.Optional;

import com.ixayda.iam.session.UserSession;

public final class LocalPasswordLoginResult {

	private static final LocalPasswordLoginResult FAILURE = new LocalPasswordLoginResult(null);

	private final UserSession session;

	private LocalPasswordLoginResult(UserSession session) {
		this.session = session;
	}

	public static LocalPasswordLoginResult success(UserSession session) {
		return new LocalPasswordLoginResult(Objects.requireNonNull(session, "User session must not be null"));
	}

	public static LocalPasswordLoginResult failure() {
		return FAILURE;
	}

	public boolean authenticated() {
		return this.session != null;
	}

	public Optional<UserSession> session() {
		return Optional.ofNullable(this.session);
	}

	@Override
	public String toString() {
		return "LocalPasswordLoginResult[authenticated=" + authenticated() + "]";
	}

}
