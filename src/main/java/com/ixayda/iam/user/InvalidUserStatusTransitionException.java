package com.ixayda.iam.user;

import java.util.Objects;

public final class InvalidUserStatusTransitionException extends IllegalStateException {

	private final UserId userId;

	private final UserStatus source;

	private final UserStatus target;

	public InvalidUserStatusTransitionException(UserId userId, UserStatus source, UserStatus target) {
		super("User cannot transition from " + source + " to " + target + ": " + userId);
		this.userId = Objects.requireNonNull(userId, "User ID must not be null");
		this.source = Objects.requireNonNull(source, "Source user status must not be null");
		this.target = Objects.requireNonNull(target, "Target user status must not be null");
	}

	public UserId userId() {
		return this.userId;
	}

	public UserStatus source() {
		return this.source;
	}

	public UserStatus target() {
		return this.target;
	}

}
