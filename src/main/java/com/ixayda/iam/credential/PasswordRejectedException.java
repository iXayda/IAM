package com.ixayda.iam.credential;

/** A password rejection that never carries the submitted password. */
public final class PasswordRejectedException extends IllegalArgumentException {

	public enum Reason {
		INVALID_LENGTH, INVALID_UNICODE, WEAK_PASSWORD
	}

	private final Reason reason;

	PasswordRejectedException(Reason reason) {
		super(reason.name());
		this.reason = reason;
	}

	public Reason reason() {
		return this.reason;
	}

}
