package com.ixayda.iam.securitystate;

import java.util.Objects;
import java.util.Optional;

public final class SecurityStateIssue {

	private static final SecurityStateIssue UNAVAILABLE =
			new SecurityStateIssue(SecurityStateIssueStatus.UNAVAILABLE, null);

	private final SecurityStateIssueStatus status;

	private final SecurityStateToken token;

	private SecurityStateIssue(SecurityStateIssueStatus status, SecurityStateToken token) {
		this.status = status;
		this.token = token;
	}

	public static SecurityStateIssue issued(SecurityStateToken token) {
		return new SecurityStateIssue(SecurityStateIssueStatus.ISSUED,
				Objects.requireNonNull(token, "Issued security state token must not be null"));
	}

	public static SecurityStateIssue unavailable() {
		return UNAVAILABLE;
	}

	public SecurityStateIssueStatus status() {
		return this.status;
	}

	public boolean issued() {
		return this.status == SecurityStateIssueStatus.ISSUED;
	}

	public Optional<SecurityStateToken> token() {
		return Optional.ofNullable(this.token);
	}

	@Override
	public String toString() {
		return "SecurityStateIssue[status=" + this.status + "]";
	}

}
