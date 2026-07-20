package com.ixayda.iam.auth;

import java.util.Objects;
import java.util.Optional;

public final class MfaChallengeIssue {

	private static final MfaChallengeIssue UNAVAILABLE =
			new MfaChallengeIssue(MfaChallengeIssueStatus.UNAVAILABLE, null);

	private final MfaChallengeIssueStatus status;

	private final MfaChallenge challenge;

	private MfaChallengeIssue(MfaChallengeIssueStatus status, MfaChallenge challenge) {
		this.status = status;
		this.challenge = challenge;
	}

	public static MfaChallengeIssue issued(MfaChallenge challenge) {
		return new MfaChallengeIssue(MfaChallengeIssueStatus.ISSUED,
				Objects.requireNonNull(challenge, "Issued MFA challenge must not be null"));
	}

	public static MfaChallengeIssue unavailable() {
		return UNAVAILABLE;
	}

	public MfaChallengeIssueStatus status() {
		return this.status;
	}

	public boolean issued() {
		return this.status == MfaChallengeIssueStatus.ISSUED;
	}

	public Optional<MfaChallenge> challenge() {
		return Optional.ofNullable(this.challenge);
	}

	@Override
	public String toString() {
		return "MfaChallengeIssue[status=" + this.status + "]";
	}

}
