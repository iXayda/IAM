package com.ixayda.iam.credential;

import java.util.Objects;
import java.util.Optional;

public final class ExternalCredentialVerification {

	private static final ExternalCredentialVerification REJECTED =
			new ExternalCredentialVerification(ExternalCredentialVerificationStatus.REJECTED, null);

	private static final ExternalCredentialVerification UNAVAILABLE =
			new ExternalCredentialVerification(ExternalCredentialVerificationStatus.UNAVAILABLE, null);

	private final ExternalCredentialVerificationStatus status;

	private final ExternalSubjectId subjectId;

	private ExternalCredentialVerification(ExternalCredentialVerificationStatus status, ExternalSubjectId subjectId) {
		this.status = status;
		this.subjectId = subjectId;
	}

	public static ExternalCredentialVerification verified(ExternalSubjectId subjectId) {
		return new ExternalCredentialVerification(ExternalCredentialVerificationStatus.VERIFIED,
				Objects.requireNonNull(subjectId, "Verified external subject ID must not be null"));
	}

	public static ExternalCredentialVerification rejected() {
		return REJECTED;
	}

	public static ExternalCredentialVerification unavailable() {
		return UNAVAILABLE;
	}

	public ExternalCredentialVerificationStatus status() {
		return this.status;
	}

	public boolean verified() {
		return this.status == ExternalCredentialVerificationStatus.VERIFIED;
	}

	public Optional<ExternalSubjectId> subjectId() {
		return Optional.ofNullable(this.subjectId);
	}

	@Override
	public String toString() {
		return "ExternalCredentialVerification[status=" + this.status + "]";
	}

}
