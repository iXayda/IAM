package com.ixayda.iam.credential;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Arrays;

import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.ExternalIdentityProviderId;
import com.ixayda.iam.user.ExternalSubjectId;
import com.ixayda.iam.user.LoginKey;
import org.junit.jupiter.api.Test;

class ExternalCredentialVerifierContractTests {

	private static final ExternalIdentityProviderId PROVIDER_ID = ExternalIdentityProviderId.from("corporate");

	private static final ExternalSubjectId SUBJECT_ID = ExternalSubjectId.from("8d86b38a-9e5e-4d4d-a08d-9cb9086a5932");

	@Test
	void exposesVerifiedRejectedAndUnavailableResultsWithoutIdentityContext() {
		ExternalCredentialVerification verified = ExternalCredentialVerification.verified(SUBJECT_ID);
		ExternalCredentialVerification rejected = ExternalCredentialVerification.rejected();
		ExternalCredentialVerification unavailable = ExternalCredentialVerification.unavailable();

		assertThat(verified.status()).isEqualTo(ExternalCredentialVerificationStatus.VERIFIED);
		assertThat(verified.verified()).isTrue();
		assertThat(verified.subjectId()).contains(SUBJECT_ID);
		assertThat(verified.toString()).isEqualTo("ExternalCredentialVerification[status=VERIFIED]")
			.doesNotContain(SUBJECT_ID.value());
		assertThat(rejected.status()).isEqualTo(ExternalCredentialVerificationStatus.REJECTED);
		assertThat(rejected.verified()).isFalse();
		assertThat(rejected.subjectId()).isEmpty();
		assertThat(ExternalCredentialVerification.rejected()).isSameAs(rejected);
		assertThat(unavailable.status()).isEqualTo(ExternalCredentialVerificationStatus.UNAVAILABLE);
		assertThat(unavailable.verified()).isFalse();
		assertThat(unavailable.subjectId()).isEmpty();
		assertThat(ExternalCredentialVerification.unavailable()).isSameAs(unavailable);
		assertThatThrownBy(() -> ExternalCredentialVerification.verified(null))
			.isInstanceOf(NullPointerException.class);
	}

	@Test
	void leavesPasswordOwnershipWithTheCaller() {
		ExternalCredentialVerifier verifier = verifier();
		try (PasswordAttempt password = new PasswordAttempt("directory-secret".toCharArray())) {
			ExternalCredentialVerification result =
					verifier.verify(TenantId.DEFAULT, LoginKey.from("alice"), password);

			assertThat(result.verified()).isTrue();
			assertThat(password.isDestroyed()).isFalse();
			assertThat(password.copy()).containsExactly("directory-secret".toCharArray());
		}
	}

	private ExternalCredentialVerifier verifier() {
		return new ExternalCredentialVerifier() {
			@Override
			public ExternalIdentityProviderId providerId() {
				return PROVIDER_ID;
			}

			@Override
			public ExternalCredentialVerification verify(TenantId tenantId, LoginKey loginKey,
					PasswordAttempt password) {
				char[] copy = password.copy();
				try {
					return ExternalCredentialVerification.verified(SUBJECT_ID);
				}
				finally {
					Arrays.fill(copy, '\0');
				}
			}
		};
	}

}
