package com.ixayda.iam.security;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.*;

class IdentityTokenRequestsTests {

	@ParameterizedTest
	@ValueSource(strings = { "https://iam.example", "https://iam.example/", "https://iam.example:443", "https://iam.example:8443/", "https://[::1]:8443" })
	void rootIssuerKeepsItsExactConfiguredIdentity(String issuer) {
		assertThat(IdentityTokenRequests.requireIssuer(issuer)).isEqualTo(issuer);
	}

	@ParameterizedTest
	@NullSource
	@ValueSource(strings = { "", "http://iam.example", "https://user:secret@iam.example", "https://iam.example?query", "https://iam.example#fragment",
			"https://iam.example:0", "https://iam.example:65536", "https://iam.example:", "https://iam.example/tenant", "https://iam.example/tenant/",
			"https://iam.example//", "https://iam.example/.", "https://iam.example/a/..", "https://iam.example/%2F", "https://iam.example/%2e" })
	void invalidOrPathBasedIssuerIsRejectedInsteadOfBeingNormalized(String issuer) {
		assertThatIllegalArgumentException().isThrownBy(() -> IdentityTokenRequests.requireIssuer(issuer))
				.withMessage("An explicit HTTPS issuer at the root path is required");
	}

}
