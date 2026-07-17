package com.ixayda.iam.authorization.internal;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class AuthorizationConsentControllerTests {

	@Test
	void preservesEncodedRedirectQueryWhileEncodingErrorState() {
		assertThat(AuthorizationConsentController.denialRedirect(
				"https://client.example.test/callback?return=a%20b&resource=%2Faccount", "state / value"))
			.asString()
			.isEqualTo("https://client.example.test/callback?return=a%20b&resource=%2Faccount&error=access_denied&state=state%20%2F%20value");
	}

}
