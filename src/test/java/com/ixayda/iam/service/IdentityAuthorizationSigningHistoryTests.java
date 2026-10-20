package com.ixayda.iam.service;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

import com.nimbusds.jose.util.Base64URL;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import static org.assertj.core.api.Assertions.*;

class IdentityAuthorizationSigningHistoryTests {

	@Test
	void newTokenHistoryIsCompleteAndRetainsEarlierKeyIdsAcrossSuccessiveRefreshes() {
		UUID first = UUID.randomUUID(); UUID second = UUID.randomUUID(); var code = empty();
		var issued = IdentityAuthorizationSigningHistory.record(token(code, first), code);
		var refreshed = IdentityAuthorizationSigningHistory.record(token(issued, second), issued);
		assertThat(IdentityAuthorizationSigningHistory.mayHaveUsed(refreshed, first)).isTrue();
		assertThat(IdentityAuthorizationSigningHistory.mayHaveUsed(refreshed, second)).isTrue();
		assertThat(IdentityAuthorizationSigningHistory.mayHaveUsed(refreshed, UUID.randomUUID())).isFalse();
		assertThat(refreshed.<String>getAttribute("iam.signingHistory")).contains("|complete|");
		assertThat(IdentityAuthorizationSigningHistory.record(token(refreshed, first), refreshed).<String>getAttribute("iam.signingHistory")).isEqualTo(refreshed.<String>getAttribute("iam.signingHistory"));
	}

	@Test
	void missingLegacyProvenanceRemainsPartialAndCannotClearAnIncidentByRefreshing() {
		var legacy = token(empty(), UUID.randomUUID()); var next = IdentityAuthorizationSigningHistory.record(token(legacy, UUID.randomUUID()), legacy);
		assertThat(IdentityAuthorizationSigningHistory.mayHaveUsed(legacy, UUID.randomUUID())).isTrue();
		assertThat(IdentityAuthorizationSigningHistory.mayHaveUsed(next, UUID.randomUUID())).isTrue();
		assertThat(next.<String>getAttribute("iam.signingHistory")).contains("|partial|");
		assertThat(IdentityAuthorizationSigningHistory.mayHaveUsed(empty(), UUID.randomUUID())).isFalse();
	}

	@ParameterizedTest
	@ValueSource(strings = { "private-invalid-history", "iam:signing-history:v2|complete|", "iam:signing-history:v1|complete|", "iam:signing-history:v1|bad|", "iam:signing-history:v1|complete|1-1-1-1-1" })
	void invalidProtectedHistoryFailsClosedWithAFixedError(String value) {
		var token = OAuth2Authorization.from(token(empty(), UUID.randomUUID())).attribute("iam.signingHistory", value).build();
		assertThatIllegalStateException().isThrownBy(() -> IdentityAuthorizationSigningHistory.mayHaveUsed(token, UUID.randomUUID()))
				.withMessage("Authorization signing history is invalid").withNoCause();
	}

	private static OAuth2Authorization empty() {
		var client = RegisteredClient.withId(UUID.randomUUID().toString()).clientId(UUID.randomUUID().toString())
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE).redirectUri("https://orders.example/callback").build();
		return OAuth2Authorization.withRegisteredClient(client).id(UUID.randomUUID().toString()).principalName(UUID.randomUUID().toString()).authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE).build();
	}
	private static OAuth2Authorization token(OAuth2Authorization original, UUID key) {
		String raw = Base64URL.encode("{\"alg\":\"RS256\",\"kid\":\"" + key + "\"}") + "." + Base64URL.encode("{}") + ".AA";
		return OAuth2Authorization.from(original).accessToken(new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, raw, Instant.now(), Instant.now().plusSeconds(300), Set.of("openid"))).build();
	}
}
