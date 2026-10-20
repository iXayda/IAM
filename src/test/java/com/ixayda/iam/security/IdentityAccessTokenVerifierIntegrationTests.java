package com.ixayda.iam.security;

import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Consumer;

import com.ixayda.iam.IdentityProtocolTestSupport;
import com.ixayda.iam.service.IdentityAccessTokens;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.SignedJWT;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessException;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationToken;
import org.springframework.transaction.support.TransactionTemplate;

import static org.assertj.core.api.Assertions.*;

class IdentityAccessTokenVerifierIntegrationTests extends IdentityProtocolTestSupport {

	@Autowired private IdentityAccessTokens online;
	private IdentityAccessTokenVerifier verifier;

	@BeforeEach
	void verifier() { this.verifier = new IdentityAccessTokenVerifier(this.online, "https://iam.example"); }

	@Test
	void acceptsOnlyTheCurrentSignedApplicationProjectionWithoutExposingBearerOrManagementAuthorities() {
		String code = code(Set.of("openid", "profile")); var issued = exchange(request(code, authenticatedClient(code)));
		var before = stored(code); var result = this.verifier.verify(issued.getAccessToken().getTokenValue()).orElseThrow();
		assertThat(result.authorizationId().toString()).isEqualTo(before.authorization().getId());
		assertThat(result.access().userId()).isEqualTo(this.userId); assertThat(result.access().clientId()).isEqualTo(this.clientId);
		assertThat(result.access().resourceId()).isEqualTo(this.resourceId); assertThat(result.access().audience()).isEqualTo("urn:example:orders");
		assertThat(result.scopes()).containsExactlyInAnyOrder("openid", "profile");
		assertThat(result.access().roles()).extracting(role -> role.code()).containsExactly("reader");
		assertThat(result.toString()).doesNotContain(issued.getAccessToken().getTokenValue(), this.secret, PASSWORD, "ROLE_IAM_ADMIN");
		assertThat(this.verifier.verifyForResource(issued.getAccessToken().getTokenValue(), this.resourceId)).contains(result);
		assertThat(this.verifier.verifyForResource(issued.getAccessToken().getTokenValue(), UUID.randomUUID())).isEmpty();
		assertThat(stored(code)).isEqualTo(before);
	}

	@Test
	void equivalentScopeRoleOrderAndSingleStringAudienceKeepTheirStandardSetSemantics() throws Exception {
		var role = this.roles.create(this.resourceId, "writer", "Writer", AUDIT);
		this.assignments.change(this.userId, role.id(), 1, true, AUDIT);
		this.clients.updateConfiguration(this.clientId, 1, configuration(this.resourceId, Set.of(this.roleId, role.id())), AUDIT);
		String code = code(Set.of("openid", "profile")); exchange(request(code, authenticatedClient(code)));
		String changed = rewrite(code, claims -> {
			claims.put("scope", "profile openid"); claims.put("roles", List.of("writer", "reader")); claims.put("aud", "urn:example:orders");
		}, headers -> { }, false, null);
		assertThat(this.verifier.verify(changed)).isPresent();
	}

	@Test
	void aChangedSignatureOnTheExactStoredBearerIsRejected() {
		String code = code(Set.of("openid")); var issued = exchange(request(code, authenticatedClient(code)));
		String raw = issued.getAccessToken().getTokenValue(); int signature = raw.lastIndexOf('.') + 1;
		String changed = raw.substring(0, signature) + (raw.charAt(signature) == 'A' ? 'B' : 'A') + raw.substring(signature + 1);
		replaceBearer(code, changed, null); assertThat(this.verifier.verify(changed)).isEmpty();
	}

	@ParameterizedTest
	@ValueSource(strings = { "subject", "client", "authorization", "issuer", "issuer-prefix", "issuer-type", "audience", "multiple-audiences", "audience-type",
			"scope", "duplicate-scopes", "scope-type", "roles", "duplicate-roles", "roles-type", "issued", "future", "expiry", "expiry-type", "issued-type", "not-before",
			"missing-expiry", "missing-issued", "missing-not-before", "missing-jti", "jti", "missing-roles", "missing-scope", "missing-client", "missing-authorization" })
	void rejectsEvenValidSignaturesWhenStoredBearerClaimsDoNotMatchItsCurrentTrustedBounds(String mutation) throws Exception {
		String code = code(Set.of("openid", "profile")); exchange(request(code, authenticatedClient(code)));
		String changed = rewrite(code, claims -> {
			switch (mutation) {
				case "subject" -> claims.put("sub", UUID.randomUUID().toString());
				case "client" -> claims.put("client_id", " " + this.clientId);
				case "authorization" -> claims.put("authorization_id", UUID.randomUUID().toString());
				case "issuer" -> claims.put("iss", "https://foreign.example"); case "issuer-prefix" -> claims.put("iss", "https://iam.example.attacker.example");
				case "issuer-type" -> claims.put("iss", List.of("https://iam.example"));
				case "audience" -> claims.put("aud", List.of("urn:example:billing"));
				case "multiple-audiences" -> claims.put("aud", List.of("urn:example:orders", "urn:example:billing")); case "audience-type" -> claims.put("aud", Map.of("value", "urn:example:orders"));
				case "scope" -> claims.put("scope", "openid"); case "duplicate-scopes" -> claims.put("scope", "openid profile profile"); case "scope-type" -> claims.put("scope", List.of("openid", "profile"));
				case "roles" -> claims.put("roles", List.of("ROLE_IAM_ADMIN")); case "duplicate-roles" -> claims.put("roles", List.of("reader", "reader")); case "roles-type" -> claims.put("roles", "reader");
				case "issued" -> claims.put("iat", ((Number) claims.get("iat")).longValue() - 1);
				case "future" -> { claims.put("iat", Instant.now().getEpochSecond() + 31); claims.put("nbf", claims.get("iat")); }
				case "expiry" -> claims.put("exp", ((Number) claims.get("exp")).longValue() + 1);
				case "expiry-type" -> claims.put("exp", claims.get("exp").toString()); case "issued-type" -> claims.put("iat", claims.get("iat").toString());
				case "not-before" -> claims.put("nbf", ((Number) claims.get("nbf")).longValue() + 1);
				case "missing-expiry" -> claims.remove("exp"); case "missing-issued" -> claims.remove("iat"); case "missing-not-before" -> claims.remove("nbf");
				case "missing-jti" -> claims.remove("jti"); case "jti" -> claims.put("jti", "unbounded-noncanonical-token-identity");
				case "missing-roles" -> claims.remove("roles"); case "missing-scope" -> claims.remove("scope"); case "missing-client" -> claims.remove("client_id");
				default -> claims.remove("authorization_id");
			}
		}, headers -> { }, false, null);
		var before = stored(code); assertThat(this.verifier.verify(changed)).isEmpty(); assertThat(stored(code)).isEqualTo(before);
	}

	@ParameterizedTest
	@ValueSource(strings = { "id-type", "missing-type", "wrong-case", "missing-kid", "unknown-kid", "noncanonical-kid", "algorithm", "remote-key", "embedded-key", "critical" })
	void trustedKeysCannotBeSelectedByAnotherTokenPurposeOrAnUnapprovedJoseHeader(String mutation) throws Exception {
		String code = code(Set.of("openid")); exchange(request(code, authenticatedClient(code)));
		String changed = rewrite(code, claims -> { }, headers -> {
			switch (mutation) {
				case "id-type" -> headers.put("typ", "JWT"); case "missing-type" -> headers.remove("typ"); case "wrong-case" -> headers.put("typ", "AT+JWT");
				case "missing-kid" -> headers.remove("kid"); case "unknown-kid" -> headers.put("kid", UUID.randomUUID().toString());
				case "noncanonical-kid" -> headers.put("kid", " " + this.signing.id());
				case "algorithm" -> headers.put("alg", "RS512"); case "remote-key" -> headers.put("jku", "https://attacker.example/jwks");
				case "embedded-key" -> headers.put("jwk", new com.nimbusds.jose.jwk.RSAKey.Builder(this.signing.publicKey()).build().toJSONObject());
				default -> { headers.put("crit", List.of("unapproved")); headers.put("unapproved", true); }
			}
		}, false, null);
		assertThat(this.verifier.verify(changed)).isEmpty();
	}

	@Test
	void aCorrectKidAndStoredBearerCannotSubstituteAValidSignatureFromAnUntrustedPrivateKey() throws Exception {
		String code = code(Set.of("openid")); exchange(request(code, authenticatedClient(code)));
		String changed = rewrite(code, claims -> { }, headers -> { }, true, null);
		assertThat(this.verifier.verify(changed)).isEmpty();
	}

	@Test
	void idTokensCannotBeUsedAsAccessTokensEvenWhenPlacedInTheAccessBearerSlot() {
		String code = code(Set.of("openid")); var issued = exchange(request(code, authenticatedClient(code)));
		String id = issued.getAdditionalParameters().get("id_token").toString(); replaceBearer(code, id, null);
		assertThat(this.verifier.verify(id)).isEmpty();
	}

	@ParameterizedTest
	@ValueSource(strings = { "", " ", "not-a-jwt", "a.b.c", "a.b.", "none", "oversized" })
	void malformedOrUnboundedInputsFailAsInactiveCredentials(String invalid) {
		String value = switch (invalid) {
			case "none" -> "eyJhbGciOiJub25lIiwidHlwIjoiYXQrand0In0.e30.";
			case "oversized" -> "a".repeat(16385); default -> invalid;
		};
		assertThat(this.verifier.verify(value)).isEmpty(); assertThat(this.verifier.verify(null)).isEmpty();
	}

	@Test
	void actualNarrowedRefreshScopesAreUsedAfterTheOfflineFamilyIsClosed() {
		String code = code(Set.of("openid", "profile", "offline_access")); var issued = exchange(request(code, authenticatedClient(code)));
		var next = rotate(issued.getRefreshToken().getTokenValue(), Set.of("profile"));
		assertThat(this.verifier.verify(issued.getAccessToken().getTokenValue())).isEmpty();
		assertThat(this.verifier.verify(next.getAccessToken().getTokenValue())).get().satisfies(token -> assertThat(token.scopes()).containsExactly("profile"));
		assertThat(stored(code).authorization().getAuthorizedScopes()).contains("openid", "profile", "offline_access");
		this.store.deleteById(this.sessionId);
		assertThat(this.verifier.verify(next.getAccessToken().getTokenValue())).isPresent();
	}

	@Test
	void configurationChangesCannotBeUndoneByPresentingTheStillCorrectlySignedBearer() {
		String code = code(Set.of("openid")); var issued = exchange(request(code, authenticatedClient(code)));
		this.clients.setEnabled(this.clientId, 1, false, AUDIT); this.clients.setEnabled(this.clientId, 2, true, AUDIT);
		assertThat(this.verifier.verify(issued.getAccessToken().getTokenValue())).isEmpty();
	}

	@Test
	void numericDateSecondsAreComparedToTheAuthoritativeLifetimeWithoutRoundingItUp() throws Exception {
		String code = code(Set.of("openid")); var issued = exchange(request(code, authenticatedClient(code)));
		Instant precise = issued.getAccessToken().getExpiresAt().minusSeconds(1).plusNanos(123456000);
		String changed = rewrite(code, claims -> claims.put("exp", precise.getEpochSecond()), headers -> { }, false, precise);
		assertThat(this.verifier.verify(changed)).get().satisfies(token -> assertThat(token.expiresAt()).isEqualTo(precise));
	}

	@Test
	void publicSignatureValidationDoesNotNeedPrivateKeyDecryption() {
		String code = code(Set.of("openid")); var issued = exchange(request(code, authenticatedClient(code)));
		byte[] encrypted = this.jdbc.sql("SELECT encrypted_private_key FROM iam_signing_key").query(byte[].class).single();
		try {
			this.jdbc.sql("UPDATE iam_signing_key SET encrypted_private_key=set_byte(encrypted_private_key,10,get_byte(encrypted_private_key,10) # 1)").update();
			assertThatIllegalStateException().isThrownBy(this.keys::signingMaterial);
			assertThat(this.verifier.verify(issued.getAccessToken().getTokenValue())).isPresent();
		}
		finally { this.jdbc.sql("UPDATE iam_signing_key SET encrypted_private_key=:value").param("value", encrypted).update(); }
	}

	@Test
	void storageOutagesPropagateAndCannotBecomeSuccessfulOfflineOrInactiveFallbacks() {
		String code = code(Set.of("openid")); var issued = exchange(request(code, authenticatedClient(code)));
		this.jdbc.sql("ALTER TABLE iam_authorization_token_index RENAME TO verifier_unavailable_index").update();
		try { assertThatThrownBy(() -> this.verifier.verify(issued.getAccessToken().getTokenValue())).isInstanceOf(DataAccessException.class); }
		finally { this.jdbc.sql("ALTER TABLE verifier_unavailable_index RENAME TO iam_authorization_token_index").update(); }
		assertThat(this.verifier.verify(issued.getAccessToken().getTokenValue())).isPresent();
	}

	@Test
	void invocationRequiresAnIndependentGateAndAResourceIdentityEstablishedByTheCaller() {
		String code = code(Set.of("openid")); var issued = exchange(request(code, authenticatedClient(code)));
		assertThatIllegalStateException().isThrownBy(() -> new TransactionTemplate(this.transactions).execute(tx -> this.verifier.verify(issued.getAccessToken().getTokenValue())));
		assertThatIllegalArgumentException().isThrownBy(() -> this.verifier.verifyForResource(issued.getAccessToken().getTokenValue(), null));
	}

	@ParameterizedTest
	@ValueSource(strings = { "", "http://iam.example", "https://iam.example?query=1", "https://iam.example#fragment", "https://user:secret@iam.example", "https://iam.example:", "https://iam.example:0", "https://iam.example:65536" })
	void issuerMustBeAnExplicitValidHttpsConfiguration(String issuer) {
		assertThatIllegalArgumentException().isThrownBy(() -> new IdentityAccessTokenVerifier(this.online, issuer)).withMessage("An explicit HTTPS issuer at the root path is required");
		assertThatIllegalArgumentException().isThrownBy(() -> new IdentityAccessTokenVerifier(this.online, null));
	}

	private String rewrite(String code, Consumer<Map<String, Object>> claimsChange, Consumer<Map<String, Object>> headerChange, boolean foreignKey, Instant expiry) throws Exception {
		var original = SignedJWT.parse(stored(code).authorization().getAccessToken().getToken().getTokenValue());
		var claims = new LinkedHashMap<>(original.getPayload().toJSONObject()); var header = new LinkedHashMap<>(original.getHeader().toJSONObject());
		claimsChange.accept(claims); headerChange.accept(header);
		var signed = new JWSObject(JWSHeader.parse(header), new Payload(claims));
		var generator = KeyPairGenerator.getInstance("RSA"); generator.initialize(2048);
		RSAPrivateKey privateKey = foreignKey ? (RSAPrivateKey) generator.generateKeyPair().getPrivate() : (RSAPrivateKey) this.keys.signingMaterial().privateKey();
		signed.sign(new RSASSASigner(privateKey)); String value = signed.serialize(); replaceBearer(code, value, expiry); return value;
	}

	private void replaceBearer(String code, String value, Instant expiry) {
		var before = stored(code); var original = before.authorization().getAccessToken(); var token = original.getToken();
		var changed = new OAuth2AccessToken(token.getTokenType(), value, token.getIssuedAt(), expiry == null ? token.getExpiresAt() : expiry, token.getScopes());
		this.authorizations.save(OAuth2Authorization.from(before.authorization()).token(changed, metadata -> metadata.putAll(original.getMetadata())).build(), before.version());
	}

	private OAuth2AccessTokenAuthenticationToken rotate(String token, Set<String> scopes) {
		return (OAuth2AccessTokenAuthenticationToken) new IdentityRefreshTokenProvider(this.applications, this.authorizations, this.bindings, this.refresh, this.keys, this.audits, this.transactions)
				.authenticate(new OAuth2RefreshTokenAuthenticationToken(token, refreshClient(this.clientId, this.secret), scopes, Map.of()));
	}

}
