package com.ixayda.iam.security;

import java.util.Set;
import java.util.UUID;

import com.ixayda.iam.IdentityProtocolTestSupport;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.service.IdentityAccessTokens;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jwt.SignedJWT;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationToken;

import static org.assertj.core.api.Assertions.*;

class IdentitySigningKeyRotationIntegrationTests extends IdentityProtocolTestSupport {

	@Autowired private IdentityAccessTokens online;

	@AfterEach
	void resetSigningState() {
		this.jdbc.sql("TRUNCATE iam_restore_release,iam_signing_key,iam_signing_key_state").update();
		this.jdbc.sql("INSERT INTO iam_signing_key_state(singleton) VALUES(1)").update();
	}

	@Test
	void existingAccessAndIdTokensStillVerifyWhileRefreshAndNewCodeExchangeUseTheNewKey() throws Exception {
		String code = code(Set.of("openid", "profile", "offline_access")); var initial = exchange(request(code, authenticatedClient(code)));
		String pending = code(Set.of("openid")); var verifier = new IdentityAccessTokenVerifier(this.online, "https://iam.example");
		var family = this.refresh.findByAuthorization(stored(code).authorization()).orElseThrow();
		var next = this.keys.rotate(this.signing.id(), audit());
		assertThat(this.refresh.findByAuthorization(stored(code).authorization())).contains(family);
		assertThat(verifier.verify(initial.getAccessToken().getTokenValue())).isPresent();
		verified(initial.getAdditionalParameters().get("id_token").toString(), "JWT");
		var jwks = new IdentityJwkSource(this.keys).get(new JWKSelector(new JWKMatcher.Builder().algorithm(JWSAlgorithm.RS256).build()), null);
		assertThat(jwks).extracting(key -> key.getKeyID()).contains(this.signing.id().toString(), next.id().toString());
		assertThat(jwks).allSatisfy(key -> assertThat(key.isPrivate()).isFalse());
		this.signing = next;
		var fresh = exchange(request(pending, authenticatedClient(pending)));
		verified(fresh.getAccessToken().getTokenValue(), "at+jwt"); verified(fresh.getAdditionalParameters().get("id_token").toString(), "JWT");
		var refreshRequest = new OAuth2RefreshTokenAuthenticationToken(initial.getRefreshToken().getTokenValue(), refreshClient(this.clientId, this.secret), Set.of(), java.util.Map.of());
		refreshRequest.setDetails(new IdentityRefreshTokenProvider.RequestEvidence(UUID.randomUUID()));
		var provider = new IdentityRefreshTokenProvider(this.applications, this.authorizations, this.bindings, this.refresh, this.keys, this.audits, this.transactions);
		var renewed = (OAuth2AccessTokenAuthenticationToken) provider.authenticate(refreshRequest);
		verified(renewed.getAccessToken().getTokenValue(), "at+jwt"); verified(renewed.getAdditionalParameters().get("id_token").toString(), "JWT");
		assertThat(verifier.verify(renewed.getAccessToken().getTokenValue())).isPresent();
	}

	@Test
	void noEncodingPathCanSelectTheRetiredKidEvenWhileItsSignatureRemainsValid() throws Exception {
		var original = this.keys.signingMaterial(); String code = code(Set.of("openid")); var issued = exchange(request(code, authenticatedClient(code)));
		this.keys.rotate(this.signing.id(), audit());
		var claims = org.springframework.security.oauth2.jwt.JwtClaimsSet.builder().issuer("https://iam.example").subject(this.userId.toString())
				.issuedAt(java.time.Instant.now()).expiresAt(java.time.Instant.now().plusSeconds(300)).build();
		var header = org.springframework.security.oauth2.jwt.JwsHeader.with(org.springframework.security.oauth2.jose.jws.SignatureAlgorithm.RS256).keyId(this.signing.id().toString()).build();
		assertThatThrownBy(() -> new org.springframework.transaction.support.TransactionTemplate(this.transactions).execute(tx ->
				new IdentityJwtEncoder(this.keys).encode(org.springframework.security.oauth2.jwt.JwtEncoderParameters.from(header, claims))))
				.isInstanceOf(org.springframework.security.oauth2.jwt.JwtEncodingException.class).hasMessage("Token signing is unavailable").hasNoCause();
		assertThat(SignedJWT.parse(issued.getAccessToken().getTokenValue()).verify(new RSASSAVerifier(original.key().publicKey()))).isTrue();
	}

	private static SecurityAuditContext audit() { return new SecurityAuditContext("deployment:operator-1", "deployment:signing-rotation:CHANGE-123", UUID.randomUUID()); }
}
