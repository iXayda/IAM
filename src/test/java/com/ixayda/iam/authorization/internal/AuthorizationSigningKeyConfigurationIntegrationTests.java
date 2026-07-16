package com.ixayda.iam.authorization.internal;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.Map;

import com.ixayda.iam.ApplicationIntegrationTest;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;

class AuthorizationSigningKeyConfigurationIntegrationTests extends ApplicationIntegrationTest {

	@Autowired
	private AuthorizationServerSettings authorizationServerSettings;

	@Autowired
	private JWKSource<SecurityContext> jwkSource;

	@Autowired
	private JwtEncoder jwtEncoder;

	@Autowired
	private JwtDecoder jwtDecoder;

	@Autowired
	private JdbcClient jdbcClient;

	@Test
	void configuresAFixedIssuerAndRestartStableDatabaseKey() throws Exception {
		assertThat(this.authorizationServerSettings.getIssuer()).isEqualTo("https://issuer.example.test");
		assertThat(this.jdbcClient.sql("SELECT count(*) FROM oauth_signing_keys WHERE status = 'active'")
			.query(Integer.class)
			.single()).isOne();

		String databaseKid = this.jdbcClient.sql("SELECT kid FROM oauth_signing_keys WHERE status = 'active'")
			.query(String.class)
			.single();
		assertThat(databaseKid).matches("[A-Za-z0-9_-]{43}");
		assertThat(this.jdbcClient.sql("""
				SELECT private_key_format = 'PKCS8'
				   AND protection_version = 1
				   AND octet_length(initialization_vector) = 12
				   AND octet_length(private_key_ciphertext) >= 1024
				FROM oauth_signing_keys
				WHERE status = 'active'
				""").query(Boolean.class).single()).isTrue();

		JWKSelector allKeys = new JWKSelector(new JWKMatcher.Builder().build());
		assertThat(this.jwkSource.get(allKeys, null)).singleElement().satisfies(key -> {
			assertThat(key.getKeyID()).isEqualTo(databaseKid);
			assertThat(key.isPrivate()).isFalse();
			assertThat(key.size()).isEqualTo(3072);
			Map<String, Object> publicJwk = key.toJSONObject();
			assertThat(publicJwk).containsKeys("kty", "use", "alg", "kid", "n", "e")
				.doesNotContainKeys("d", "p", "q", "dp", "dq", "qi", "oth");
		});
	}

	@Test
	void signsWithTheActiveKeyAndVerifiesWithPublishedPublicKeys() {
		Instant now = Instant.now();
		JwtClaimsSet claims = JwtClaimsSet.builder()
			.issuer(this.authorizationServerSettings.getIssuer())
			.subject("019cf2eb-c956-75e2-9cf1-9042aaa94001")
			.issuedAt(now)
			.expiresAt(now.plusSeconds(300))
			.build();

		Jwt encoded = this.jwtEncoder.encode(JwtEncoderParameters.from(claims));
		Jwt decoded = this.jwtDecoder.decode(encoded.getTokenValue());

		assertThat(encoded.getHeaders().get("alg")).hasToString("RS256");
		assertThat(encoded.getHeaders().get("kid")).isEqualTo(
				this.jdbcClient.sql("SELECT kid FROM oauth_signing_keys WHERE status = 'active'")
					.query(String.class)
					.single());
		assertThat(decoded.getSubject()).isEqualTo(claims.getSubject());
		assertThat(decoded.getIssuer().toString()).isEqualTo(this.authorizationServerSettings.getIssuer());
	}

	@Test
	void rejectsTokensForAnotherOrMissingIssuer() {
		Instant now = Instant.now();
		JwtClaimsSet wrongIssuer = JwtClaimsSet.builder()
			.issuer("https://other-issuer.example.test")
			.subject("issuer-mismatch")
			.issuedAt(now)
			.expiresAt(now.plusSeconds(300))
			.build();
		JwtClaimsSet missingIssuer = JwtClaimsSet.builder()
			.subject("issuer-missing")
			.issuedAt(now)
			.expiresAt(now.plusSeconds(300))
			.build();

		Jwt wrongIssuerJwt = this.jwtEncoder.encode(JwtEncoderParameters.from(wrongIssuer));
		Jwt missingIssuerJwt = this.jwtEncoder.encode(JwtEncoderParameters.from(missingIssuer));

		org.assertj.core.api.Assertions.assertThatThrownBy(
				() -> this.jwtDecoder.decode(wrongIssuerJwt.getTokenValue()))
			.isInstanceOf(JwtValidationException.class);
		org.assertj.core.api.Assertions.assertThatThrownBy(
				() -> this.jwtDecoder.decode(missingIssuerJwt.getTokenValue()))
			.isInstanceOf(JwtValidationException.class);
	}

}
