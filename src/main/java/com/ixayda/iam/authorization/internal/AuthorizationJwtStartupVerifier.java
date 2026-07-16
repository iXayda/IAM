package com.ixayda.iam.authorization.internal;

import java.time.Instant;
import java.util.List;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.stereotype.Component;

@Component
class AuthorizationJwtStartupVerifier implements InitializingBean {

	private static final String SUBJECT = "authorization-signing-key-startup-self-test";

	private final AuthorizationSigningKeyRing keyRing;

	private final JWKSource<SecurityContext> jwkSource;

	private final JwtEncoder encoder;

	private final JwtDecoder decoder;

	private final AuthorizationServerSettings settings;

	AuthorizationJwtStartupVerifier(AuthorizationSigningKeyRing keyRing, JWKSource<SecurityContext> jwkSource,
			JwtEncoder encoder, JwtDecoder decoder, AuthorizationServerSettings settings) {
		this.keyRing = keyRing;
		this.jwkSource = jwkSource;
		this.encoder = encoder;
		this.decoder = decoder;
		this.settings = settings;
	}

	@Override
	public void afterPropertiesSet() {
		try {
			Instant now = Instant.now();
			JwtClaimsSet claims = JwtClaimsSet.builder()
				.issuer(this.settings.getIssuer())
				.subject(SUBJECT)
				.issuedAt(now)
				.expiresAt(now.plusSeconds(60))
				.build();
			Jwt encoded = this.encoder.encode(JwtEncoderParameters.from(claims));
			String activeKid = this.keyRing.activeSigningKey().getKeyID();
			if (!activeKid.equals(encoded.getHeaders().get("kid"))) {
				throw new IllegalStateException("Authorization JWT self-test selected an unexpected signing key");
			}
			Jwt decoded = this.decoder.decode(encoded.getTokenValue());
			if (!SUBJECT.equals(decoded.getSubject()) || decoded.getIssuer() == null
					|| !this.settings.getIssuer().equals(decoded.getIssuer().toString())) {
				throw new IllegalStateException("Authorization JWT self-test claims did not round-trip");
			}

			List<JWK> published = this.jwkSource
				.get(new JWKSelector(new JWKMatcher.Builder().build()), null);
			long matchingPublicKeys = published.stream()
				.filter(key -> activeKid.equals(key.getKeyID()) && !key.isPrivate())
				.count();
			if (matchingPublicKeys != 1 || published.stream().anyMatch(JWK::isPrivate)) {
				throw new IllegalStateException("Authorization JWK source self-test failed");
			}
		}
		catch (IllegalStateException exception) {
			throw exception;
		}
		catch (Exception exception) {
			throw new IllegalStateException("Authorization JWT startup self-test failed", exception);
		}
	}

}
