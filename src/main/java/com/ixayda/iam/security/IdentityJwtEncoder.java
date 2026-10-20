package com.ixayda.iam.security;

import java.security.interfaces.RSAPrivateKey;
import java.util.Set;

import com.ixayda.iam.service.IdentitySigningKeys;

import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwtEncodingException;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

/** The trusted issuance transaction owns this signing capability and its persisted result. */
public final class IdentityJwtEncoder implements JwtEncoder {

	private final IdentitySigningKeys keys;

	public IdentityJwtEncoder(IdentitySigningKeys keys) { this.keys = keys; }

	@Override
	public Jwt encode(JwtEncoderParameters parameters) throws JwtEncodingException {
		if (parameters == null) { throw unavailable(); }
		try {
			var header = parameters.getJwsHeader() == null ? JwsHeader.with(SignatureAlgorithm.RS256).type("JWT").build() : parameters.getJwsHeader();
			if (!SignatureAlgorithm.RS256.equals(header.getAlgorithm()) || !Set.of("alg", "typ", "kid").containsAll(header.getHeaders().keySet())
					|| header.getType() != null && !Set.of("JWT", "at+jwt").contains(header.getType())) { throw unavailable(); }
			var material = this.keys.lockForIssuance();
			String id = material.key().id().toString();
			if (header.getKeyId() != null && !id.equals(header.getKeyId())) { throw unavailable(); }
			var signedHeader = JwsHeader.from(header).keyId(id).type(header.getType() == null ? "JWT" : header.getType()).build();
			// A new official encoder per call prevents its private-key cache from outliving the locked database state.
			var encoder = NimbusJwtEncoder.withKeyPair(material.key().publicKey(), (RSAPrivateKey) material.privateKey())
					.algorithm(SignatureAlgorithm.RS256).jwkPostProcessor(key -> key.keyID(id)).build();
			var token = encoder.encode(JwtEncoderParameters.from(signedHeader, parameters.getClaims()));
			if (token.getTokenValue().length() > 16_384) { throw unavailable(); }
			return token;
		}
		catch (RuntimeException ex) { throw unavailable(); }
	}

	private static JwtEncodingException unavailable() { return new JwtEncodingException("Token signing is unavailable"); }

}
