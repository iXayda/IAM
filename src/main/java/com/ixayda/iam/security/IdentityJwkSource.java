package com.ixayda.iam.security;

import java.util.List;

import com.ixayda.iam.service.IdentitySigningKeys;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

/** Public verification source; no private-key loading or decryption occurs here. */
public final class IdentityJwkSource implements JWKSource<SecurityContext> {

	private final IdentitySigningKeys keys;

	public IdentityJwkSource(IdentitySigningKeys keys) { this.keys = keys; }

	@Override
	public List<JWK> get(JWKSelector selector, SecurityContext context) throws KeySourceException {
		try {
			List<JWK> available = this.keys.findPublicKey().stream().map(key -> (JWK) new RSAKey.Builder(key.publicKey())
					.keyID(key.id().toString()).keyUse(KeyUse.SIGNATURE).algorithm(JWSAlgorithm.RS256).build()).toList();
			return selector.select(new JWKSet(available));
		}
		catch (RuntimeException ex) { throw new KeySourceException("Public signing keys are unavailable"); }
	}

}
