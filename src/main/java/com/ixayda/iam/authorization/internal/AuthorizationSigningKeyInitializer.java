package com.ixayda.iam.authorization.internal;

import java.time.Instant;

import com.nimbusds.jose.jwk.RSAKey;
import org.springframework.stereotype.Component;

@Component
class AuthorizationSigningKeyInitializer {

	private final JdbcAuthorizationSigningKeyRepository repository;

	private final AuthorizationSigningKeyWriter writer;

	private final AuthorizationSigningKeyCodec codec;

	private final AuthorizationSigningKeyTimeSource timeSource;

	AuthorizationSigningKeyInitializer(JdbcAuthorizationSigningKeyRepository repository,
			AuthorizationSigningKeyWriter writer, AuthorizationSigningKeyCodec codec,
			AuthorizationSigningKeyTimeSource timeSource) {
		this.repository = repository;
		this.writer = writer;
		this.codec = codec;
		this.timeSource = timeSource;
	}

	AuthorizationSigningKeyRing initialize() {
		StoredAuthorizationSigningKey active = this.repository.findActive().orElseGet(() -> {
			Instant now = this.timeSource.now();
			return this.writer.loadOrCreate(this.codec.generateActive(now));
		});
		RSAKey activeSigningKey = this.codec.restoreActive(active);
		return new AuthorizationSigningKeyRing(activeSigningKey, java.util.List.of(this.codec.restorePublic(active)));
	}

}
