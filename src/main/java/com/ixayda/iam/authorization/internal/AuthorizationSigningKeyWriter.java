package com.ixayda.iam.authorization.internal;

import java.util.Objects;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Service
class AuthorizationSigningKeyWriter {

	private final JdbcAuthorizationSigningKeyRepository repository;

	AuthorizationSigningKeyWriter(JdbcAuthorizationSigningKeyRepository repository) {
		this.repository = repository;
	}

	@Transactional(propagation = Propagation.REQUIRES_NEW, isolation = Isolation.READ_COMMITTED)
	StoredAuthorizationSigningKey loadOrCreate(StoredAuthorizationSigningKey candidate) {
		Objects.requireNonNull(candidate, "Candidate signing key must not be null");
		this.repository.lockKeyRing();
		return this.repository.findActive().orElseGet(() -> {
			this.repository.insertActive(candidate);
			return candidate;
		});
	}

}
