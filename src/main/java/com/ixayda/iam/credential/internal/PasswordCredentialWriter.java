package com.ixayda.iam.credential.internal;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;
import com.ixayda.iam.user.UserOperations;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
class PasswordCredentialWriter {

	private final JdbcPasswordCredentialRepository repository;

	private final UserOperations users;

	private final PasswordTimeSource timeSource;

	PasswordCredentialWriter(JdbcPasswordCredentialRepository repository, UserOperations users,
			PasswordTimeSource timeSource) {
		this.repository = repository;
		this.users = users;
		this.timeSource = timeSource;
	}

	@Transactional
	void store(TenantId tenantId, UserId userId, String encodedPassword) {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		Objects.requireNonNull(userId, "User ID must not be null");
		Objects.requireNonNull(encodedPassword, "Encoded password must not be null");

		this.users.requireActiveForUpdate(tenantId, userId);
		Optional<PasswordCredential> current = this.repository.findByUserForUpdate(tenantId, userId);
		Instant now = this.timeSource.now();
		if (current.isPresent()) {
			PasswordCredential stored = current.orElseThrow();
			this.repository.update(stored, stored.replaceWith(encodedPassword, now));
		}
		else {
			this.repository.insert(PasswordCredential.initial(tenantId, userId, encodedPassword, now));
		}
	}

}
