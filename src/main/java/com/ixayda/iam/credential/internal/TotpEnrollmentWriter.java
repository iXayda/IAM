package com.ixayda.iam.credential.internal;

import java.time.Instant;
import java.util.Objects;

import com.ixayda.iam.credential.TotpCredential;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;
import com.ixayda.iam.user.UserOperations;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
class TotpEnrollmentWriter {

	private final JdbcTotpCredentialRepository repository;

	private final TotpSecretCipher cipher;

	private final UserOperations users;

	private final TotpSettingsProperties settings;

	private final TotpTimeSource timeSource;

	TotpEnrollmentWriter(JdbcTotpCredentialRepository repository, TotpSecretCipher cipher, UserOperations users,
			TotpSettingsProperties settings, TotpTimeSource timeSource) {
		this.repository = repository;
		this.cipher = cipher;
		this.users = users;
		this.settings = settings;
		this.timeSource = timeSource;
	}

	@Transactional
	TotpCredential store(TenantId tenantId, UserId userId, byte[] secret) {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		Objects.requireNonNull(userId, "User ID must not be null");
		Objects.requireNonNull(secret, "TOTP enrollment secret must not be null");
		this.users.requireActiveForUpdate(tenantId, userId);
		Instant now = this.timeSource.now();
		this.repository.findPendingByUserForUpdate(tenantId, userId)
			.ifPresent(pending -> this.repository.revoke(pending, pending.credential().revoke(now)));

		TotpCredential credential = TotpCredential.pending(tenantId, userId, now,
				now.plus(this.settings.enrollmentTtl()));
		TotpSecretCipher.SecretContext context = new TotpSecretCipher.SecretContext(tenantId, userId, credential.id(),
				credential.algorithm(), credential.digits(), credential.periodSeconds());
		TotpSecretCipher.ProtectedTotpSecret protectedSecret = this.cipher.protect(secret, context);
		this.repository.insert(new StoredTotpCredential(credential, protectedSecret));
		return credential;
	}

}
