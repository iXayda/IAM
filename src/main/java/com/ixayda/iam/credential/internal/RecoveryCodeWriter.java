package com.ixayda.iam.credential.internal;

import java.util.List;

import com.ixayda.iam.credential.CredentialSecurityEvent;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;
import com.ixayda.iam.user.UserOperations;
import org.springframework.stereotype.Component;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.transaction.annotation.Transactional;

@Component
class RecoveryCodeWriter {

	private final JdbcRecoveryCodeRepository repository;

	private final UserOperations users;

	private final ApplicationEventPublisher events;

	RecoveryCodeWriter(JdbcRecoveryCodeRepository repository, UserOperations users, ApplicationEventPublisher events) {
		this.repository = repository;
		this.users = users;
		this.events = events;
	}

	@Transactional
	void replace(TenantId tenantId, UserId userId, List<StoredRecoveryCode> codes) {
		this.users.requireActiveForUpdate(tenantId, userId);
		this.repository.replaceAll(tenantId, userId, codes);
		this.events.publishEvent(new CredentialSecurityEvent(tenantId, userId,
				CredentialSecurityEvent.Type.RECOVERY_CODES_REPLACED, null, codes.getFirst().createdAt()));
	}

}
