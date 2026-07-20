package com.ixayda.iam.credential.internal;

import java.util.List;

import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;
import com.ixayda.iam.user.UserOperations;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
class RecoveryCodeWriter {

	private final JdbcRecoveryCodeRepository repository;

	private final UserOperations users;

	RecoveryCodeWriter(JdbcRecoveryCodeRepository repository, UserOperations users) {
		this.repository = repository;
		this.users = users;
	}

	@Transactional
	void replace(TenantId tenantId, UserId userId, List<StoredRecoveryCode> codes) {
		this.users.requireActiveForUpdate(tenantId, userId);
		this.repository.replaceAll(tenantId, userId, codes);
	}

}
