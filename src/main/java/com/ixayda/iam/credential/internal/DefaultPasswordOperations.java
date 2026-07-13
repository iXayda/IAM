package com.ixayda.iam.credential.internal;

import java.util.Objects;
import java.util.Optional;

import com.ixayda.iam.credential.NewPassword;
import com.ixayda.iam.credential.PasswordAttempt;
import com.ixayda.iam.credential.PasswordOperations;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;
import com.ixayda.iam.user.UserOperations;
import org.springframework.stereotype.Service;
import org.springframework.transaction.IllegalTransactionStateException;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronizationManager;

@Service
class DefaultPasswordOperations implements PasswordOperations {

	private final PasswordCredentialWriter writer;

	private final JdbcPasswordCredentialRepository repository;

	private final UserOperations users;

	private final PasswordHashing hashing;

	private final PasswordTimeSource timeSource;

	DefaultPasswordOperations(PasswordCredentialWriter writer, JdbcPasswordCredentialRepository repository,
			UserOperations users, PasswordHashing hashing, PasswordTimeSource timeSource) {
		this.writer = writer;
		this.repository = repository;
		this.users = users;
		this.hashing = hashing;
		this.timeSource = timeSource;
	}

	@Override
	public void setPassword(TenantId tenantId, UserId userId, NewPassword password) {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		Objects.requireNonNull(userId, "User ID must not be null");
		Objects.requireNonNull(password, "New password must not be null");
		String encodedPassword = this.hashing.encode(password);
		this.writer.store(tenantId, userId, encodedPassword);
	}

	@Override
	@Transactional(propagation = Propagation.MANDATORY)
	public boolean verifyPassword(TenantId tenantId, UserId userId, PasswordAttempt attempt) {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		Objects.requireNonNull(userId, "User ID must not be null");
		Objects.requireNonNull(attempt, "Password attempt must not be null");
		requireReadWriteTransaction();

		this.users.requireActive(tenantId, userId);
		Optional<PasswordCredential> candidate = this.repository.findByUser(tenantId, userId);
		if (candidate.isEmpty()) {
			this.hashing.performDummyMatch(attempt);
			return false;
		}
		if (!this.hashing.matches(attempt, candidate.orElseThrow().encodedPassword())) {
			return false;
		}

		PasswordCredential matched = candidate.orElseThrow();
		String preparedUpgrade = prepareUpgrade(matched, attempt);
		this.users.requireActiveForWrite(tenantId, userId);
		Optional<PasswordCredential> locked = this.repository.findByUserForUpdate(tenantId, userId);
		if (locked.isEmpty()) {
			return false;
		}

		PasswordCredential latest = locked.orElseThrow();
		boolean unchanged = sameVersionAndEncoding(matched, latest);
		if (!unchanged && !this.hashing.matches(attempt, latest.encodedPassword())) {
			return false;
		}

		boolean needsUpgrade = unchanged ? preparedUpgrade != null
				: this.hashing.upgradeEncoding(latest.encodedPassword());
		if (needsUpgrade) {
			String encodedPassword = preparedUpgrade != null ? preparedUpgrade : this.hashing.reencode(attempt);
			this.repository.update(latest, latest.replaceWith(encodedPassword, this.timeSource.now()));
		}
		return true;
	}

	private String prepareUpgrade(PasswordCredential credential, PasswordAttempt attempt) {
		return this.hashing.upgradeEncoding(credential.encodedPassword()) ? this.hashing.reencode(attempt) : null;
	}

	private static boolean sameVersionAndEncoding(PasswordCredential first, PasswordCredential second) {
		return first.version() == second.version() && first.encodedPassword().equals(second.encodedPassword());
	}

	private static void requireReadWriteTransaction() {
		if (!TransactionSynchronizationManager.isActualTransactionActive()
				|| TransactionSynchronizationManager.isCurrentTransactionReadOnly()) {
			throw new IllegalTransactionStateException(
					"Password verification requires an existing read-write transaction");
		}
	}

}
