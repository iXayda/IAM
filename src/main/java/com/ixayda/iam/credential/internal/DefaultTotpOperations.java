package com.ixayda.iam.credential.internal;

import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;

import com.ixayda.iam.credential.TotpCodeAttempt;
import com.ixayda.iam.credential.TotpCredential;
import com.ixayda.iam.credential.TotpCredentialId;
import com.ixayda.iam.credential.TotpCredentialStatus;
import com.ixayda.iam.credential.TotpEnrollment;
import com.ixayda.iam.credential.TotpOperations;
import com.ixayda.iam.tenant.TenantDisabledException;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.tenant.TenantNotFoundException;
import com.ixayda.iam.user.UserId;
import com.ixayda.iam.user.UserNotActiveException;
import com.ixayda.iam.user.UserNotFoundException;
import com.ixayda.iam.user.UserOperations;
import org.springframework.stereotype.Service;
import org.springframework.transaction.IllegalTransactionStateException;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronizationManager;

@Service
class DefaultTotpOperations implements TotpOperations {

	private final TotpEnrollmentWriter enrollmentWriter;

	private final JdbcTotpCredentialRepository repository;

	private final TotpSecretCipher cipher;

	private final TotpCodeGenerator codeGenerator;

	private final TotpSecretGenerator secretGenerator;

	private final TotpSettingsProperties settings;

	private final TotpTimeSource timeSource;

	private final UserOperations users;

	DefaultTotpOperations(TotpEnrollmentWriter enrollmentWriter, JdbcTotpCredentialRepository repository,
			TotpSecretCipher cipher, TotpCodeGenerator codeGenerator, TotpSecretGenerator secretGenerator,
			TotpSettingsProperties settings, TotpTimeSource timeSource, UserOperations users) {
		this.enrollmentWriter = enrollmentWriter;
		this.repository = repository;
		this.cipher = cipher;
		this.codeGenerator = codeGenerator;
		this.secretGenerator = secretGenerator;
		this.settings = settings;
		this.timeSource = timeSource;
		this.users = users;
	}

	@Override
	public TotpEnrollment beginEnrollment(TenantId tenantId, UserId userId) {
		requireKey(tenantId, userId);
		requireNoTransaction();
		byte[] secret = this.secretGenerator.generate();
		try {
			TotpCredential credential = this.enrollmentWriter.store(tenantId, userId, secret);
			return new TotpEnrollment(credential.id(), credential.enrollmentExpiresAt(), secret);
		}
		finally {
			Arrays.fill(secret, (byte) 0);
		}
	}

	@Override
	@Transactional
	public boolean activate(TenantId tenantId, UserId userId, TotpCredentialId credentialId, TotpCodeAttempt code) {
		requireKey(tenantId, userId);
		Objects.requireNonNull(credentialId, "TOTP credential ID must not be null");
		Objects.requireNonNull(code, "TOTP code attempt must not be null");
		this.users.requireActiveForUpdate(tenantId, userId);
		Optional<StoredTotpCredential> candidate =
				this.repository.findByIdForUpdate(tenantId, userId, credentialId);
		if (candidate.isEmpty() || candidate.orElseThrow().credential().status() != TotpCredentialStatus.PENDING) {
			return false;
		}

		StoredTotpCredential pending = candidate.orElseThrow();
		Instant evaluatedAt = this.timeSource.now();
		if (!pending.credential().isPendingAt(evaluatedAt)) {
			this.repository.revoke(pending, pending.credential().revoke(evaluatedAt));
			return false;
		}
		OptionalLong matchedTimeStep = match(pending, code, evaluatedAt);
		if (matchedTimeStep.isEmpty()) {
			return false;
		}

		Instant transitionAt = evaluatedAt.isBefore(pending.credential().updatedAt())
				? pending.credential().updatedAt() : evaluatedAt;
		this.repository.findActiveByUserForUpdate(tenantId, userId)
			.ifPresent(active -> this.repository.revoke(active, active.credential().revoke(transitionAt)));
		this.repository.activate(pending,
				pending.credential().activate(matchedTimeStep.orElseThrow(), transitionAt));
		return true;
	}

	@Override
	@Transactional(propagation = Propagation.MANDATORY)
	public boolean verify(TenantId tenantId, UserId userId, TotpCodeAttempt code) {
		requireKey(tenantId, userId);
		Objects.requireNonNull(code, "TOTP code attempt must not be null");
		requireReadWriteTransaction();
		Optional<StoredTotpCredential> candidate = this.repository.findActiveByUser(tenantId, userId);
		if (candidate.isEmpty()) {
			return false;
		}

		StoredTotpCredential active = candidate.orElseThrow();
		Instant evaluatedAt = this.timeSource.now();
		OptionalLong matchedTimeStep = match(active, code, evaluatedAt);
		if (matchedTimeStep.isEmpty()) {
			return false;
		}
		try {
			this.users.requireActiveForWrite(tenantId, userId);
		}
		catch (TenantDisabledException | TenantNotFoundException | UserNotActiveException | UserNotFoundException ex) {
			return false;
		}
		Instant transitionAt = evaluatedAt.isBefore(active.credential().updatedAt())
				? active.credential().updatedAt() : evaluatedAt;
		return this.repository.acceptTimeStep(active, matchedTimeStep.orElseThrow(), transitionAt).isPresent();
	}

	@Override
	@Transactional
	public boolean revoke(TenantId tenantId, UserId userId, TotpCredentialId credentialId) {
		requireKey(tenantId, userId);
		Objects.requireNonNull(credentialId, "TOTP credential ID must not be null");
		Optional<StoredTotpCredential> stored =
				this.repository.findByIdForUpdate(tenantId, userId, credentialId);
		if (stored.isEmpty() || stored.orElseThrow().credential().status() == TotpCredentialStatus.REVOKED) {
			return false;
		}
		StoredTotpCredential credential = stored.orElseThrow();
		this.repository.revoke(credential, credential.credential().revoke(this.timeSource.now()));
		return true;
	}

	private OptionalLong match(StoredTotpCredential stored, TotpCodeAttempt code, Instant now) {
		char[] characters = code.copy();
		byte[] secret = null;
		try {
			secret = this.cipher.reveal(stored.protectedSecret(), context(stored.credential()));
			String candidate = new String(characters);
			long currentTimeStep = this.codeGenerator.timeStepAt(now);
			for (int offset = this.settings.allowedClockSkewSteps(); offset >= -this.settings.allowedClockSkewSteps();
					offset--) {
				long timeStep = currentTimeStep + offset;
				if (timeStep >= 0 && this.codeGenerator.matches(secret, timeStep, candidate)) {
					return OptionalLong.of(timeStep);
				}
			}
			return OptionalLong.empty();
		}
		finally {
			if (secret != null) {
				Arrays.fill(secret, (byte) 0);
			}
			Arrays.fill(characters, '\0');
		}
	}

	private static TotpSecretCipher.SecretContext context(TotpCredential credential) {
		return new TotpSecretCipher.SecretContext(credential.tenantId(), credential.userId(), credential.id(),
				credential.algorithm(), credential.digits(), credential.periodSeconds());
	}

	private static void requireKey(TenantId tenantId, UserId userId) {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		Objects.requireNonNull(userId, "User ID must not be null");
	}

	private static void requireReadWriteTransaction() {
		if (!TransactionSynchronizationManager.isActualTransactionActive()
				|| TransactionSynchronizationManager.isCurrentTransactionReadOnly()) {
			throw new IllegalTransactionStateException("TOTP verification requires an existing read-write transaction");
		}
	}

	private static void requireNoTransaction() {
		if (TransactionSynchronizationManager.isActualTransactionActive()) {
			throw new IllegalTransactionStateException("TOTP enrollment must not run inside a database transaction");
		}
	}

}
