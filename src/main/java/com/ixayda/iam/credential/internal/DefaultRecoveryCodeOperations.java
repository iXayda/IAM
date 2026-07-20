package com.ixayda.iam.credential.internal;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import com.ixayda.iam.credential.GeneratedRecoveryCodes;
import com.ixayda.iam.credential.RecoveryCode;
import com.ixayda.iam.credential.RecoveryCodeAttempt;
import com.ixayda.iam.credential.RecoveryCodeOperations;
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
class DefaultRecoveryCodeOperations implements RecoveryCodeOperations {

	private static final int MAX_GENERATION_ATTEMPTS = 100;

	private final RecoveryCodeGenerator generator;

	private final RecoveryCodeHashing hashing;

	private final RecoveryCodeWriter writer;

	private final JdbcRecoveryCodeRepository repository;

	private final RecoveryCodeTimeSource timeSource;

	private final UserOperations users;

	DefaultRecoveryCodeOperations(RecoveryCodeGenerator generator, RecoveryCodeHashing hashing,
			RecoveryCodeWriter writer, JdbcRecoveryCodeRepository repository, RecoveryCodeTimeSource timeSource,
			UserOperations users) {
		this.generator = generator;
		this.hashing = hashing;
		this.writer = writer;
		this.repository = repository;
		this.timeSource = timeSource;
		this.users = users;
	}

	@Override
	public GeneratedRecoveryCodes replace(TenantId tenantId, UserId userId) {
		requireKey(tenantId, userId);
		requireNoTransaction();
		List<RecoveryCode> codes = generateUniqueCodes();
		try {
			Instant createdAt = this.timeSource.now();
			List<StoredRecoveryCode> stored = codes.stream()
				.map(code -> new StoredRecoveryCode(tenantId, userId, code.selector(), this.hashing.encode(code),
						createdAt, null))
				.toList();
			this.writer.replace(tenantId, userId, stored);
			return new GeneratedRecoveryCodes(codes);
		}
		finally {
			codes.forEach(RecoveryCode::close);
		}
	}

	@Override
	@Transactional(propagation = Propagation.MANDATORY)
	public boolean verifyAndConsume(TenantId tenantId, UserId userId, RecoveryCodeAttempt attempt) {
		requireKey(tenantId, userId);
		Objects.requireNonNull(attempt, "Recovery code attempt must not be null");
		requireReadWriteTransaction();
		Optional<StoredRecoveryCode> candidate = this.repository.findAvailable(tenantId, userId, attempt.selector());
		if (candidate.isEmpty()) {
			this.hashing.performDummyMatch(attempt);
			return false;
		}
		StoredRecoveryCode observed = candidate.orElseThrow();
		if (!this.hashing.matches(attempt, observed.encodedCode())) {
			return false;
		}
		try {
			this.users.requireActiveForWrite(tenantId, userId);
		}
		catch (TenantDisabledException | TenantNotFoundException | UserNotActiveException | UserNotFoundException ex) {
			return false;
		}
		return this.repository.consume(observed, this.timeSource.now()).isPresent();
	}

	private List<RecoveryCode> generateUniqueCodes() {
		List<RecoveryCode> codes = new ArrayList<>(GeneratedRecoveryCodes.CODE_COUNT);
		Set<String> selectors = new HashSet<>();
		try {
			for (int attempts = 0; codes.size() < GeneratedRecoveryCodes.CODE_COUNT
					&& attempts < MAX_GENERATION_ATTEMPTS; attempts++) {
				RecoveryCode code = this.generator.generate();
				if (selectors.add(code.selector())) {
					codes.add(code);
				}
				else {
					code.close();
				}
			}
			if (codes.size() != GeneratedRecoveryCodes.CODE_COUNT) {
				throw new IllegalStateException("Unable to generate unique recovery code selectors");
			}
			return codes;
		}
		catch (RuntimeException ex) {
			codes.forEach(RecoveryCode::close);
			throw ex;
		}
	}

	private static void requireKey(TenantId tenantId, UserId userId) {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		Objects.requireNonNull(userId, "User ID must not be null");
	}

	private static void requireReadWriteTransaction() {
		if (!TransactionSynchronizationManager.isActualTransactionActive()
				|| TransactionSynchronizationManager.isCurrentTransactionReadOnly()) {
			throw new IllegalTransactionStateException(
					"Recovery code verification requires an existing read-write transaction");
		}
	}

	private static void requireNoTransaction() {
		if (TransactionSynchronizationManager.isActualTransactionActive()) {
			throw new IllegalTransactionStateException(
					"Recovery code replacement must not run inside a database transaction");
		}
	}

}
