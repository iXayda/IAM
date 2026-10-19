package com.ixayda.iam.service;

import java.time.Instant;
import java.util.Arrays;
import java.util.Optional;
import java.util.UUID;

import com.ixayda.iam.credential.TotpCodes;
import com.ixayda.iam.credential.TotpSecrets;
import com.ixayda.iam.model.IdentityTotpEnrollment;
import com.ixayda.iam.model.IdentityTotpVerification;
import com.ixayda.iam.model.IdentityUser;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.SecurityAuditEvent.Action;
import com.ixayda.iam.model.TotpAuthenticationContext;
import com.ixayda.iam.repository.IdentityTotpRepository;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.util.Assert;

/** Internal factor workflows; trusted entries authorize enrollment and bind verification to their password flow. */
@Service
public class IdentityTotps {

	private final IdentityUsers users;
	private final IdentityTotpRepository repository;
	private final TotpCodes codes;
	private final TotpSecrets secrets;
	private final TotpAuthenticationLimits limits;
	private final SecurityAudits audits;
	private final TransactionTemplate transaction;

	IdentityTotps(IdentityUsers users, IdentityTotpRepository repository, TotpCodes codes, TotpSecrets secrets,
			TotpAuthenticationLimits limits, SecurityAudits audits, PlatformTransactionManager manager) {
		this.users = users;
		this.repository = repository;
		this.codes = codes;
		this.secrets = secrets;
		this.limits = limits;
		this.audits = audits;
		this.transaction = new TransactionTemplate(manager);
	}

	public IdentityTotpEnrollment beginEnrollment(UUID userId, SecurityAuditContext audit) {
		validateInvocation(userId);
		Assert.notNull(audit, "Trusted audit context is required");
		this.secrets.requireConfigured();
		return this.transaction.execute(status -> beginEnrollmentInTransaction(userId, audit));
	}

	/** The caller holds its workflow locks and delivers the secret only after its transaction commits. */
	@Transactional(propagation = Propagation.MANDATORY)
	IdentityTotpEnrollment beginEnrollmentInTransaction(UUID userId, SecurityAuditContext audit) {
		Assert.notNull(userId, "User id is required");
		Assert.notNull(audit, "Trusted audit context is required");
		this.secrets.requireConfigured();
		if (this.users.lockById(userId).status() != IdentityUser.Status.ACTIVE) {
			throw new IllegalStateException("TOTP enrollment requires an active user with a password");
		}
		long version = this.users.passwordVersion(userId).orElseThrow(
				() -> new IllegalStateException("TOTP enrollment requires an active user with a password"));
		if (this.repository.find(userId).filter(IdentityTotpRepository.Factor::active).isPresent()) {
			throw new IllegalStateException("An active TOTP factor cannot be replaced through enrollment");
		}
		UUID factorId = UUID.randomUUID();
		byte[] secret = this.secrets.generate();
		try {
			var expires = this.repository.enroll(userId, factorId, this.secrets.encrypt(userId, factorId, secret), this.secrets.keyId(), version);
			this.audits.recordSuccess(Action.TOTP_ENROLLMENT_STARTED, userId, audit);
			String encoded = this.codes.encodeSecret(secret);
			String uri = "otpauth://totp/IAM:" + userId + "?secret=" + encoded + "&issuer=IAM&algorithm=SHA1&digits=6&period=30";
			return new IdentityTotpEnrollment(userId, factorId, encoded, uri, expires);
		}
		finally { Arrays.fill(secret, (byte) 0); }
	}

	@Transactional(propagation = Propagation.MANDATORY)
	boolean hasActiveFactor(UUID userId) {
		return this.repository.find(userId).filter(IdentityTotpRepository.Factor::active).isPresent();
	}

	public boolean cancelEnrollment(UUID userId, UUID factorId, SecurityAuditContext audit) {
		validateInvocation(userId);
		Assert.notNull(factorId, "Factor id is required");
		Assert.notNull(audit, "Trusted audit context is required");
		return this.transaction.execute(status -> cancelEnrollmentInTransaction(userId, factorId, audit));
	}

	@Transactional(propagation = Propagation.MANDATORY)
	boolean cancelEnrollmentInTransaction(UUID userId, UUID factorId, SecurityAuditContext audit) {
		Assert.notNull(userId, "User id is required");
		Assert.notNull(factorId, "Factor id is required");
		Assert.notNull(audit, "Trusted audit context is required");
		this.users.lockById(userId);
		if (!this.repository.cancel(userId, factorId)) { return false; }
		this.audits.recordSuccess(Action.TOTP_ENROLLMENT_CANCELLED, userId, audit);
		return true;
	}

	/** The confirming code is consumed; confirmation alone does not create an MFA session. */
	public boolean confirmEnrollment(UUID userId, UUID factorId, String code, TotpAuthenticationContext context) {
		return evaluate(userId, factorId, code, context, true).isPresent();
	}

	public Optional<IdentityTotpVerification> verify(UUID userId, String code, TotpAuthenticationContext context) {
		return evaluate(userId, null, code, context, false);
	}

	private Optional<IdentityTotpVerification> evaluate(UUID userId, UUID factorId, String code,
			TotpAuthenticationContext context, boolean activate) {
		validateInvocation(userId);
		if (activate) { Assert.notNull(factorId, "Factor id is required"); }
		Assert.notNull(context, "Trusted authentication context is required");
		this.secrets.requireConfigured();
		return this.transaction.execute(status -> evaluateLocked(userId, factorId, code, context, activate));
	}

	/** Joins an internal workflow so factor consumption and its protected operation commit together. */
	@Transactional(propagation = Propagation.MANDATORY)
	Optional<IdentityTotpVerification> verifyInTransaction(UUID userId, String code, TotpAuthenticationContext context) {
		Assert.notNull(userId, "User id is required");
		Assert.notNull(context, "Trusted authentication context is required");
		this.secrets.requireConfigured();
		return evaluateLocked(userId, null, code, context, false);
	}

	/** Factor activation joins its protected workflow; failure rolls both back. */
	@Transactional(propagation = Propagation.MANDATORY)
	Optional<IdentityTotpVerification> confirmEnrollmentInTransaction(UUID userId, UUID factorId, String code,
			TotpAuthenticationContext context) {
		Assert.notNull(userId, "User id is required");
		Assert.notNull(factorId, "Factor id is required");
		Assert.notNull(context, "Trusted authentication context is required");
		this.secrets.requireConfigured();
		return evaluateLocked(userId, factorId, code, context, true);
	}

	private Optional<IdentityTotpVerification> evaluateLocked(UUID userId, UUID factorId, String code,
			TotpAuthenticationContext context, boolean activate) {
		var attempt = this.limits.lock(userId, context);
		var anonymous = new SecurityAuditContext("anonymous", context.source(), context.correlationId());
		if (!attempt.allowed()) {
			this.audits.recordFailure(activate ? Action.TOTP_ENROLLMENT_THROTTLED : Action.TOTP_AUTH_THROTTLED, null, anonymous);
			return Optional.empty();
		}
		var user = this.users.lockForTotp(userId);
		var version = user.filter(value -> value.status() == IdentityUser.Status.ACTIVE)
				.flatMap(value -> this.users.passwordVersion(userId));
		var factor = this.repository.find(userId).filter(value -> (!activate || value.factorId().equals(factorId))
				&& value.active() != activate && (!activate || (value.unexpired() && version.isPresent()
						&& value.enrollmentCredentialVersion() == version.orElseThrow())));
		if (version.isPresent() && factor.isPresent()) {
			var stored = factor.orElseThrow();
			byte[] secret = this.secrets.decrypt(userId, stored.factorId(), stored.keyId(), stored.encryptedSecret());
			try {
				var step = this.codes.match(secret, code, stored.now(), stored.lastUsedStep() == null ? -1 : stored.lastUsedStep());
				Optional<Instant> consumedAt = step.isPresent()
						? this.repository.consume(userId, stored.factorId(), step.getAsLong(), activate) : Optional.empty();
				if (consumedAt.isPresent()) {
					this.limits.succeeded(attempt);
					this.audits.recordSuccess(activate ? Action.TOTP_ENROLLMENT_COMPLETED : Action.TOTP_AUTHENTICATED,
							userId, new SecurityAuditContext("user:" + userId, context.source(), context.correlationId()));
					return Optional.of(new IdentityTotpVerification(userId, stored.factorId(), version.orElseThrow(), step.getAsLong(), consumedAt.orElseThrow(), context.correlationId()));
				}
			}
			finally { Arrays.fill(secret, (byte) 0); }
		}
		this.limits.failed(attempt);
		this.audits.recordFailure(activate ? Action.TOTP_ENROLLMENT_FAILED : Action.TOTP_AUTH_FAILED,
				user.map(IdentityUser::id).orElse(null), anonymous);
		return Optional.empty();
	}

	@Scheduled(fixedDelayString = "${iam.totp.cleanup-ms:60000}", initialDelayString = "${iam.totp.cleanup-ms:60000}")
	public void cleanUpExpiredLimits() {
		this.transaction.executeWithoutResult(status -> this.limits.cleanUpExpired());
	}

	private static void validateInvocation(UUID userId) {
		Assert.notNull(userId, "User id is required");
		if (TransactionSynchronizationManager.isActualTransactionActive()) {
			throw new IllegalStateException("TOTP requires an independent transaction");
		}
	}

}
