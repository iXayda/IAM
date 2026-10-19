package com.ixayda.iam.service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Arrays;
import java.util.Optional;
import java.util.UUID;

import com.ixayda.iam.credential.TotpCodes;
import com.ixayda.iam.credential.TotpRecoveryTokens;
import com.ixayda.iam.credential.TotpSecrets;
import com.ixayda.iam.model.IdentityTotpEnrollment;
import com.ixayda.iam.model.IdentityTotpRecovery;
import com.ixayda.iam.model.IdentityUser;
import com.ixayda.iam.model.MfaRecoveryCodeContext;
import com.ixayda.iam.model.MfaRecoveryCodeSet;
import com.ixayda.iam.model.PasswordAuthenticationContext;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.SecurityAuditEvent.Action;
import com.ixayda.iam.model.TotpAuthenticationContext;
import com.ixayda.iam.repository.IdentityTotpRecoveryRepository;
import com.ixayda.iam.repository.IdentityTotpRepository;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.util.Assert;

/** Password plus a recovery code can authorize only rebuilding a factor, never management access. */
@Service
public class IdentityTotpRecoveries {

	private final IdentityUsers users;
	private final IdentityAuthentications authentications;
	private final IdentityMfaRecoveryCodes recoveryCodes;
	private final MfaRecoveryCodeLimits recoveryLimits;
	private final TotpAuthenticationLimits totpLimits;
	private final IdentityTotpRepository factors;
	private final IdentityTotpRecoveryRepository repository;
	private final TotpRecoveryTokens tokens;
	private final TotpSecrets secrets;
	private final TotpCodes codes;
	private final IdentityBrowserSessions sessions;
	private final SecurityAudits audits;
	private final TransactionTemplate transaction;

	IdentityTotpRecoveries(IdentityUsers users, IdentityAuthentications authentications, IdentityMfaRecoveryCodes recoveryCodes,
			MfaRecoveryCodeLimits recoveryLimits, TotpAuthenticationLimits totpLimits, IdentityTotpRepository factors,
			IdentityTotpRecoveryRepository repository, TotpRecoveryTokens tokens, TotpSecrets secrets, TotpCodes codes,
			IdentityBrowserSessions sessions, SecurityAudits audits, PlatformTransactionManager manager) {
		this.users = users;
		this.authentications = authentications;
		this.recoveryCodes = recoveryCodes;
		this.recoveryLimits = recoveryLimits;
		this.totpLimits = totpLimits;
		this.factors = factors;
		this.repository = repository;
		this.tokens = tokens;
		this.secrets = secrets;
		this.codes = codes;
		this.sessions = sessions;
		this.audits = audits;
		this.transaction = new TransactionTemplate(manager);
	}

	/** Both credentials are verified here; no prior decision object supplied by the caller is accepted. */
	public Optional<IdentityTotpRecovery> begin(UUID userId, String password, String recoveryCode, MfaRecoveryCodeContext context) {
		validateInvocation(userId);
		return this.transaction.execute(status -> beginInTransaction(userId, password, recoveryCode, context));
	}

	/** A trusted session workflow prelocks recovery and password budgets before user/session rows. */
	@Transactional(propagation = Propagation.MANDATORY)
	Optional<IdentityTotpRecovery> beginInTransaction(UUID userId, String password, String recoveryCode, MfaRecoveryCodeContext context) {
		Assert.notNull(context, "Trusted recovery-code context is required");
		this.secrets.requireConfigured();
		// Global lock order: recovery budgets, password budgets, user, code, recovery. Never acquire a new budget after the user lock.
		var attempt = this.recoveryLimits.lock(userId, context);
		if (!attempt.allowed()) {
			this.audits.recordFailure(Action.MFA_RECOVERY_CODE_THROTTLED, null, anonymous(context));
			return Optional.empty();
		}
		var passwordContext = new PasswordAuthenticationContext(context.source(), context.clientAddress(), context.correlationId());
		String username = this.users.findById(userId).map(IdentityUser::username).orElse(null);
		var authenticated = this.authentications.authenticateInTransaction(username, password, passwordContext);
		if (authenticated.isEmpty() || !authenticated.orElseThrow().userId().equals(userId)) {
			// Also bound recovery bucket creation when password authentication is already blocked.
			this.recoveryLimits.failed(attempt);
			return Optional.empty();
		}
		var consumed = this.recoveryCodes.consumeInTransaction(userId, recoveryCode, context);
		if (consumed.isEmpty()) { return Optional.empty(); }
		var decision = consumed.orElseThrow();
		UUID recoveryId = UUID.randomUUID();
		UUID newFactorId = UUID.randomUUID();
		String token = this.tokens.generate();
		byte[] secret = this.secrets.generate();
		try {
			var expiresAt = this.repository.issue(userId, recoveryId, decision.factorId(), newFactorId, decision.generationId(),
					decision.credentialVersion(), this.tokens.digest(userId, recoveryId, token),
					this.secrets.encrypt(userId, newFactorId, secret), this.secrets.keyId());
			this.audits.recordSuccess(Action.TOTP_RECOVERY_STARTED, userId, userAudit(userId, context.source(), context.correlationId()));
			String encoded = this.codes.encodeSecret(secret);
			String uri = "otpauth://totp/IAM:" + userId + "?secret=" + encoded + "&issuer=IAM&algorithm=SHA1&digits=6&period=30";
			return Optional.of(new IdentityTotpRecovery(userId, recoveryId, token,
					new IdentityTotpEnrollment(userId, newFactorId, encoded, uri, expiresAt)));
		}
		finally { Arrays.fill(secret, (byte) 0); }
	}

	/** Activates only the pending factor proven by this recovery token and a new-factor code. */
	public Optional<MfaRecoveryCodeSet> complete(UUID userId, UUID recoveryId, String token, String code, TotpAuthenticationContext context) {
		validateInvocation(userId);
		Assert.notNull(recoveryId, "Recovery id is required");
		return this.transaction.execute(status -> completeInTransaction(userId, recoveryId, token, code, context));
	}

	/** Only trusted workflows may compose recovery with their owning password-session checks. */
	@Transactional(propagation = Propagation.MANDATORY)
	Optional<MfaRecoveryCodeSet> completeInTransaction(UUID userId, UUID recoveryId, String token, String code, TotpAuthenticationContext context) {
		Assert.notNull(context, "Trusted authentication context is required");
		this.secrets.requireConfigured();
		var attempt = this.totpLimits.lock(userId, context);
		var anonymous = new SecurityAuditContext("anonymous", context.source(), context.correlationId());
		if (!attempt.allowed()) {
			this.audits.recordFailure(Action.TOTP_RECOVERY_THROTTLED, null, anonymous);
			return Optional.empty();
		}
		var user = this.users.lockForMfaRecovery(userId);
		var version = user.filter(value -> value.status() == IdentityUser.Status.ACTIVE).flatMap(value -> this.users.passwordVersion(userId));
		var pending = this.repository.find(userId).filter(value -> value.recoveryId().equals(recoveryId)
				&& value.expiresAt().isAfter(value.now()) && value.recoveryCodesCurrent()
				&& version.filter(current -> current == value.credentialVersion()).isPresent());
		if (pending.isPresent() && this.factors.find(userId).filter(value -> value.active()
				&& value.factorId().equals(pending.orElseThrow().oldFactorId())).isPresent()) {
			var recovery = pending.orElseThrow();
			String digest = null;
			try { digest = this.tokens.digest(userId, recoveryId, token); }
			catch (IllegalArgumentException ex) { /* Malformed proof is an ordinary, metered denial. */ }
			if (digest != null && MessageDigest.isEqual(digest.getBytes(StandardCharsets.US_ASCII),
					recovery.tokenDigest().getBytes(StandardCharsets.US_ASCII))) {
				byte[] secret = this.secrets.decrypt(userId, recovery.newFactorId(), recovery.keyId(), recovery.ciphertext());
				try {
					var step = this.codes.match(secret, code, recovery.now(), -1);
					var consumedAt = step.isPresent() ? this.repository.consume(userId, recoveryId, digest, step.getAsLong()) : Optional.<Instant>empty();
					if (consumedAt.isPresent()) {
						long nextVersion = Math.addExact(version.orElseThrow(), 1);
						this.factors.replaceActive(userId, recovery.oldFactorId(), new IdentityTotpRepository.Replacement(
								recovery.newFactorId(), recovery.ciphertext(), recovery.keyId(), recovery.issuedAt(), recovery.expiresAt()),
								step.getAsLong(), consumedAt.orElseThrow(), nextVersion);
						this.users.invalidateAuthentications(userId, version.orElseThrow());
						var audit = userAudit(userId, context.source(), context.correlationId());
						this.sessions.revokeAll(userId, audit);
						var replacementCodes = this.recoveryCodes.issueForVerifiedFactor(userId, recovery.newFactorId(), audit);
						this.totpLimits.succeeded(attempt);
						this.audits.recordSuccess(Action.TOTP_RECOVERY_COMPLETED, userId, audit);
						return Optional.of(replacementCodes);
					}
				}
				finally { Arrays.fill(secret, (byte) 0); }
			}
		}
		this.totpLimits.failed(attempt);
		this.audits.recordFailure(Action.TOTP_RECOVERY_FAILED, user.map(IdentityUser::id).orElse(null), anonymous);
		return Optional.empty();
	}

	@Scheduled(fixedDelayString = "${iam.totp-recovery.cleanup-ms:60000}", initialDelayString = "${iam.totp-recovery.cleanup-ms:60000}")
	public void cleanUpExpiredRecoveries() {
		this.transaction.executeWithoutResult(status -> this.repository.cleanUpExpired());
	}

	private static SecurityAuditContext anonymous(MfaRecoveryCodeContext context) {
		return new SecurityAuditContext("anonymous", context.source(), context.correlationId());
	}

	private static SecurityAuditContext userAudit(UUID userId, String source, UUID correlationId) {
		return new SecurityAuditContext("user:" + userId, source, correlationId);
	}

	private static void validateInvocation(UUID userId) {
		Assert.notNull(userId, "User id is required");
		if (TransactionSynchronizationManager.isActualTransactionActive()) {
			throw new IllegalStateException("TOTP recovery requires an independent transaction");
		}
	}

}
