package com.ixayda.iam.service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Arrays;
import java.util.Optional;
import java.util.UUID;

import com.ixayda.iam.credential.TotpCodes;
import com.ixayda.iam.credential.TotpReplacementTokens;
import com.ixayda.iam.credential.TotpSecrets;
import com.ixayda.iam.model.IdentityTotpEnrollment;
import com.ixayda.iam.model.IdentityTotpReplacement;
import com.ixayda.iam.model.IdentityUser;
import com.ixayda.iam.model.MfaRecoveryCodeSet;
import com.ixayda.iam.model.PasswordAuthenticationContext;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.SecurityAuditEvent.Action;
import com.ixayda.iam.model.TotpAuthenticationContext;
import com.ixayda.iam.repository.IdentityTotpReplacementRepository;
import com.ixayda.iam.repository.IdentityTotpRepository;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.util.Assert;

/** Current password and active factor authorize replacing only that factor, never management access. */
@Service
public class IdentityTotpReplacements {

	private final IdentityUsers users;
	private final IdentityAuthentications authentications;
	private final IdentityMfaRecoveryCodes recoveryCodes;
	private final IdentityTotps totps;
	private final TotpAuthenticationLimits totpLimits;
	private final IdentityTotpRepository factors;
	private final IdentityTotpReplacementRepository repository;
	private final TotpReplacementTokens tokens;
	private final TotpSecrets secrets;
	private final TotpCodes codes;
	private final IdentityBrowserSessions sessions;
	private final IdentityAuthorizationRevocations revocations;
	private final SecurityAudits audits;
	private final TransactionTemplate transaction;

	IdentityTotpReplacements(IdentityUsers users, IdentityAuthentications authentications, IdentityMfaRecoveryCodes recoveryCodes,
			IdentityTotps totps, TotpAuthenticationLimits totpLimits, IdentityTotpRepository factors,
			IdentityTotpReplacementRepository repository, TotpReplacementTokens tokens, TotpSecrets secrets, TotpCodes codes,
			IdentityBrowserSessions sessions, IdentityAuthorizationRevocations revocations, SecurityAudits audits, PlatformTransactionManager manager) {
		this.users = users;
		this.authentications = authentications;
		this.recoveryCodes = recoveryCodes;
		this.totps = totps;
		this.totpLimits = totpLimits;
		this.factors = factors;
		this.repository = repository;
		this.tokens = tokens;
		this.secrets = secrets;
		this.codes = codes;
		this.sessions = sessions;
		this.revocations = revocations;
		this.audits = audits;
		this.transaction = new TransactionTemplate(manager);
	}

	/** Verify original credentials here; caller-supplied verification results are never accepted. */
	public Optional<IdentityTotpReplacement> begin(UUID userId, String password, String oldCode, TotpAuthenticationContext context) {
		validateInvocation(userId);
		return this.transaction.execute(status -> beginInTransaction(userId, password, oldCode, context));
	}

	/** A trusted session workflow prelocks both budgets before its user/session rows. */
	@Transactional(propagation = Propagation.MANDATORY)
	Optional<IdentityTotpReplacement> beginInTransaction(UUID userId, String password, String oldCode, TotpAuthenticationContext context) {
		Assert.notNull(context, "Trusted authentication context is required");
		this.secrets.requireConfigured();
		// Prelock TOTP budgets before password budgets/user; verification only reenters these same budget locks.
		var attempt = this.totpLimits.lock(userId, context);
		if (!attempt.allowed()) {
			this.audits.recordFailure(Action.TOTP_REPLACEMENT_THROTTLED, null, anonymous(context));
			return Optional.empty();
		}
		var passwordContext = new PasswordAuthenticationContext(context.source(), context.clientAddress(), context.correlationId());
		String username = this.users.findById(userId).map(IdentityUser::username).orElse(null);
		var authenticated = this.authentications.authenticateInTransaction(username, password, passwordContext);
		if (authenticated.isEmpty() || !authenticated.orElseThrow().userId().equals(userId)) {
			// Bound account-bucket creation even when the shared password source is already blocked.
			this.totpLimits.failed(attempt);
			return Optional.empty();
		}
		var verified = this.totps.verifyInTransaction(userId, oldCode, context);
		if (verified.isEmpty()) { return Optional.empty(); }
		var decision = verified.orElseThrow();
		UUID replacementId = UUID.randomUUID();
		UUID newFactorId = UUID.randomUUID();
		String token = this.tokens.generate();
		byte[] secret = this.secrets.generate();
		try {
			var expiresAt = this.repository.issue(userId, replacementId, decision.factorId(), newFactorId,
					decision.credentialVersion(), this.tokens.digest(userId, replacementId, token),
					this.secrets.encrypt(userId, newFactorId, secret), this.secrets.keyId());
			this.audits.recordSuccess(Action.TOTP_REPLACEMENT_STARTED, userId, userAudit(userId, context.source(), context.correlationId()));
			String encoded = this.codes.encodeSecret(secret);
			String uri = "otpauth://totp/IAM:" + userId + "?secret=" + encoded + "&issuer=IAM&algorithm=SHA1&digits=6&period=30";
			return Optional.of(new IdentityTotpReplacement(userId, replacementId, token,
					new IdentityTotpEnrollment(userId, newFactorId, encoded, uri, expiresAt)));
		}
		finally { Arrays.fill(secret, (byte) 0); }
	}

	/** Activates only the pending factor proven by this replacement token and a new-factor code. */
	public Optional<MfaRecoveryCodeSet> complete(UUID userId, UUID replacementId, String token, String code, TotpAuthenticationContext context) {
		validateInvocation(userId);
		Assert.notNull(replacementId, "Replacement id is required");
		return this.transaction.execute(status -> completeInTransaction(userId, replacementId, token, code, context));
	}

	/** Only trusted workflows may compose factor replacement with their owning-session checks. */
	@Transactional(propagation = Propagation.MANDATORY)
	Optional<MfaRecoveryCodeSet> completeInTransaction(UUID userId, UUID replacementId, String token, String code, TotpAuthenticationContext context) {
		Assert.notNull(context, "Trusted authentication context is required");
		this.secrets.requireConfigured();
		var attempt = this.totpLimits.lock(userId, context);
		var anonymous = new SecurityAuditContext("anonymous", context.source(), context.correlationId());
		if (!attempt.allowed()) {
			this.audits.recordFailure(Action.TOTP_REPLACEMENT_THROTTLED, null, anonymous);
			return Optional.empty();
		}
		var user = this.users.lockForTotp(userId);
		var version = user.filter(value -> value.status() == IdentityUser.Status.ACTIVE).flatMap(value -> this.users.passwordVersion(userId));
		var pending = this.repository.find(userId).filter(value -> value.replacementId().equals(replacementId)
				&& value.expiresAt().isAfter(value.now())
				&& version.filter(current -> current == value.credentialVersion()).isPresent());
		if (pending.isPresent() && this.factors.find(userId).filter(value -> value.active()
				&& value.factorId().equals(pending.orElseThrow().oldFactorId())).isPresent()) {
			var replacement = pending.orElseThrow();
			String digest = null;
			try { digest = this.tokens.digest(userId, replacementId, token); }
			catch (IllegalArgumentException ex) { /* Malformed proof is an ordinary, metered denial. */ }
			if (digest != null && MessageDigest.isEqual(digest.getBytes(StandardCharsets.US_ASCII),
					replacement.tokenDigest().getBytes(StandardCharsets.US_ASCII))) {
				byte[] secret = this.secrets.decrypt(userId, replacement.newFactorId(), replacement.keyId(), replacement.ciphertext());
				try {
					var step = this.codes.match(secret, code, replacement.now(), -1);
					var consumedAt = step.isPresent() ? this.repository.consume(userId, replacementId, digest, step.getAsLong()) : Optional.<Instant>empty();
					if (consumedAt.isPresent()) {
						long nextVersion = Math.addExact(version.orElseThrow(), 1);
						this.factors.replaceActive(userId, replacement.oldFactorId(), new IdentityTotpRepository.Replacement(
								replacement.newFactorId(), replacement.ciphertext(), replacement.keyId(), replacement.issuedAt(), replacement.expiresAt()),
								step.getAsLong(), consumedAt.orElseThrow(), nextVersion);
						this.users.invalidateAuthentications(userId, version.orElseThrow());
						var audit = userAudit(userId, context.source(), context.correlationId());
						this.sessions.revokeAll(userId, audit);
						this.revocations.revokeForUser(userId, audit);
						var replacementCodes = this.recoveryCodes.issueForVerifiedFactor(userId, replacement.newFactorId(), audit);
						this.totpLimits.succeeded(attempt);
						this.audits.recordSuccess(Action.TOTP_REPLACEMENT_COMPLETED, userId, audit);
						return Optional.of(replacementCodes);
					}
				}
				finally { Arrays.fill(secret, (byte) 0); }
			}
		}
		this.totpLimits.failed(attempt);
		this.audits.recordFailure(Action.TOTP_REPLACEMENT_FAILED, user.map(IdentityUser::id).orElse(null), anonymous);
		return Optional.empty();
	}

	@Scheduled(fixedDelayString = "${iam.totp-replacement.cleanup-ms:60000}", initialDelayString = "${iam.totp-replacement.cleanup-ms:60000}")
	public void cleanUpExpiredReplacements() {
		this.transaction.executeWithoutResult(status -> this.repository.cleanUpExpired());
	}

	private static SecurityAuditContext anonymous(TotpAuthenticationContext context) {
		return new SecurityAuditContext("anonymous", context.source(), context.correlationId());
	}

	private static SecurityAuditContext userAudit(UUID userId, String source, UUID correlationId) {
		return new SecurityAuditContext("user:" + userId, source, correlationId);
	}

	private static void validateInvocation(UUID userId) {
		Assert.notNull(userId, "User id is required");
		if (TransactionSynchronizationManager.isActualTransactionActive()) {
			throw new IllegalStateException("TOTP replacement requires an independent transaction");
		}
	}

}
