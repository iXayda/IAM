package com.ixayda.iam.service;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Optional;
import java.util.UUID;

import com.ixayda.iam.credential.MfaRecoveryCodes;
import com.ixayda.iam.model.IdentityUser;
import com.ixayda.iam.model.MfaRecoveryCodeConsumption;
import com.ixayda.iam.model.MfaRecoveryCodeSet;
import com.ixayda.iam.model.MfaRecoveryCodeContext;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.SecurityAuditEvent.Action;
import com.ixayda.iam.model.TotpAuthenticationContext;
import com.ixayda.iam.repository.IdentityMfaRecoveryCodeRepository;
import com.ixayda.iam.repository.IdentityTotpRepository;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.util.Assert;

/** Trusted internal code workflows; consumption never grants MFA or management permission. */
@Service
public class IdentityMfaRecoveryCodes {

	private final IdentityUsers users;
	private final IdentityBrowserSessions sessions;
	private final TotpAuthenticationLimits totpLimits;
	private final IdentityTotps totps;
	private final IdentityTotpRepository factors;
	private final IdentityMfaRecoveryCodeRepository repository;
	private final MfaRecoveryCodes codes;
	private final MfaRecoveryCodeLimits limits;
	private final SecurityAudits audits;
	private final TransactionTemplate transaction;

	IdentityMfaRecoveryCodes(IdentityUsers users, IdentityBrowserSessions sessions, TotpAuthenticationLimits totpLimits,
			IdentityTotps totps, IdentityTotpRepository factors,
			IdentityMfaRecoveryCodeRepository repository, MfaRecoveryCodes codes, MfaRecoveryCodeLimits limits,
			SecurityAudits audits, PlatformTransactionManager manager) {
		this.users = users;
		this.sessions = sessions;
		this.totpLimits = totpLimits;
		this.totps = totps;
		this.factors = factors;
		this.repository = repository;
		this.codes = codes;
		this.limits = limits;
		this.audits = audits;
		this.transaction = new TransactionTemplate(manager);
	}

	/** A fresh active-factor verification and replacement of the entire code set commit atomically. */
	public Optional<MfaRecoveryCodeSet> issue(UUID userId, String totpCode, TotpAuthenticationContext context) {
		validateInvocation(userId);
		Assert.notNull(context, "Trusted authentication context is required");
		return this.transaction.execute(status -> {
			var verified = this.totps.verifyInTransaction(userId, totpCode, context);
			if (verified.isEmpty()) { return Optional.empty(); }
			var verification = verified.orElseThrow();
			return Optional.of(issueForVerifiedFactor(userId, verification.factorId(),
					new SecurityAuditContext("user:" + userId, context.source(), context.correlationId())));
		});
	}

	/** Revalidates the owning password session and consumes fresh TOTP before replacing its recovery codes. */
	public Result issueForSession(UUID userId, String sessionId, long credentialVersion, long authenticatedAt,
			String totpCode, TotpAuthenticationContext context, Runnable persistSession) {
		validateInvocation(userId);
		Assert.hasText(sessionId, "Authenticated session id is required");
		Assert.notNull(context, "Trusted authentication context is required");
		Assert.notNull(persistSession, "Session persistence is required");
		return this.transaction.execute(status -> {
			// Shared TOTP source/account budgets precede the user and owning browser session locks.
			var attempt = this.totpLimits.lock(userId, context);
			if (!attempt.allowed()) {
				this.audits.recordFailure(Action.TOTP_AUTH_THROTTLED, null,
						new SecurityAuditContext("anonymous", context.source(), context.correlationId()));
				return new Result(Status.THROTTLED, null);
			}
			var user = this.users.lockForTotp(userId);
			var expiry = this.sessions.lockOwnedSessionExpiry(userId, sessionId);
			if (user.filter(value -> value.status() == IdentityUser.Status.ACTIVE).isEmpty() || expiry.isEmpty()
					|| !this.sessions.isAuthenticationCurrent(userId, authenticatedAt, credentialVersion)) {
				return new Result(Status.INVALID_SESSION, null);
			}
			var verified = this.totps.verifyInTransaction(userId, totpCode, context);
			if (verified.isEmpty()) { return new Result(Status.REJECTED, null); }
			var factor = verified.orElseThrow();
			if (factor.credentialVersion() != credentialVersion) {
				throw new IllegalStateException("Password authentication is no longer current");
			}
			var replacement = issueForVerifiedFactor(userId, factor.factorId(),
					new SecurityAuditContext("user:" + userId, context.source(), context.correlationId()));
			// Spring Session writes join this transaction; a later finalizer cannot retry a rolled-back save.
			persistSession.run();
			if (!this.sessions.isAuthenticationCurrent(userId, authenticatedAt, credentialVersion)
					|| !this.sessions.isWithinSessionDeadline(authenticatedAt, expiry.orElseThrow())
					|| !this.sessions.lockOwnedSession(userId, sessionId)) {
				throw new IllegalStateException("Password session expired during recovery code issuance");
			}
			return new Result(Status.ISSUED, replacement);
		});
	}

	/** Internal workflow already verified this factor while holding the user lock. */
	@Transactional(propagation = Propagation.MANDATORY)
	MfaRecoveryCodeSet issueForVerifiedFactor(UUID userId, UUID factorId, SecurityAuditContext audit) {
		Assert.notNull(audit, "Trusted audit context is required");
		if (this.users.lockById(userId).status() != IdentityUser.Status.ACTIVE
				|| this.users.passwordVersion(userId).isEmpty()
				|| this.factors.find(userId).filter(value -> value.active() && value.factorId().equals(factorId)).isEmpty()) {
			throw new IllegalStateException("Recovery codes require the verified active factor");
		}
		UUID generationId = UUID.randomUUID();
		var plaintext = new ArrayList<String>(10);
		var digests = new HashSet<String>();
		for (int index = 0; index < 10; index++) {
			String code = this.codes.generate();
			if (!digests.add(this.codes.digest(userId, factorId, code))) {
				throw new IllegalStateException("Duplicate MFA recovery credential generated");
			}
			plaintext.add(code);
		}
		var issuedAt = this.repository.replace(userId, factorId, generationId, digests.stream().toList());
		this.audits.recordSuccess(Action.MFA_RECOVERY_CODES_GENERATED, userId, audit);
		return new MfaRecoveryCodeSet(userId, factorId, generationId, plaintext, issuedAt);
	}

	/** The trusted caller binds the user to its password-authenticated recovery flow. */
	public Optional<MfaRecoveryCodeConsumption> consume(UUID userId, String code, MfaRecoveryCodeContext context) {
		validateInvocation(userId);
		Assert.notNull(context, "Trusted recovery context is required");
		return this.transaction.execute(status -> consumeInTransaction(userId, code, context));
	}

	/** Recovery issuance prelocks the same recovery budgets before password/user locks. */
	@Transactional(propagation = Propagation.MANDATORY)
	Optional<MfaRecoveryCodeConsumption> consumeInTransaction(UUID userId, String code, MfaRecoveryCodeContext context) {
		Assert.notNull(userId, "User id is required");
		Assert.notNull(context, "Trusted recovery context is required");
		var attempt = this.limits.lock(userId, context);
		var anonymous = new SecurityAuditContext("anonymous", context.source(), context.correlationId());
		if (!attempt.allowed()) {
			this.audits.recordFailure(Action.MFA_RECOVERY_CODE_THROTTLED, null, anonymous);
			return Optional.empty();
		}
		var user = this.users.lockForMfaRecovery(userId);
		var version = user.filter(value -> value.status() == IdentityUser.Status.ACTIVE)
				.flatMap(value -> this.users.passwordVersion(userId));
		var factor = this.factors.find(userId).filter(IdentityTotpRepository.Factor::active);
		if (version.isPresent() && factor.isPresent()) {
			String digest = null;
			try { digest = this.codes.digest(userId, factor.orElseThrow().factorId(), code); }
			catch (IllegalArgumentException ex) { /* Malformed credentials consume the ordinary failure budget. */ }
			if (digest != null) {
				var consumed = this.repository.consume(userId, factor.orElseThrow().factorId(), digest);
				if (consumed.isPresent()) {
					this.limits.succeeded(attempt);
					this.audits.recordSuccess(Action.MFA_RECOVERY_CODE_CONSUMED, userId,
							new SecurityAuditContext("user:" + userId, context.source(), context.correlationId()));
					return Optional.of(new MfaRecoveryCodeConsumption(userId, factor.orElseThrow().factorId(),
							consumed.orElseThrow().generationId(), version.orElseThrow(), consumed.orElseThrow().consumedAt(),
							context.correlationId()));
				}
			}
		}
		this.limits.failed(attempt);
		this.audits.recordFailure(Action.MFA_RECOVERY_CODE_FAILED, user.map(IdentityUser::id).orElse(null), anonymous);
		return Optional.empty();
	}

	@Scheduled(fixedDelayString = "${iam.mfa-recovery.cleanup-ms:60000}", initialDelayString = "${iam.mfa-recovery.cleanup-ms:60000}")
	public void cleanUpExpiredLimits() {
		this.transaction.executeWithoutResult(status -> this.limits.cleanUpExpired());
	}

	public enum Status { ISSUED, REJECTED, THROTTLED, INVALID_SESSION }

	public record Result(Status status, MfaRecoveryCodeSet codeSet) { }

	private static void validateInvocation(UUID userId) {
		Assert.notNull(userId, "User id is required");
		if (TransactionSynchronizationManager.isActualTransactionActive()) {
			throw new IllegalStateException("MFA recovery codes require an independent transaction");
		}
	}

}
