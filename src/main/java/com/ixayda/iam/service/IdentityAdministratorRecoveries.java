package com.ixayda.iam.service;

import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Optional;
import java.util.UUID;

import com.ixayda.iam.credential.AdministratorRecoveryTokens;
import com.ixayda.iam.credential.TotpCodes;
import com.ixayda.iam.credential.TotpSecrets;
import com.ixayda.iam.model.IdentityAdministratorRecovery;
import com.ixayda.iam.model.IdentityTotpEnrollment;
import com.ixayda.iam.model.IdentityUser;
import com.ixayda.iam.model.MfaRecoveryCodeSet;
import com.ixayda.iam.model.PasswordAuthenticationContext;
import com.ixayda.iam.model.PasswordAuthenticationResult;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.SecurityAuditEvent.Action;
import com.ixayda.iam.model.TotpAuthenticationContext;
import com.ixayda.iam.repository.IdentityAdministratorRecoveryRepository;
import com.ixayda.iam.repository.IdentityAdministratorRepository;
import com.ixayda.iam.repository.IdentityTotpRepository;

import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.util.Assert;

/** Deployment-only recovery after external identity verification; never grants membership or a session. */
@Service
public class IdentityAdministratorRecoveries {

	private final IdentityUsers users;
	private final IdentityAuthentications authentications;
	private final TotpAuthenticationLimits limits;
	private final IdentityAdministratorRepository administrators;
	private final IdentityAdministratorRecoveryRepository repository;
	private final IdentityTotpRepository factors;
	private final AdministratorRecoveryTokens tokens;
	private final TotpSecrets secrets;
	private final TotpCodes codes;
	private final IdentityBrowserSessions sessions;
	private final IdentityAuthorizationRevocations revocations;
	private final IdentityMfaRecoveryCodes recoveryCodes;
	private final SecurityAudits audits;
	private final TransactionTemplate transaction;

	IdentityAdministratorRecoveries(IdentityUsers users, IdentityAuthentications authentications, TotpAuthenticationLimits limits,
			IdentityAdministratorRepository administrators, IdentityAdministratorRecoveryRepository repository, IdentityTotpRepository factors,
			AdministratorRecoveryTokens tokens, TotpSecrets secrets, TotpCodes codes, IdentityBrowserSessions sessions, IdentityAuthorizationRevocations revocations,
			IdentityMfaRecoveryCodes recoveryCodes, SecurityAudits audits, PlatformTransactionManager manager) {
		this.users = users;
		this.authentications = authentications;
		this.limits = limits;
		this.administrators = administrators;
		this.repository = repository;
		this.factors = factors;
		this.tokens = tokens;
		this.secrets = secrets;
		this.codes = codes;
		this.sessions = sessions;
		this.revocations = revocations;
		this.recoveryCodes = recoveryCodes;
		this.audits = audits;
		this.transaction = new TransactionTemplate(manager);
	}

	/** Retains the current factor, recovery codes and sessions until the new factor is proven. */
	public Optional<IdentityAdministratorRecovery> begin(UUID userId, String password, SecurityAuditContext audit) {
		validateInvocation(userId, audit);
		this.secrets.requireConfigured();
		return this.transaction.execute(status -> {
			this.repository.requireDatabaseOwner();
			var attempt = this.limits.lock(userId, authentication(audit));
			if (!attempt.allowed()) { return throttled(audit); }
			var authenticated = authenticate(userId, password, audit);
			if (authenticated.isEmpty()) { return rejected(userId, attempt, audit); }
			var lifecycle = this.administrators.lockLifecycle();
			var factor = this.factors.find(userId).filter(IdentityTotpRepository.Factor::active);
			if (!lifecycle.closed() || this.administrators.find(userId).isEmpty() || factor.isEmpty()) {
				return rejected(userId, attempt, audit);
			}
			UUID recoveryId = UUID.randomUUID();
			UUID factorId = UUID.randomUUID();
			String token = this.tokens.generate();
			byte[] secret = this.secrets.generate();
			try {
				var expiresAt = this.repository.issue(userId, recoveryId, factor.orElseThrow().factorId(), factorId,
						authenticated.orElseThrow().credentialVersion(), this.tokens.digest(userId, recoveryId, token),
						this.secrets.encrypt(userId, factorId, secret), this.secrets.keyId(), audit);
				this.audits.recordSuccess(Action.ADMIN_RECOVERY_STARTED, userId, audit);
				this.repository.requireUnexpired(expiresAt);
				String encoded = this.codes.encodeSecret(secret);
				String uri = "otpauth://totp/IAM:" + userId + "?secret=" + encoded + "&issuer=IAM&algorithm=SHA1&digits=6&period=30";
				return Optional.of(new IdentityAdministratorRecovery(userId, recoveryId, token,
						new IdentityTotpEnrollment(userId, factorId, encoded, uri, expiresAt)));
			}
			finally { Arrays.fill(secret, (byte) 0); }
		});
	}

	/** Rechecks the password, deployment attribution and current membership before the atomic replacement. */
	public Optional<MfaRecoveryCodeSet> complete(UUID userId, UUID recoveryId, String token, String password, String code,
			SecurityAuditContext audit) {
		validateInvocation(userId, audit);
		Assert.notNull(recoveryId, "Recovery id is required");
		this.secrets.requireConfigured();
		return this.transaction.execute(status -> {
			this.repository.requireDatabaseOwner();
			var attempt = this.limits.lock(userId, authentication(audit));
			if (!attempt.allowed()) { return throttled(audit); }
			var authenticated = authenticate(userId, password, audit);
			if (authenticated.isEmpty()) { return rejected(userId, attempt, audit); }
			var lifecycle = this.administrators.lockLifecycle();
			var pending = this.repository.find(userId).filter(value -> value.recoveryId().equals(recoveryId)
					&& value.expiresAt().isAfter(value.now()) && value.audit().equals(audit)
					&& value.credentialVersion() == authenticated.orElseThrow().credentialVersion());
			if (!lifecycle.closed() || this.administrators.find(userId).isEmpty() || pending.isEmpty()) {
				return rejected(userId, attempt, audit);
			}
			var recovery = pending.orElseThrow();
			if (this.factors.find(userId).filter(value -> value.active() && value.factorId().equals(recovery.oldFactorId())).isEmpty()) {
				return rejected(userId, attempt, audit);
			}
			String digest;
			try { digest = this.tokens.digest(userId, recoveryId, token); }
			catch (IllegalArgumentException ex) { return rejected(userId, attempt, audit); }
			if (!MessageDigest.isEqual(digest.getBytes(StandardCharsets.US_ASCII), recovery.tokenDigest().getBytes(StandardCharsets.US_ASCII))) {
				return rejected(userId, attempt, audit);
			}
			byte[] secret = this.secrets.decrypt(userId, recovery.newFactorId(), recovery.keyId(), recovery.ciphertext());
			try {
				var step = this.codes.match(secret, code, recovery.now(), -1);
				var consumedAt = step.isPresent() ? this.repository.consume(userId, recoveryId, digest, step.getAsLong())
						: Optional.<java.time.Instant>empty();
				if (consumedAt.isEmpty()) { return rejected(userId, attempt, audit); }
				this.factors.replaceActive(userId, recovery.oldFactorId(), new IdentityTotpRepository.Replacement(
						recovery.newFactorId(), recovery.ciphertext(), recovery.keyId(), recovery.issuedAt(), recovery.expiresAt()),
						step.getAsLong(), consumedAt.orElseThrow(), Math.addExact(recovery.credentialVersion(), 1));
				this.users.invalidateAuthentications(userId, recovery.credentialVersion());
				this.administrators.advanceRevision(lifecycle.revision());
				this.sessions.revokeAll(userId, audit);
				this.revocations.revokeForUser(userId, audit);
				var replacementCodes = this.recoveryCodes.issueForVerifiedFactor(userId, recovery.newFactorId(), audit);
				this.limits.succeeded(attempt);
				this.audits.recordSuccess(Action.ADMIN_RECOVERY_COMPLETED, userId, audit);
				this.repository.requireUnexpired(recovery.expiresAt());
				return Optional.of(replacementCodes);
			}
			finally { Arrays.fill(secret, (byte) 0); }
		});
	}

	public void cleanUpExpiredRecoveries() {
		this.transaction.executeWithoutResult(status -> {
			this.repository.requireDatabaseOwner();
			this.repository.cleanUpExpired();
		});
	}

	private Optional<PasswordAuthenticationResult> authenticate(UUID userId, String password, SecurityAuditContext audit) {
		String username = this.users.findById(userId).map(IdentityUser::username).orElse(null);
		return this.authentications.authenticateInTransaction(username, password,
				new PasswordAuthenticationContext(audit.source(), InetAddress.getLoopbackAddress(), audit.correlationId()))
				.filter(value -> value.userId().equals(userId));
	}

	private <T> Optional<T> rejected(UUID userId, TotpAuthenticationLimits.Attempt attempt, SecurityAuditContext audit) {
		this.limits.failed(attempt);
		this.audits.recordFailure(Action.ADMIN_RECOVERY_REJECTED, this.users.findById(userId).map(IdentityUser::id).orElse(null), audit);
		return Optional.empty();
	}

	private <T> Optional<T> throttled(SecurityAuditContext audit) {
		this.audits.recordFailure(Action.ADMIN_RECOVERY_THROTTLED, null, audit);
		return Optional.empty();
	}

	private static TotpAuthenticationContext authentication(SecurityAuditContext audit) {
		return new TotpAuthenticationContext(audit.source(), InetAddress.getLoopbackAddress(), audit.correlationId());
	}

	private static void validateInvocation(UUID userId, SecurityAuditContext audit) {
		Assert.notNull(userId, "User id is required");
		Assert.notNull(audit, "Trusted deployment audit context is required");
		if (!audit.actor().matches("deployment:[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}")
				|| !audit.source().matches("deployment:admin-recovery:[a-zA-Z0-9][a-zA-Z0-9._-]{0,31}")) {
			throw new IllegalArgumentException("Deployment operator and authorization reference are required");
		}
		if (TransactionSynchronizationManager.isActualTransactionActive()) {
			throw new IllegalStateException("Administrator recovery requires an independent transaction");
		}
	}

}
