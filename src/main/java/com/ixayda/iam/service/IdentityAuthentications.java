package com.ixayda.iam.service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Optional;
import java.util.UUID;

import com.ixayda.iam.credential.PasswordHasher;
import com.ixayda.iam.model.IdentityUser;
import com.ixayda.iam.model.PasswordAuthenticationContext;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.SecurityAuditEvent.Action;
import com.ixayda.iam.repository.PasswordAuthenticationLimitRepository;

import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.util.Assert;

/** Transactional password decisions; the authentication adapter rejects ambient transactions. */
@Service
public class IdentityAuthentications {

	private final IdentityUsers users;

	private final PasswordHasher passwords;

	private final PasswordAuthenticationLimitRepository repository;

	private final SecurityAudits audits;

	private final String placeholderHash;

	private final TransactionTemplate transaction;

	IdentityAuthentications(IdentityUsers users, PasswordHasher passwords, PasswordAuthenticationLimitRepository repository,
			SecurityAudits audits, PlatformTransactionManager transactionManager) {
		this.users = users;
		this.passwords = passwords;
		this.repository = repository;
		this.audits = audits;
		this.transaction = new TransactionTemplate(transactionManager);
		this.placeholderHash = passwords.hash(UUID.randomUUID().toString(), "iam-authentication-placeholder");
	}

	/** Ordinary denial is a result so failure counters and failure audit commit before the adapter throws. */
	public Optional<IdentityUser> authenticate(String username, String password, PasswordAuthenticationContext context) {
		Assert.notNull(context, "Trusted authentication context is required");
		if (TransactionSynchronizationManager.isActualTransactionActive()) {
			throw new IllegalStateException("Password authentication requires an independent transaction");
		}
		return this.transaction.execute(status -> evaluate(username, password, context));
	}

	private Optional<IdentityUser> evaluate(String username, String password, PasswordAuthenticationContext context) {
		String account = normalizeAccount(username);
		String sourceKey = digest("password-authentication:source:", addressBytes(context));
		String accountKey = digest("password-authentication:account:", account.getBytes(StandardCharsets.US_ASCII));
		int sourceFailures = this.repository.lockLimit("source", sourceKey, 300);
		SecurityAuditContext anonymous = new SecurityAuditContext("anonymous", context.source(), context.correlationId());
		// Short-circuit a blocked source before creating, resetting, or locking an account bucket.
		if (sourceFailures >= 50 || this.repository.lockLimit("account", accountKey, 900) >= 10) {
			this.audits.recordFailure(Action.PASSWORD_AUTH_THROTTLED, null, anonymous);
			return Optional.empty();
		}
		Optional<IdentityUser> user = account.equals("<invalid>") ? Optional.empty() : this.users.lockForPasswordAuthentication(account);
		Optional<String> storedHash = user.flatMap(value -> this.users.passwordHash(value.id()));
		boolean matches = this.passwords.matches(password, storedHash.orElse(this.placeholderHash));
		if (matches && storedHash.isPresent() && user.orElseThrow().status() == IdentityUser.Status.ACTIVE) {
			IdentityUser authenticated = user.orElseThrow();
			this.repository.clearAccount(accountKey);
			this.audits.recordSuccess(Action.PASSWORD_AUTHENTICATED, authenticated.id(),
					new SecurityAuditContext("user:" + authenticated.id(), context.source(), context.correlationId()));
			return user;
		}
		this.repository.recordFailure("source", sourceKey);
		this.repository.recordFailure("account", accountKey);
		this.audits.recordFailure(Action.PASSWORD_AUTH_FAILED, user.map(IdentityUser::id).orElse(null), anonymous);
		return Optional.empty();
	}

	private static String normalizeAccount(String username) {
		return username != null && username.length() >= 3 && username.length() <= 64
				&& username.matches("[a-zA-Z0-9._-]{3,64}") ? username.toLowerCase(Locale.ROOT) : "<invalid>";
	}

	private static byte[] addressBytes(PasswordAuthenticationContext context) {
		byte[] address = context.clientAddress().getAddress();
		// Treat an IPv4-mapped IPv6 address as the same peer as its four-byte IPv4 form.
		if (address.length == 16 && Arrays.equals(Arrays.copyOf(address, 12),
				new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 0xff, (byte) 0xff })) {
			return Arrays.copyOfRange(address, 12, 16);
		}
		return address;
	}

	private static String digest(String purpose, byte[] value) {
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			digest.update(purpose.getBytes(StandardCharsets.US_ASCII));
			return HexFormat.of().formatHex(digest.digest(value));
		}
		catch (NoSuchAlgorithmException ex) {
			throw new IllegalStateException("SHA-256 is unavailable", ex);
		}
	}

}
