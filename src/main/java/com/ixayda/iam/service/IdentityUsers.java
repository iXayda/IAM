package com.ixayda.iam.service;

import java.text.Normalizer;
import java.util.Locale;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.UUID;

import com.ixayda.iam.credential.PasswordHasher;
import com.ixayda.iam.model.IdentityUser;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.SecurityAuditEvent.Action;
import com.ixayda.iam.repository.IdentityUserRepository;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.Assert;

/** Internal persistence operations used by controlled user lifecycle workflows. */
@Service
public class IdentityUsers {

	private final IdentityUserRepository repository;

	private final PasswordHasher passwords;

	private final SecurityAudits audits;

	IdentityUsers(IdentityUserRepository repository, PasswordHasher passwords, SecurityAudits audits) {
		this.repository = repository;
		this.passwords = passwords;
		this.audits = audits;
	}

	@Transactional
	public IdentityUser create(String username, String displayName, SecurityAuditContext audit) {
		Assert.notNull(audit, "Audit context is required");
		IdentityUser user = this.repository.create(UUID.randomUUID(), normalizeUsername(username), normalizeDisplayName(displayName));
		this.audits.recordSuccess(Action.USER_CREATED, user.id(), audit);
		return user;
	}

	public Optional<IdentityUser> findById(UUID id) {
		Assert.notNull(id, "User id is required");
		return this.repository.findById(id);
	}

	public Optional<IdentityUser> findByUsername(String username) {
		return this.repository.findByUsername(normalizeUsername(username));
	}

	/** Stores the first password without activating the user or replacing an existing credential. */
	@Transactional
	public void setInitialPassword(UUID id, String password, SecurityAuditContext audit) {
		Assert.notNull(id, "User id is required");
		Assert.notNull(audit, "Audit context is required");
		IdentityUser user = this.repository.lockById(id).orElseThrow(() -> new NoSuchElementException("User not found"));
		if (user.status() != IdentityUser.Status.PENDING) {
			throw new IllegalStateException("Initial password requires a pending user");
		}
		this.repository.insertPassword(id, this.passwords.hash(password, user.username()));
		this.audits.recordSuccess(Action.INITIAL_PASSWORD_SET, id, audit);
	}

	@Transactional(propagation = Propagation.MANDATORY)
	IdentityUser lockById(UUID id) {
		return this.repository.lockById(id).orElseThrow(() -> new NoSuchElementException("User not found"));
	}

	@Transactional(propagation = Propagation.MANDATORY)
	void lockForSetup(UUID id) {
		IdentityUser user = lockById(id);
		if (user.status() != IdentityUser.Status.PENDING || this.repository.hasPassword(id)) {
			throw new IllegalStateException("Account setup requires a pending user without a password");
		}
	}

	@Transactional(propagation = Propagation.MANDATORY)
	void activateAfterSetup(UUID id) {
		this.repository.activateAfterSetup(id);
	}

	@Transactional(propagation = Propagation.MANDATORY)
	Optional<IdentityUser> lockForPasswordAuthentication(String username) {
		return this.repository.lockByUsername(username);
	}

	@Transactional(propagation = Propagation.MANDATORY)
	Optional<String> passwordHash(UUID id) {
		return this.repository.findPasswordHash(id);
	}

	@Transactional(propagation = Propagation.MANDATORY)
	Optional<Long> passwordVersion(UUID id) {
		return this.repository.findPasswordVersion(id);
	}

	public boolean hasCurrentPasswordVersion(UUID id, long version) {
		return this.repository.hasCurrentPasswordVersion(id, version);
	}

	@Transactional(propagation = Propagation.MANDATORY)
	void replacePassword(UUID id, String hash, long version) {
		this.repository.replacePassword(id, hash, version);
	}

	private static String normalizeUsername(String value) {
		if (value == null || !value.matches("[a-zA-Z0-9._-]{3,64}")) {
			throw new IllegalArgumentException("Username requires 3 to 64 ASCII letters, digits, dots, underscores or hyphens");
		}
		return value.toLowerCase(Locale.ROOT);
	}

	private static String normalizeDisplayName(String value) {
		if (value == null || value.length() > 65_536) {
			throw new IllegalArgumentException("Display name is invalid");
		}
		for (int i = 0; i < value.length(); i++) {
			char current = value.charAt(i);
			if (Character.isHighSurrogate(current)) {
				if (++i >= value.length() || !Character.isLowSurrogate(value.charAt(i))) {
					throw new IllegalArgumentException("Display name is invalid");
				}
			}
			else if (Character.isLowSurrogate(current)) {
				throw new IllegalArgumentException("Display name is invalid");
			}
		}
		String normalized = Normalizer.normalize(value, Normalizer.Form.NFC);
		int length = normalized.codePointCount(0, normalized.length());
		if (length < 1 || length > 128 || normalized.codePoints().anyMatch(Character::isISOControl)
				|| normalized.codePoints().allMatch(cp -> Character.isWhitespace(cp) || Character.isSpaceChar(cp))) {
			throw new IllegalArgumentException("Display name is invalid");
		}
		return normalized;
	}

}
