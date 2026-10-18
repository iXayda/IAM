package com.ixayda.iam.service;

import java.text.Normalizer;
import java.util.Locale;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.UUID;

import com.ixayda.iam.credential.PasswordHasher;
import com.ixayda.iam.model.IdentityUser;
import com.ixayda.iam.model.IdentityUserPage;
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

	/** Internal listing; the caller authorizes access and reuses the returned cursor with the same filters. */
	public IdentityUserPage search(String keyword, IdentityUser.Status status, int pageSize, IdentityUserPage.Cursor after) {
		if (pageSize < 1 || pageSize > 100) {
			throw new IllegalArgumentException("Page size must be between 1 and 100");
		}
		String normalized = normalizeSearchKeyword(keyword);
		if (after != null && (!after.keyword().equals(normalized) || after.status() != status)) {
			throw new IllegalArgumentException("Cursor search filters do not match");
		}
		var rows = this.repository.search(normalized, status, pageSize + 1, after);
		boolean hasMore = rows.size() > pageSize;
		var items = hasMore ? rows.subList(0, pageSize) : rows;
		IdentityUserPage.Cursor next = null;
		if (hasMore) {
			var last = items.getLast();
			next = new IdentityUserPage.Cursor(last.createdAt(), last.id(), normalized, status);
		}
		return new IdentityUserPage(items, next);
	}

	private static String normalizeSearchKeyword(String value) {
		if (value == null || value.isEmpty()) {
			return "";
		}
		return normalizeUserText(value, "Search keyword is invalid");
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
	Optional<IdentityUser> lockForTotp(UUID id) {
		return this.repository.lockById(id);
	}

	@Transactional(propagation = Propagation.MANDATORY)
	Optional<IdentityUser> lockForMfaRecovery(UUID id) {
		return this.repository.lockById(id);
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
	Optional<IdentityUser> lockForPasswordRecovery(UUID id) {
		return this.repository.lockById(id).filter(user -> user.status() == IdentityUser.Status.ACTIVE);
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

	/** The profile workflow holds the user lock and supplies the normalized display name. */
	@Transactional(propagation = Propagation.MANDATORY)
	void updateDisplayName(UUID id, String displayName) {
		this.repository.updateDisplayName(id, displayName);
	}

	@Transactional(propagation = Propagation.MANDATORY)
	void replacePassword(UUID id, String hash, long version) {
		this.repository.replacePassword(id, hash, version);
	}

	@Transactional(propagation = Propagation.MANDATORY)
	void invalidateAuthentications(UUID id, long version) {
		this.repository.advanceCredentialVersion(id, version);
	}

	@Transactional(propagation = Propagation.MANDATORY)
	void disable(UUID id) {
		this.repository.disable(id);
	}

	@Transactional(propagation = Propagation.MANDATORY)
	void enable(UUID id) {
		this.repository.enable(id);
	}

	private static String normalizeUsername(String value) {
		if (value == null || !value.matches("[a-zA-Z0-9._-]{3,64}")) {
			throw new IllegalArgumentException("Username requires 3 to 64 ASCII letters, digits, dots, underscores or hyphens");
		}
		return value.toLowerCase(Locale.ROOT);
	}

	static String normalizeDisplayName(String value) {
		return normalizeUserText(value, "Display name is invalid");
	}

	private static String normalizeUserText(String value, String error) {
		if (value == null || value.length() > 65_536) {
			throw new IllegalArgumentException(error);
		}
		for (int i = 0; i < value.length(); i++) {
			char current = value.charAt(i);
			if (Character.isHighSurrogate(current)) {
				if (++i >= value.length() || !Character.isLowSurrogate(value.charAt(i))) {
					throw new IllegalArgumentException(error);
				}
			}
			else if (Character.isLowSurrogate(current)) {
				throw new IllegalArgumentException(error);
			}
		}
		String normalized = Normalizer.normalize(value, Normalizer.Form.NFC);
		int length = normalized.codePointCount(0, normalized.length());
		if (length < 1 || length > 128 || normalized.codePoints().anyMatch(Character::isISOControl)
				|| normalized.codePoints().allMatch(cp -> Character.isWhitespace(cp) || Character.isSpaceChar(cp))) {
			throw new IllegalArgumentException(error);
		}
		return normalized;
	}

}
