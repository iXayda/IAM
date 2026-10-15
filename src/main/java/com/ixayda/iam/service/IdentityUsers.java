package com.ixayda.iam.service;

import java.text.Normalizer;
import java.util.Locale;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.UUID;

import com.ixayda.iam.credential.PasswordHasher;
import com.ixayda.iam.model.IdentityUser;
import com.ixayda.iam.repository.IdentityUserRepository;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.Assert;

/** Internal persistence operations used by controlled user lifecycle workflows. */
@Service
public class IdentityUsers {

	private final IdentityUserRepository repository;

	private final PasswordHasher passwords;

	IdentityUsers(IdentityUserRepository repository, PasswordHasher passwords) {
		this.repository = repository;
		this.passwords = passwords;
	}

	@Transactional
	public IdentityUser create(String username, String displayName) {
		return this.repository.create(UUID.randomUUID(), normalizeUsername(username), normalizeDisplayName(displayName));
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
	public void setInitialPassword(UUID id, String password) {
		Assert.notNull(id, "User id is required");
		IdentityUser user = this.repository.lockById(id).orElseThrow(() -> new NoSuchElementException("User not found"));
		if (user.status() != IdentityUser.Status.PENDING) {
			throw new IllegalStateException("Initial password requires a pending user");
		}
		this.repository.insertPassword(id, this.passwords.hash(password, user.username()));
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
