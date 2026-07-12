package com.ixayda.iam.credential.internal;

import java.time.Instant;
import java.util.Objects;
import java.util.regex.Pattern;

import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;

final class PasswordCredential {

	private static final Pattern ENCODED_PASSWORD_PATTERN =
			Pattern.compile("\\{[A-Za-z0-9@._-]{1,64}}[!-~]{20,}");

	private final TenantId tenantId;

	private final UserId userId;

	private final String encodedPassword;

	private final long version;

	private final Instant createdAt;

	private final Instant updatedAt;

	PasswordCredential(TenantId tenantId, UserId userId, String encodedPassword, long version, Instant createdAt,
			Instant updatedAt) {
		this.tenantId = Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		this.userId = Objects.requireNonNull(userId, "User ID must not be null");
		this.encodedPassword = validateEncodedPassword(encodedPassword);
		if (version < 0) {
			throw new IllegalArgumentException("Password credential version must not be negative");
		}
		this.version = version;
		this.createdAt = Objects.requireNonNull(createdAt, "Password credential creation time must not be null");
		this.updatedAt = Objects.requireNonNull(updatedAt, "Password credential update time must not be null");
		if (updatedAt.isBefore(createdAt)) {
			throw new IllegalArgumentException("Password credential update time must not precede creation time");
		}
	}

	static PasswordCredential initial(TenantId tenantId, UserId userId, String encodedPassword, Instant now) {
		return new PasswordCredential(tenantId, userId, encodedPassword, 0, now, now);
	}

	PasswordCredential replaceWith(String encodedPassword, Instant now) {
		Objects.requireNonNull(now, "Password credential update time must not be null");
		Instant replacementTime = now.isBefore(this.updatedAt) ? this.updatedAt : now;
		return new PasswordCredential(this.tenantId, this.userId, encodedPassword, Math.incrementExact(this.version),
				this.createdAt, replacementTime);
	}

	TenantId tenantId() {
		return this.tenantId;
	}

	UserId userId() {
		return this.userId;
	}

	String encodedPassword() {
		return this.encodedPassword;
	}

	long version() {
		return this.version;
	}

	Instant createdAt() {
		return this.createdAt;
	}

	Instant updatedAt() {
		return this.updatedAt;
	}

	@Override
	public String toString() {
		return "PasswordCredential[tenantId=" + this.tenantId + ", userId=" + this.userId + ", version="
				+ this.version + ", encodedPassword=redacted, createdAt=" + this.createdAt + ", updatedAt="
				+ this.updatedAt + "]";
	}

	private static String validateEncodedPassword(String encodedPassword) {
		Objects.requireNonNull(encodedPassword, "Encoded password must not be null");
		if (encodedPassword.length() < 32 || encodedPassword.length() > 1024
				|| !ENCODED_PASSWORD_PATTERN.matcher(encodedPassword).matches()
				|| encodedPassword.regionMatches(true, 0, "{noop}", 0, 6)) {
			throw new IllegalArgumentException("Encoded password format is invalid");
		}
		return encodedPassword;
	}

}
