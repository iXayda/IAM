package com.ixayda.iam.user;

import java.util.Objects;

public record UserDirectoryQuery(int offset, int limit, Criterion criterion) {

	public static final int MAX_LIMIT = 100;

	public UserDirectoryQuery {
		if (offset < 0) {
			throw new IllegalArgumentException("User directory offset must not be negative");
		}
		if (limit < 0 || limit > MAX_LIMIT) {
			throw new IllegalArgumentException("User directory limit must be between 0 and " + MAX_LIMIT);
		}
		Objects.requireNonNull(criterion, "User directory criterion must not be null");
	}

	public static UserDirectoryQuery all(int offset, int limit) {
		return new UserDirectoryQuery(offset, limit, new All());
	}

	public static UserDirectoryQuery none(int offset, int limit) {
		return new UserDirectoryQuery(offset, limit, new None());
	}

	public static UserDirectoryQuery idEquals(int offset, int limit, UserId userId) {
		return new UserDirectoryQuery(offset, limit, new IdEquals(userId));
	}

	public static UserDirectoryQuery primaryIdentifierEquals(int offset, int limit, String primaryIdentifier) {
		return new UserDirectoryQuery(offset, limit, new PrimaryIdentifierEquals(primaryIdentifier));
	}

	public sealed interface Criterion permits All, None, IdEquals, PrimaryIdentifierEquals {
	}

	public record All() implements Criterion {
	}

	public record None() implements Criterion {
	}

	public record IdEquals(UserId userId) implements Criterion {

		public IdEquals {
			Objects.requireNonNull(userId, "User ID criterion must not be null");
		}

	}

	public record PrimaryIdentifierEquals(String value) implements Criterion {

		public PrimaryIdentifierEquals {
			Objects.requireNonNull(value, "Primary identifier criterion must not be null");
		}

	}

}
