package com.ixayda.iam.group;

import java.util.Objects;

public record GroupDirectoryQuery(int offset, int limit, Criterion criterion) {

	public static final int MAX_LIMIT = 100;

	public GroupDirectoryQuery {
		if (offset < 0) {
			throw new IllegalArgumentException("Group directory offset must not be negative");
		}
		if (limit < 0 || limit > MAX_LIMIT) {
			throw new IllegalArgumentException("Group directory limit must be between 0 and " + MAX_LIMIT);
		}
		Objects.requireNonNull(criterion, "Group directory criterion must not be null");
	}

	public static GroupDirectoryQuery all(int offset, int limit) {
		return new GroupDirectoryQuery(offset, limit, new All());
	}

	public static GroupDirectoryQuery none(int offset, int limit) {
		return new GroupDirectoryQuery(offset, limit, new None());
	}

	public static GroupDirectoryQuery idEquals(int offset, int limit, GroupId groupId) {
		return new GroupDirectoryQuery(offset, limit, new IdEquals(groupId));
	}

	public static GroupDirectoryQuery displayNameEquals(int offset, int limit, String displayName) {
		return new GroupDirectoryQuery(offset, limit, new DisplayNameEquals(displayName));
	}

	public sealed interface Criterion permits All, None, IdEquals, DisplayNameEquals {
	}

	public record All() implements Criterion {
	}

	public record None() implements Criterion {
	}

	public record IdEquals(GroupId groupId) implements Criterion {

		public IdEquals {
			Objects.requireNonNull(groupId, "Group ID criterion must not be null");
		}

	}

	public record DisplayNameEquals(String value) implements Criterion {

		public DisplayNameEquals {
			Objects.requireNonNull(value, "Group display name criterion must not be null");
		}

	}

}
