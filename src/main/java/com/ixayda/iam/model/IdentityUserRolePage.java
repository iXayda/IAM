package com.ixayda.iam.model;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/** Assignment revision and rows read from one database statement snapshot. */
public record IdentityUserRolePage(List<IdentityUserRole> items, long version, Cursor nextCursor) {

	public IdentityUserRolePage { items = List.copyOf(items); }

	public record Cursor(UUID userId, UUID resourceId, long version, Instant createdAt, UUID roleId) {

		private static final Instant MIN_TIME = Instant.parse("-4712-01-01T00:00:00Z");
		private static final Instant MAX_TIME = Instant.parse("+294277-01-01T00:00:00Z");

		public Cursor {
			Objects.requireNonNull(userId, "Cursor user id is required");
			Objects.requireNonNull(resourceId, "Cursor resource id is required");
			Objects.requireNonNull(createdAt, "Cursor creation time is required");
			Objects.requireNonNull(roleId, "Cursor role id is required");
			if (version < 1 || createdAt.isBefore(MIN_TIME) || !createdAt.isBefore(MAX_TIME) || createdAt.getNano() % 1_000 != 0) {
				throw new IllegalArgumentException("Cursor requires a positive assignment revision and finite microsecond position");
			}
		}

	}

}
