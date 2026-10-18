package com.ixayda.iam.model;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/** A bounded user listing and its continuation position, without credential data. */
public record IdentityUserPage(List<IdentityUser> items, Cursor nextCursor) {

	public IdentityUserPage {
		items = List.copyOf(items);
	}

	/** A position in one normalized search; it does not confer permission to list users. */
	public record Cursor(Instant createdAt, UUID id, String keyword, IdentityUser.Status status) {

		public Cursor {
			Objects.requireNonNull(createdAt, "Cursor creation time is required");
			Objects.requireNonNull(id, "Cursor user id is required");
			Objects.requireNonNull(keyword, "Cursor search keyword is required");
		}

	}

}
