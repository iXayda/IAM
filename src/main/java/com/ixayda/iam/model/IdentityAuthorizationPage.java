package com.ixayda.iam.model;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

public record IdentityAuthorizationPage(List<IdentityAuthorizationSummary> items, Cursor nextCursor) {

	public IdentityAuthorizationPage { items = List.copyOf(items); }

	public record Cursor(UUID userId, Instant issuedAt, UUID id) {
		public Cursor {
			Objects.requireNonNull(userId); Objects.requireNonNull(issuedAt); Objects.requireNonNull(id);
			if (issuedAt.isBefore(Instant.parse("-4712-01-01T00:00:00Z")) || !issuedAt.isBefore(Instant.parse("+294277-01-01T00:00:00Z"))
					|| issuedAt.getNano() % 1000 != 0) { throw new IllegalArgumentException("Cursor time must be finite with microsecond precision"); }
		}
	}
}
