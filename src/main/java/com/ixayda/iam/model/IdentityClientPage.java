package com.ixayda.iam.model;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

public record IdentityClientPage(List<IdentityClient> items, Cursor nextCursor) {

	public IdentityClientPage { items = List.copyOf(items); }

	public record Cursor(Instant createdAt, UUID id, IdentityClient.Status status) {

		private static final Instant MIN_TIME = Instant.parse("-4712-01-01T00:00:00Z");
		private static final Instant MAX_TIME = Instant.parse("+294277-01-01T00:00:00Z");

		public Cursor {
			Objects.requireNonNull(createdAt, "Cursor creation time is required");
			Objects.requireNonNull(id, "Cursor client id is required");
			if (createdAt.isBefore(MIN_TIME) || !createdAt.isBefore(MAX_TIME) || createdAt.getNano() % 1_000 != 0) {
				throw new IllegalArgumentException("Cursor requires a finite microsecond position");
			}
		}

	}

}
