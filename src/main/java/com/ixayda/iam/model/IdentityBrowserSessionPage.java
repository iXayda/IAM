package com.ixayda.iam.model;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

public record IdentityBrowserSessionPage(List<IdentityBrowserSessionSummary> items, Cursor nextCursor) {

	public IdentityBrowserSessionPage { items = List.copyOf(items); }

	public record Cursor(UUID userId, Instant createdAt, UUID id) {
		public Cursor {
			Objects.requireNonNull(userId); Objects.requireNonNull(createdAt); Objects.requireNonNull(id);
			if (createdAt.isBefore(Instant.EPOCH) || createdAt.isAfter(Instant.ofEpochMilli(Long.MAX_VALUE)) || createdAt.getNano() % 1_000_000 != 0) {
				throw new IllegalArgumentException("Session cursor time must have nonnegative millisecond precision");
			}
		}
	}
}
