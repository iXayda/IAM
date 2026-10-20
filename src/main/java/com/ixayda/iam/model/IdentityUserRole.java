package com.ixayda.iam.model;

import java.time.Instant;
import java.util.UUID;

/** A direct assignment; an effective permission also requires active subjects and client approval. */
public record IdentityUserRole(UUID userId, UUID resourceId, UUID roleId, Instant createdAt) { }
