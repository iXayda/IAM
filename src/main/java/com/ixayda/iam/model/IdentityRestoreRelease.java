package com.ixayda.iam.model;

import java.time.Instant;
import java.util.UUID;

/** Immutable authorization to admit a quarantined restore with one newly verified administrator. */
public record IdentityRestoreRelease(UUID restoreId, UUID userId, UUID factorId, UUID signingKeyId, Instant releasedAt) { }
