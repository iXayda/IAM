package com.ixayda.iam.model;

import java.time.Instant;
import java.util.UUID;

/** A verified deployment recovery candidate, independent of the permanently closed installation bootstrap. */
public record IdentityRestoreAdministrator(UUID restoreId, UUID userId, UUID factorId, Instant preparedAt, Instant completedAt) { }
