package com.ixayda.iam.model;

import java.time.Instant;
import java.util.UUID;

/** Evidence from the restored snapshot; it does not assert continuity with events lost after the backup. */
public record IdentityRestore(UUID id, String archiveSha256, String databaseName, Instant quarantinedAt,
		long snapshotAuditCount, Instant snapshotLastAuditAt, UUID snapshotLastAuditId) { }
