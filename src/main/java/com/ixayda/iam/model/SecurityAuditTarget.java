package com.ixayda.iam.model;

import java.util.Objects;
import java.util.UUID;

/** Typed object target, optionally related to a separately identified user. */
public record SecurityAuditTarget(Type type, UUID id) {

	public SecurityAuditTarget {
		Objects.requireNonNull(type, "Audit target type is required");
		Objects.requireNonNull(id, "Audit target id is required");
	}

	public enum Type { RESOURCE, ROLE }

}
