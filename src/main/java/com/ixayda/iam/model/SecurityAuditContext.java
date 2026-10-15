package com.ixayda.iam.model;

import java.util.UUID;

/** Attribution supplied by a trusted application entry point, not by request payloads. */
public record SecurityAuditContext(String actor, String source, UUID correlationId) {

	public SecurityAuditContext {
		if (!isIdentifier(actor, 128) || !isIdentifier(source, 64) || correlationId == null) {
			throw new IllegalArgumentException("Audit actor, source and correlation id are required");
		}
	}

	private static boolean isIdentifier(String value, int maxLength) {
		return value != null && value.length() >= 1 && value.length() <= maxLength
				&& value.matches("[a-zA-Z0-9][a-zA-Z0-9._:-]*");
	}

}
