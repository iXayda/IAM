package com.ixayda.iam.audit;

import java.util.Objects;
import java.util.regex.Pattern;

public record AuditEventType(String value) {

	private static final Pattern FORMAT = Pattern.compile("[a-z][a-z0-9_]*(\\.[a-z][a-z0-9_]*)+");

	public AuditEventType {
		Objects.requireNonNull(value, "Audit event type must not be null");
		if (value.length() < 3 || value.length() > 120 || !FORMAT.matcher(value).matches()) {
			throw new IllegalArgumentException("Audit event type must be a 3 to 120 character dotted identifier");
		}
	}

	public static AuditEventType from(String value) {
		return new AuditEventType(value);
	}

	@Override
	public String toString() {
		return this.value;
	}

}
