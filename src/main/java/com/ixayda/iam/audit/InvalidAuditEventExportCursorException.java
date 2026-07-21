package com.ixayda.iam.audit;

public final class InvalidAuditEventExportCursorException extends RuntimeException {

	public InvalidAuditEventExportCursorException() {
		super("Audit export cursor is invalid");
	}

}
