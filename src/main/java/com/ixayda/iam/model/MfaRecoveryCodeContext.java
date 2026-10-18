package com.ixayda.iam.model;

import java.net.InetAddress;
import java.util.UUID;

/** Source and transport peer established by the trusted recovery-code entry point. */
public record MfaRecoveryCodeContext(String source, InetAddress clientAddress, UUID correlationId) {

	public MfaRecoveryCodeContext {
		new SecurityAuditContext("anonymous", source, correlationId);
		if (clientAddress == null) {
			throw new IllegalArgumentException("Verified client address is required");
		}
	}

}
