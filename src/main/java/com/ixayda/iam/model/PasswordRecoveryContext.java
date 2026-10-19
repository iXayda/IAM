package com.ixayda.iam.model;

import java.net.InetAddress;
import java.util.UUID;

/** Attribution and direct transport peer supplied by the trusted password recovery entry. */
public record PasswordRecoveryContext(String source, InetAddress clientAddress, UUID correlationId) {

	public PasswordRecoveryContext {
		new SecurityAuditContext("anonymous", source, correlationId);
		if (clientAddress == null) { throw new IllegalArgumentException("Verified client address is required"); }
	}

}
