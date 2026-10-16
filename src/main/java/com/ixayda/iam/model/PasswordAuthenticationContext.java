package com.ixayda.iam.model;

import java.net.InetAddress;
import java.util.UUID;

/** The entry point identifies its own source and the verified transport peer, never request fields. */
public record PasswordAuthenticationContext(String source, InetAddress clientAddress, UUID correlationId) {

	public PasswordAuthenticationContext {
		new SecurityAuditContext("anonymous", source, correlationId);
		if (clientAddress == null) {
			throw new IllegalArgumentException("Verified client address is required");
		}
	}

}
