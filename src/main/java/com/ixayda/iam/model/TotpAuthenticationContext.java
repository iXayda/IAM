package com.ixayda.iam.model;

import java.net.InetAddress;
import java.util.UUID;

/** Attribution and transport peer established by a trusted factor-verification entry point. */
public record TotpAuthenticationContext(String source, InetAddress clientAddress, UUID correlationId) {

	public TotpAuthenticationContext {
		new SecurityAuditContext("anonymous", source, correlationId);
		if (clientAddress == null) {
			throw new IllegalArgumentException("Verified client address is required");
		}
	}

}
