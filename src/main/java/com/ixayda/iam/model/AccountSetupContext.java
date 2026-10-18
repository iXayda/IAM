package com.ixayda.iam.model;

import java.net.InetAddress;
import java.util.UUID;

/** Attribution and direct transport peer supplied by the trusted account setup entry. */
public record AccountSetupContext(String source, InetAddress clientAddress, UUID correlationId) {

	public AccountSetupContext {
		new SecurityAuditContext("anonymous", source, correlationId);
		if (clientAddress == null) { throw new IllegalArgumentException("Verified client address is required"); }
	}

}
