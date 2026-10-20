package com.ixayda.iam.service;

import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Service;

/** Checks mandatory protocol dependencies without creating identities, sessions, grants or audit events. */
@Service
@Lazy
public class IdentityReadiness {

	private final IdentitySigningKeys keys;
	private final IdentityAuthorizations authorizations;
	private final SecurityAudits audits;

	IdentityReadiness(IdentitySigningKeys keys, IdentityAuthorizations authorizations, SecurityAudits audits) {
		this.keys = keys; this.authorizations = authorizations; this.audits = audits;
	}

	public void requireReady() {
		if (!this.audits.isAvailable()) { throw new IllegalStateException("Mandatory audit storage is unavailable"); }
		this.authorizations.requireConfigured();
		this.keys.signingMaterial();
	}
}
