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
	private final IdentityRestores restores;

	IdentityReadiness(IdentitySigningKeys keys, IdentityAuthorizations authorizations, SecurityAudits audits, IdentityRestores restores) {
		this.keys = keys; this.authorizations = authorizations; this.audits = audits; this.restores = restores;
	}

	public void requireReady() {
		this.restores.requireAvailable();
		if (!this.audits.isAvailable()) { throw new IllegalStateException("Mandatory audit storage is unavailable"); }
		this.authorizations.requireConfigured();
		this.keys.signingMaterial();
	}
}
