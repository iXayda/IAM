package com.ixayda.iam.model;

/** One-time delivery after an audited transaction commits; ordinary reads return only lifecycle facts. */
public record IdentityResourceSecret(IdentityResourceCredential credential, String secret) {

	@Override
	public String toString() { return "IdentityResourceSecret[REDACTED]"; }

}
