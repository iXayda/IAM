package com.ixayda.iam.model;

/** One-time delivery result; the clear secret is never reconstructible from the client record. */
public record IdentityClientSecret(IdentityClient client, String secret) {

	@Override
	public String toString() { return "IdentityClientSecret[REDACTED]"; }

}
