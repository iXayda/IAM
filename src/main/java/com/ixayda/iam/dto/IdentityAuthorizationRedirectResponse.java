package com.ixayda.iam.dto;

/** The redirect can contain a single-use authorization code and must not be logged or persisted by the frontend. */
public record IdentityAuthorizationRedirectResponse(String redirectUri) {
	@Override public String toString() { return "AuthorizationRedirectResponse[REDACTED]"; }
}
