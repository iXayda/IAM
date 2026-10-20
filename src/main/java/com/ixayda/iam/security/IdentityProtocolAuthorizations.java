package com.ixayda.iam.security;

import com.ixayda.iam.service.IdentityAuthorizations;

import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;

/** Native client proof may read a code; audited, versioned workflows exclusively own mutations. */
final class IdentityProtocolAuthorizations implements OAuth2AuthorizationService {

	private final IdentityAuthorizations authorizations;

	IdentityProtocolAuthorizations(IdentityAuthorizations authorizations) { this.authorizations = authorizations; }

	@Override
	public OAuth2Authorization findByToken(String token, OAuth2TokenType type) {
		if (type == null || !"code".equals(type.getValue())) { throw new UnsupportedOperationException("Client proof can only look up a code"); }
		return this.authorizations.findByToken(token, "code").map(IdentityAuthorizations.Snapshot::authorization).orElse(null);
	}

	@Override
	public OAuth2Authorization findById(String id) { throw new UnsupportedOperationException("Native proof cannot enumerate authorizations"); }

	@Override
	public void save(OAuth2Authorization authorization) { throw new UnsupportedOperationException("Protocol writes require an audited versioned workflow"); }

	@Override
	public void remove(OAuth2Authorization authorization) { throw new UnsupportedOperationException("Protocol revocation requires an audited workflow"); }

}
