package com.ixayda.iam.client;

import java.util.Set;

public record CreateClientRequest(ClientIdentifier identifier, String displayName, ClientType type,
		ClientAuthenticationMethod authenticationMethod, ClientAuthorizationGrant authorizationGrant,
		Set<ClientRedirectUri> redirectUris,
		Set<ClientRedirectUri> postLogoutRedirectUris, Set<ClientScope> scopes, ClientTokenPolicy tokenPolicy) {

	public CreateClientRequest {
		displayName = OAuthClient.normalizeDisplayName(displayName);
		OAuthClient.validateAuthentication(identifier, type, authenticationMethod);
		if (authorizationGrant == null) {
			throw new NullPointerException("Client authorization grant must not be null");
		}
		if (authorizationGrant == ClientAuthorizationGrant.CLIENT_CREDENTIALS && type != ClientType.CONFIDENTIAL) {
			throw new IllegalArgumentException("Client credentials require a confidential client");
		}
		redirectUris = OAuthClient.redirectUris(authorizationGrant, redirectUris);
		postLogoutRedirectUris = OAuthClient.optionalCopy(postLogoutRedirectUris,
				"Client post-logout redirect URIs", OAuthClient.MAX_REDIRECT_URI_COUNT);
		scopes = OAuthClient.requiredCopy(scopes, "Client scopes", OAuthClient.MAX_SCOPE_COUNT);
		OAuthClient.validateProtocolShape(authorizationGrant, postLogoutRedirectUris, scopes);
		OAuthClient.validateTokenPolicy(type, authorizationGrant, tokenPolicy);
	}

	public CreateClientRequest(ClientIdentifier identifier, String displayName, ClientType type,
			ClientAuthenticationMethod authenticationMethod, Set<ClientRedirectUri> redirectUris,
			Set<ClientRedirectUri> postLogoutRedirectUris, Set<ClientScope> scopes,
			ClientTokenPolicy tokenPolicy) {
		this(identifier, displayName, type, authenticationMethod, ClientAuthorizationGrant.AUTHORIZATION_CODE,
				redirectUris, postLogoutRedirectUris, scopes, tokenPolicy);
	}

}
