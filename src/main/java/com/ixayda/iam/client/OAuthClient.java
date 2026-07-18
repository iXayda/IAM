package com.ixayda.iam.client;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.Set;

import com.ixayda.iam.tenant.TenantId;

public record OAuthClient(ClientId id, TenantId tenantId, ClientIdentifier identifier, String displayName,
		ClientType type, ClientAuthenticationMethod authenticationMethod, ClientAuthorizationGrant authorizationGrant,
		ClientStatus status,
		ClientSecretMetadata secretMetadata, Set<ClientRedirectUri> redirectUris,
		Set<ClientRedirectUri> postLogoutRedirectUris, Set<ClientScope> scopes, ClientTokenPolicy tokenPolicy,
		long version, Instant createdAt, Instant updatedAt) {

	private static final int MAX_DISPLAY_NAME_LENGTH = 200;

	private static final ClientScope OPENID_SCOPE = new ClientScope("openid");

	private static final ClientScope OFFLINE_ACCESS_SCOPE = new ClientScope("offline_access");

	private static final Set<ClientScope> OIDC_SCOPES = Set.of(OPENID_SCOPE, OFFLINE_ACCESS_SCOPE,
			new ClientScope("profile"), new ClientScope("email"), new ClientScope("address"), new ClientScope("phone"));

	static final int MAX_REDIRECT_URI_COUNT = 20;

	static final int MAX_SCOPE_COUNT = 50;

	public OAuthClient {
		Objects.requireNonNull(id, "Client ID must not be null");
		Objects.requireNonNull(tenantId, "Client tenant ID must not be null");
		displayName = normalizeDisplayName(displayName);
		validateIdentity(identifier, type, authenticationMethod, authorizationGrant, secretMetadata);
		Objects.requireNonNull(status, "Client status must not be null");
		redirectUris = redirectUris(authorizationGrant, redirectUris);
		postLogoutRedirectUris = optionalCopy(postLogoutRedirectUris, "Client post-logout redirect URIs",
				MAX_REDIRECT_URI_COUNT);
		scopes = requiredCopy(scopes, "Client scopes", MAX_SCOPE_COUNT);
		validateProtocolShape(authorizationGrant, postLogoutRedirectUris, scopes);
		validateTokenPolicy(type, authorizationGrant, tokenPolicy);
		Objects.requireNonNull(createdAt, "Client creation time must not be null");
		Objects.requireNonNull(updatedAt, "Client update time must not be null");
		if (version < 0) {
			throw new IllegalArgumentException("Client version must not be negative");
		}
		if (updatedAt.isBefore(createdAt)) {
			throw new IllegalArgumentException("Client update time must not be before its creation time");
		}
		if (secretMetadata != null && (secretMetadata.issuedAt().isBefore(createdAt)
				|| secretMetadata.issuedAt().isAfter(updatedAt))) {
			throw new IllegalArgumentException("Client secret issue time must be within the client lifetime");
		}
	}

	public OAuthClient(ClientId id, TenantId tenantId, ClientIdentifier identifier, String displayName,
			ClientType type, ClientAuthenticationMethod authenticationMethod, ClientStatus status,
			ClientSecretMetadata secretMetadata, Set<ClientRedirectUri> redirectUris,
			Set<ClientRedirectUri> postLogoutRedirectUris, Set<ClientScope> scopes, ClientTokenPolicy tokenPolicy,
			long version, Instant createdAt, Instant updatedAt) {
		this(id, tenantId, identifier, displayName, type, authenticationMethod,
				ClientAuthorizationGrant.AUTHORIZATION_CODE, status, secretMetadata, redirectUris,
				postLogoutRedirectUris, scopes, tokenPolicy, version, createdAt, updatedAt);
	}

	public static OAuthClient create(ClientId id, TenantId tenantId, CreateClientRequest request,
			ClientSecretMetadata secretMetadata, Instant createdAt) {
		Objects.requireNonNull(request, "Client creation request must not be null");
		return new OAuthClient(id, tenantId, request.identifier(), request.displayName(), request.type(),
				request.authenticationMethod(), request.authorizationGrant(), ClientStatus.ACTIVE, secretMetadata,
				request.redirectUris(),
				request.postLogoutRedirectUris(), request.scopes(), request.tokenPolicy(), 0, createdAt, createdAt);
	}

	public boolean isActive() {
		return this.status == ClientStatus.ACTIVE;
	}

	public boolean hasSecret() {
		return this.secretMetadata != null;
	}

	public boolean requiresProofKey() {
		return this.authorizationGrant == ClientAuthorizationGrant.AUTHORIZATION_CODE;
	}

	public boolean supportsRefreshTokens() {
		return this.tokenPolicy.refreshTokensEnabled();
	}

	public boolean requiresConsent() {
		return this.authorizationGrant == ClientAuthorizationGrant.AUTHORIZATION_CODE;
	}

	public OAuthClient activate(Instant changedAt) {
		return changeStatus(ClientStatus.ACTIVE, changedAt);
	}

	public OAuthClient disable(Instant changedAt) {
		return changeStatus(ClientStatus.DISABLED, changedAt);
	}

	@Override
	public String toString() {
		return "OAuthClient[id=" + this.id + ", tenantId=" + this.tenantId + ", identifier=" + this.identifier
				+ ", type=" + this.type + ", authenticationMethod=" + this.authenticationMethod
				+ ", authorizationGrant=" + this.authorizationGrant + ", status=" + this.status + ", version=" + this.version
				+ ", redirectUriCount=" + this.redirectUris.size() + ", scopeCount=" + this.scopes.size() + "]";
	}

	static String normalizeDisplayName(String displayName) {
		Objects.requireNonNull(displayName, "Client display name must not be null");
		String normalized = displayName.strip();
		if (normalized.isEmpty() || normalized.length() > MAX_DISPLAY_NAME_LENGTH) {
			throw new IllegalArgumentException("Client display name must contain 1 to 200 characters");
		}
		return normalized;
	}

	static void validateIdentity(ClientIdentifier identifier, ClientType type,
			ClientAuthenticationMethod authenticationMethod, ClientAuthorizationGrant authorizationGrant,
			ClientSecretMetadata secretMetadata) {
		validateAuthentication(identifier, type, authenticationMethod);
		Objects.requireNonNull(authorizationGrant, "Client authorization grant must not be null");
		if (authorizationGrant == ClientAuthorizationGrant.CLIENT_CREDENTIALS && type != ClientType.CONFIDENTIAL) {
			throw new IllegalArgumentException("Client credentials require a confidential client");
		}
		if (type == ClientType.PUBLIC && secretMetadata != null) {
			throw new IllegalArgumentException("Public client must not have client secret metadata");
		}
		if (type == ClientType.CONFIDENTIAL && secretMetadata == null) {
			throw new IllegalArgumentException("Confidential client must have active secret metadata");
		}
	}

	static void validateAuthentication(ClientIdentifier identifier, ClientType type,
			ClientAuthenticationMethod authenticationMethod) {
		Objects.requireNonNull(identifier, "Client identifier must not be null");
		Objects.requireNonNull(type, "Client type must not be null");
		Objects.requireNonNull(authenticationMethod, "Client authentication method must not be null");
		if (type == ClientType.PUBLIC && authenticationMethod != ClientAuthenticationMethod.NONE) {
			throw new IllegalArgumentException("Public client must use no client authentication");
		}
		if (type == ClientType.CONFIDENTIAL
				&& authenticationMethod != ClientAuthenticationMethod.CLIENT_SECRET_BASIC) {
			throw new IllegalArgumentException("Confidential client must use client_secret_basic");
		}
	}

	static void validateProtocolShape(ClientAuthorizationGrant authorizationGrant,
			Set<ClientRedirectUri> postLogoutRedirectUris, Set<ClientScope> scopes) {
		if (authorizationGrant == ClientAuthorizationGrant.CLIENT_CREDENTIALS && !postLogoutRedirectUris.isEmpty()) {
			throw new IllegalArgumentException("Client-credentials clients must not have post-logout redirect URIs");
		}
		if (!postLogoutRedirectUris.isEmpty() && !scopes.contains(OPENID_SCOPE)) {
			throw new IllegalArgumentException("Client post-logout redirect URIs require the openid scope");
		}
		if (authorizationGrant == ClientAuthorizationGrant.CLIENT_CREDENTIALS
				&& scopes.stream().anyMatch(OIDC_SCOPES::contains)) {
			throw new IllegalArgumentException("Client-credentials clients must not request OpenID Connect scopes");
		}
		if (scopes.contains(OFFLINE_ACCESS_SCOPE)) {
			throw new IllegalArgumentException("Client offline_access scope requires refresh-token support");
		}
	}

	static ClientTokenPolicy requireTokenPolicy(ClientTokenPolicy tokenPolicy) {
		return Objects.requireNonNull(tokenPolicy, "Client token policy must not be null");
	}

	static void validateTokenPolicy(ClientType type, ClientAuthorizationGrant authorizationGrant,
			ClientTokenPolicy tokenPolicy) {
		requireTokenPolicy(tokenPolicy);
		if (authorizationGrant == ClientAuthorizationGrant.CLIENT_CREDENTIALS
				&& tokenPolicy.refreshTokensEnabled()) {
			throw new IllegalArgumentException("Client-credentials clients must not enable refresh tokens");
		}
		if (authorizationGrant == ClientAuthorizationGrant.CLIENT_CREDENTIALS
				&& tokenPolicy.accessTokenTtl().compareTo(Duration.ofMinutes(5)) > 0) {
			throw new IllegalArgumentException("Client-credentials access token TTL must not exceed 5 minutes");
		}
		if (tokenPolicy.refreshTokensEnabled() && type != ClientType.CONFIDENTIAL) {
			throw new IllegalArgumentException("Refresh tokens require a confidential client");
		}
	}

	static Set<ClientRedirectUri> redirectUris(ClientAuthorizationGrant authorizationGrant,
			Set<ClientRedirectUri> redirectUris) {
		Set<ClientRedirectUri> copy = optionalCopy(redirectUris, "Client redirect URIs", MAX_REDIRECT_URI_COUNT);
		if (authorizationGrant == ClientAuthorizationGrant.AUTHORIZATION_CODE && copy.isEmpty()) {
			throw new IllegalArgumentException("Client redirect URIs must not be empty");
		}
		if (authorizationGrant == ClientAuthorizationGrant.CLIENT_CREDENTIALS && !copy.isEmpty()) {
			throw new IllegalArgumentException("Client-credentials clients must not have redirect URIs");
		}
		return copy;
	}

	static <T> Set<T> requiredCopy(Set<T> values, String name, int maximumSize) {
		Set<T> copy = optionalCopy(values, name, maximumSize);
		if (copy.isEmpty()) {
			throw new IllegalArgumentException(name + " must not be empty");
		}
		return copy;
	}

	static <T> Set<T> optionalCopy(Set<T> values, String name, int maximumSize) {
		Objects.requireNonNull(values, name + " must not be null");
		try {
			Set<T> copy = Set.copyOf(values);
			if (copy.size() > maximumSize) {
				throw new IllegalArgumentException(name + " must contain at most " + maximumSize + " values");
			}
			return copy;
		}
		catch (NullPointerException exception) {
			throw new IllegalArgumentException(name + " must not contain null values", exception);
		}
	}

	private OAuthClient changeStatus(ClientStatus targetStatus, Instant changedAt) {
		Objects.requireNonNull(changedAt, "Client status change time must not be null");
		if (this.status == targetStatus) {
			return this;
		}
		if (changedAt.isBefore(this.updatedAt)) {
			throw new IllegalArgumentException("Client status change time must not be before its last update");
		}
		return new OAuthClient(this.id, this.tenantId, this.identifier, this.displayName, this.type,
				this.authenticationMethod, this.authorizationGrant, targetStatus, this.secretMetadata, this.redirectUris,
				this.postLogoutRedirectUris, this.scopes, this.tokenPolicy, Math.incrementExact(this.version),
				this.createdAt, changedAt);
	}

}
