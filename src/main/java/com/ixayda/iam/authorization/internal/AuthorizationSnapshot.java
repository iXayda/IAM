package com.ixayda.iam.authorization.internal;

import java.time.Instant;
import java.util.Collections;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

import com.ixayda.iam.authorization.AuthorizationPrincipal;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

record AuthorizationSnapshot(UUID authorizationId, UUID tenantId, UUID clientId, String clientIdentifier,
		AuthorizationGrantKind grantType, AuthorizationPrincipal principal, Set<String> principalAuthorities, String authorizationUri,
		String redirectUri, String clientState, Map<String, Object> requestParameters, Set<String> requestedScopes,
		Set<String> authorizedScopes, String consentState, Long expectedVersion,
		Map<AuthorizationTokenKind, AuthorizationTokenSnapshot> tokens) {

	AuthorizationSnapshot {
		Objects.requireNonNull(grantType, "Authorization grant type must not be null");
		if (grantType == AuthorizationGrantKind.AUTHORIZATION_CODE && principal == null) {
			throw new IllegalArgumentException("Authorization-code owner must be an IAM user");
		}
		if (grantType == AuthorizationGrantKind.CLIENT_CREDENTIALS && (principal != null
				|| !principalAuthorities.isEmpty() || authorizationUri != null || redirectUri != null || clientState != null
				|| !requestParameters.isEmpty() || consentState != null)) {
			throw new IllegalArgumentException("Client-credentials authorization must not contain user or request state");
		}
		principalAuthorities = Collections.unmodifiableSet(new LinkedHashSet<>(principalAuthorities));
		requestParameters = Collections.unmodifiableMap(new LinkedHashMap<>(requestParameters));
		requestedScopes = Collections.unmodifiableSet(new LinkedHashSet<>(requestedScopes));
		authorizedScopes = Collections.unmodifiableSet(new LinkedHashSet<>(authorizedScopes));
		EnumMap<AuthorizationTokenKind, AuthorizationTokenSnapshot> tokenCopy =
				new EnumMap<>(AuthorizationTokenKind.class);
		tokenCopy.putAll(tokens);
		tokens = Collections.unmodifiableMap(tokenCopy);
	}

	String principalName() {
		return this.principal == null ? this.clientIdentifier : this.principal.getName();
	}

	@Override
	public String toString() {
		return "AuthorizationSnapshot[authorizationId=" + this.authorizationId + ", tenantId=" + this.tenantId
				+ ", clientId=" + this.clientId + ", grantType=" + this.grantType + ", principalName="
				+ principalName() + ", requestedScopes=" + this.requestedScopes + ", authorizedScopes="
				+ this.authorizedScopes + ", tokenKinds=" + this.tokens.keySet() + "]";
	}

}

enum AuthorizationGrantKind {

	AUTHORIZATION_CODE(AuthorizationGrantType.AUTHORIZATION_CODE),

	CLIENT_CREDENTIALS(AuthorizationGrantType.CLIENT_CREDENTIALS);

	private final AuthorizationGrantType value;

	AuthorizationGrantKind(AuthorizationGrantType value) {
		this.value = value;
	}

	AuthorizationGrantType value() {
		return this.value;
	}

	String databaseValue() {
		return this.value.getValue();
	}

	static AuthorizationGrantKind from(AuthorizationGrantType value) {
		for (AuthorizationGrantKind kind : values()) {
			if (kind.value.equals(value)) {
				return kind;
			}
		}
		throw new IllegalArgumentException("Unsupported authorization grant type: " + value);
	}

	static AuthorizationGrantKind fromDatabaseValue(String value) {
		for (AuthorizationGrantKind kind : values()) {
			if (kind.databaseValue().equals(value)) {
				return kind;
			}
		}
		throw new IllegalArgumentException("Unsupported stored authorization grant type: " + value);
	}

}

enum AuthorizationTokenKind {

	STATE("state"),

	AUTHORIZATION_CODE("authorization_code"),

	ACCESS_TOKEN("access_token"),

	REFRESH_TOKEN("refresh_token"),

	ID_TOKEN("id_token");

	private final String databaseValue;

	AuthorizationTokenKind(String databaseValue) {
		this.databaseValue = databaseValue;
	}

	String databaseValue() {
		return this.databaseValue;
	}

	static AuthorizationTokenKind fromDatabaseValue(String value) {
		for (AuthorizationTokenKind kind : values()) {
			if (kind.databaseValue.equals(value)) {
				return kind;
			}
		}
		throw new IllegalArgumentException("Unsupported stored authorization token type: " + value);
	}

}

record AuthorizationTokenSnapshot(String value, Instant issuedAt, Instant expiresAt, boolean invalidated,
		String accessTokenType, Set<String> scopes, Map<String, Object> claims) {

	AuthorizationTokenSnapshot {
		scopes = Collections.unmodifiableSet(new LinkedHashSet<>(scopes));
		claims = claims == null ? null : Collections.unmodifiableMap(new LinkedHashMap<>(claims));
	}

	@Override
	public String toString() {
		return "AuthorizationTokenSnapshot[issuedAt=" + this.issuedAt + ", expiresAt=" + this.expiresAt
				+ ", invalidated=" + this.invalidated + ", accessTokenType=" + this.accessTokenType + ", scopes="
				+ this.scopes + ", claimsPresent=" + (this.claims != null) + "]";
	}

}
