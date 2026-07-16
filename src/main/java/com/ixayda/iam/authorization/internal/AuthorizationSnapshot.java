package com.ixayda.iam.authorization.internal;

import java.time.Instant;
import java.util.Collections;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import com.ixayda.iam.authorization.AuthorizationPrincipal;

record AuthorizationSnapshot(UUID authorizationId, UUID tenantId, UUID clientId, String clientIdentifier,
		AuthorizationPrincipal principal, Set<String> principalAuthorities, String authorizationUri,
		String redirectUri, String clientState, Map<String, Object> requestParameters, Set<String> requestedScopes,
		Set<String> authorizedScopes, String consentState, Long expectedVersion,
		Map<AuthorizationTokenKind, AuthorizationTokenSnapshot> tokens) {

	AuthorizationSnapshot {
		principalAuthorities = Collections.unmodifiableSet(new LinkedHashSet<>(principalAuthorities));
		requestParameters = Collections.unmodifiableMap(new LinkedHashMap<>(requestParameters));
		requestedScopes = Collections.unmodifiableSet(new LinkedHashSet<>(requestedScopes));
		authorizedScopes = Collections.unmodifiableSet(new LinkedHashSet<>(authorizedScopes));
		EnumMap<AuthorizationTokenKind, AuthorizationTokenSnapshot> tokenCopy =
				new EnumMap<>(AuthorizationTokenKind.class);
		tokenCopy.putAll(tokens);
		tokens = Collections.unmodifiableMap(tokenCopy);
	}

}

enum AuthorizationTokenKind {

	STATE("state"),

	AUTHORIZATION_CODE("authorization_code"),

	ACCESS_TOKEN("access_token"),

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

}
