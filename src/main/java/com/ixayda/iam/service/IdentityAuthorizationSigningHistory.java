package com.ixayda.iam.service;

import java.text.ParseException;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.SignedJWT;

import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;

/** Authenticated native attributes retain signing provenance across refreshes; they never authorize token use. */
public final class IdentityAuthorizationSigningHistory {

	private static final String ATTRIBUTE = "iam.signingHistory";
	private static final String PREFIX = "iam:signing-history:v1|";

	private IdentityAuthorizationSigningHistory() { }

	/** Called only after the trusted native generator has produced tokens, before the same transaction saves them. */
	public static OAuth2Authorization record(OAuth2Authorization issued, OAuth2Authorization previous) {
		var history = read(previous); var ids = new TreeSet<>(history.ids());
		addTokens(previous, ids); addTokens(issued, ids);
		return OAuth2Authorization.from(issued).attribute(ATTRIBUTE, PREFIX + (history.complete() ? "complete|" : "partial|") + String.join(",", ids)).build();
	}

	/** Legacy grants without complete provenance are conservatively included in a key incident. */
	static boolean mayHaveUsed(OAuth2Authorization authorization, UUID keyId) {
		if (!hasTokens(authorization)) { return false; }
		var history = read(authorization);
		return !history.complete() || history.ids().contains(keyId.toString());
	}

	private static History read(OAuth2Authorization authorization) {
		Object raw = authorization.getAttribute(ATTRIBUTE);
		if (raw == null) { return new History(!hasTokens(authorization), Set.of()); }
		if (!(raw instanceof String value) || !value.startsWith(PREFIX)) { throw invalid(); }
		String[] fields = value.substring(PREFIX.length()).split("\\|", -1);
		if (fields.length != 2 || !Set.of("complete", "partial").contains(fields[0])) { throw invalid(); }
		var ids = new TreeSet<String>();
		if (!fields[1].isEmpty()) {
			for (String id : fields[1].split(",", -1)) {
				try { if (!UUID.fromString(id).toString().equals(id) || !ids.add(id)) { throw invalid(); } }
				catch (IllegalArgumentException ex) { throw invalid(); }
			}
		}
		if (!String.join(",", ids).equals(fields[1]) || hasTokens(authorization) && ids.isEmpty()) { throw invalid(); }
		return new History(fields[0].equals("complete"), Set.copyOf(ids));
	}

	private static boolean hasTokens(OAuth2Authorization authorization) {
		return authorization.getAccessToken() != null || authorization.getToken(OidcIdToken.class) != null;
	}

	private static void addTokens(OAuth2Authorization authorization, Set<String> ids) {
		if (authorization.getAccessToken() != null) { ids.add(keyId(authorization.getAccessToken().getToken().getTokenValue())); }
		var id = authorization.getToken(OidcIdToken.class);
		if (id != null) { ids.add(keyId(id.getToken().getTokenValue())); }
	}

	private static String keyId(String raw) {
		try {
			var header = SignedJWT.parse(raw).getHeader(); String id = header.getKeyID();
			if (!JWSAlgorithm.RS256.equals(header.getAlgorithm()) || id == null || !UUID.fromString(id).toString().equals(id)) { throw invalid(); }
			return id;
		}
		catch (ParseException | IllegalArgumentException ex) { throw invalid(); }
	}

	private static IllegalStateException invalid() { return new IllegalStateException("Authorization signing history is invalid"); }
	private record History(boolean complete, Set<String> ids) { }
}
