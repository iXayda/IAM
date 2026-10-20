package com.ixayda.iam.model;

import java.net.URI;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/** A pending, browser-owned request carries no authentication or application authority. */
public record IdentityAuthorizationInteraction(UUID id, Request request, long originalAuthenticatedAt,
		Instant createdAt, Instant expiresAt) {

	public IdentityAuthorizationInteraction {
		Objects.requireNonNull(id); Objects.requireNonNull(request); Objects.requireNonNull(createdAt); Objects.requireNonNull(expiresAt);
		if (originalAuthenticatedAt < 0 || originalAuthenticatedAt > createdAt.toEpochMilli()
				|| !expiresAt.equals(createdAt.plusSeconds(600))) { throw new IllegalArgumentException("Invalid authorization interaction bounds"); }
	}

	@Override
	public String toString() { return "IdentityAuthorizationInteraction[REDACTED]"; }

	/** Canonical request shape; the protocol workflow must also validate the current registered client. */
	public record Request(String authorizationUri, UUID clientId, String redirectUri, String state,
			Set<String> scopes, Map<String, String> parameters) {

		private static final Set<String> PARAMETERS = Set.of("code_challenge", "code_challenge_method", "nonce", "prompt", "max_age", "response_mode");

		public Request {
			Objects.requireNonNull(clientId); scopes = Set.copyOf(scopes); parameters = Map.copyOf(parameters);
			if (!https(authorizationUri, false) || !https(redirectUri, true) || !text(state, 512, false)
					|| !scopes.contains("openid") || !Set.of("openid", "profile", "offline_access").containsAll(scopes)
					|| !PARAMETERS.containsAll(parameters.keySet())
					|| parameters.entrySet().stream().anyMatch(entry -> !text(entry.getValue(), entry.getKey().equals("nonce") ? 256 : 512, entry.getKey().equals("prompt")))
					|| !"S256".equals(parameters.get("code_challenge_method")) || !challenge(parameters.get("code_challenge"))
					|| parameters.containsKey("response_mode") && !"query".equals(parameters.get("response_mode"))) {
				throw new IllegalArgumentException("Invalid authorization interaction request");
			}
			if (parameters.containsKey("prompt")) {
				String[] prompts = parameters.get("prompt").split(" ", -1);
				var values = Set.copyOf(Arrays.asList(prompts));
				if (values.size() != prompts.length || !Set.of("login", "consent", "select_account").containsAll(values)) {
					// prompt=none must never create an interactive workflow.
					throw new IllegalArgumentException("Invalid authorization interaction prompt");
				}
			}
			if (parameters.containsKey("max_age")) {
				String value = parameters.get("max_age");
				if (!value.matches("[0-9]{1,19}")) { throw new IllegalArgumentException("Invalid authorization interaction age"); }
				try { Long.parseLong(value); }
				catch (NumberFormatException ex) { throw new IllegalArgumentException("Invalid authorization interaction age"); }
			}
		}

		@Override
		public String toString() { return "AuthorizationInteractionRequest[REDACTED]"; }

		private static boolean https(String value, boolean queryAllowed) {
			if (!text(value, 2048, false)) { return false; }
			try {
				var uri = URI.create(value);
				return "https".equals(uri.getScheme()) && uri.getHost() != null && uri.getRawUserInfo() == null && uri.getRawFragment() == null
						&& (queryAllowed || uri.getRawQuery() == null) && uri.getPort() != 0 && uri.getPort() >= -1 && uri.getPort() <= 65535
						&& !uri.getRawAuthority().endsWith(":") && !controls(uri.getPath()) && !controls(uri.getQuery());
			}
			catch (IllegalArgumentException ex) { return false; }
		}

		private static boolean controls(String value) { return value != null && value.chars().anyMatch(character -> character < 0x20 || character == 0x7f); }
		private static boolean text(String value, int maximum, boolean spaces) {
			return value != null && !value.isEmpty() && value.length() <= maximum && value.chars().allMatch(character -> character >= (spaces ? 0x20 : 0x21) && character <= 0x7e);
		}
		private static boolean challenge(String value) {
			return value != null && value.matches("[A-Za-z0-9_-]{43}")
					&& Base64.getUrlEncoder().withoutPadding().encodeToString(Base64.getUrlDecoder().decode(value)).equals(value);
		}
	}

}
