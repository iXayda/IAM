package com.ixayda.iam.client;

import java.net.URI;
import java.util.Objects;

public record ClientRedirectUri(String value) {

	private static final int MAX_LENGTH = 2048;

	public ClientRedirectUri {
		Objects.requireNonNull(value, "Client redirect URI must not be null");
		if (value.isEmpty() || value.length() > MAX_LENGTH || !value.equals(value.strip())
				|| !value.chars().allMatch(ClientRedirectUri::isUriCharacter) || value.indexOf('*') >= 0) {
			throw invalidUri();
		}

		URI uri;
		try {
			uri = URI.create(value);
		}
		catch (IllegalArgumentException exception) {
			throw invalidUri(exception);
		}
		validate(uri);
	}

	private static void validate(URI uri) {
		String scheme = uri.getScheme();
		String host = uri.getHost();
		int port = uri.getPort();
		if (!uri.isAbsolute() || uri.isOpaque() || scheme == null || host == null || host.isBlank()
				|| uri.getRawUserInfo() != null || uri.getRawFragment() != null
				|| !Objects.equals(uri.getRawPath(), uri.normalize().getRawPath())
				|| uri.getRawAuthority().endsWith(":") || port == 0 || port > 65535) {
			throw invalidUri();
		}

		if (!"https".equalsIgnoreCase(scheme)) {
			throw invalidUri();
		}
	}

	private static boolean isUriCharacter(int character) {
		return character >= 0x21 && character <= 0x7e;
	}

	private static IllegalArgumentException invalidUri() {
		return new IllegalArgumentException(
				"Client redirect URI must be an absolute ASCII HTTPS URI of at most 2048 characters without user info, fragments, wildcards, invalid ports, or dot segments");
	}

	private static IllegalArgumentException invalidUri(IllegalArgumentException cause) {
		return new IllegalArgumentException(
				"Client redirect URI must be an absolute ASCII HTTPS URI of at most 2048 characters without user info, fragments, wildcards, invalid ports, or dot segments",
				cause);
	}

	@Override
	public String toString() {
		return this.value;
	}

}
