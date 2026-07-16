package com.ixayda.iam.authorization.internal;

import java.net.URI;
import java.util.Locale;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("iam.authorization.server")
record AuthorizationServerProperties(URI issuer) {

	AuthorizationServerProperties {
		if (issuer == null || !issuer.isAbsolute() || issuer.getHost() == null || issuer.getRawUserInfo() != null
				|| issuer.getRawQuery() != null || issuer.getRawFragment() != null) {
			throw new IllegalArgumentException(
					"The authorization server issuer must be an absolute HTTP(S) URL without user info, query, or fragment");
		}
		String scheme = issuer.getScheme().toLowerCase(Locale.ROOT);
		if (!"https".equals(scheme) && !("http".equals(scheme) && isLoopback(issuer.getHost()))) {
			throw new IllegalArgumentException(
					"The authorization server issuer must use HTTPS except for a loopback development address");
		}
	}

	private static boolean isLoopback(String host) {
		return "localhost".equalsIgnoreCase(host) || "127.0.0.1".equals(host) || "::1".equals(host)
				|| "[::1]".equals(host);
	}

}
