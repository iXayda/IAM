package com.ixayda.iam.authorization.internal;

import java.net.URI;
import java.util.Locale;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("iam.authorization.server")
record AuthorizationServerProperties(URI issuer, URI serviceTokenAudience) {

	AuthorizationServerProperties {
		issuer = trustedUri(issuer, "authorization server issuer");
		serviceTokenAudience = trustedUri(serviceTokenAudience, "service token audience");
	}

	private static URI trustedUri(URI value, String name) {
		if (value == null || !value.isAbsolute() || value.getHost() == null || value.getRawUserInfo() != null
				|| value.getRawQuery() != null || value.getRawFragment() != null) {
			throw new IllegalArgumentException("The " + name
					+ " must be an absolute HTTP(S) URL without user info, query, or fragment");
		}
		String scheme = value.getScheme().toLowerCase(Locale.ROOT);
		if (!"https".equals(scheme) && !("http".equals(scheme) && isLoopback(value.getHost()))) {
			throw new IllegalArgumentException(
					"The " + name + " must use HTTPS except for a loopback development address");
		}
		return value;
	}

	private static boolean isLoopback(String host) {
		return "localhost".equalsIgnoreCase(host) || "127.0.0.1".equals(host) || "::1".equals(host)
				|| "[::1]".equals(host);
	}

}
