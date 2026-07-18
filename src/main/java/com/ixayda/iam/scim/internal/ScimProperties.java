package com.ixayda.iam.scim.internal;

import java.net.URI;
import java.util.Locale;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.web.util.UriComponentsBuilder;

@ConfigurationProperties("iam.scim")
record ScimProperties(URI baseUrl) {

	ScimProperties {
		if (baseUrl == null || !baseUrl.isAbsolute() || baseUrl.getHost() == null || baseUrl.getRawUserInfo() != null
				|| baseUrl.getRawQuery() != null || baseUrl.getRawFragment() != null
				|| !baseUrl.getRawPath().endsWith(ScimMetadataController.BASE_PATH)) {
			throw new IllegalArgumentException(
					"The SCIM base URL must be an absolute HTTP(S) URL ending in /scim/v2 without user info, query, or fragment");
		}
		String scheme = baseUrl.getScheme().toLowerCase(Locale.ROOT);
		if (!"https".equals(scheme) && !("http".equals(scheme) && isLoopback(baseUrl.getHost()))) {
			throw new IllegalArgumentException("The SCIM base URL must use HTTPS except for a loopback development address");
		}
	}

	URI endpoint(String path) {
		return UriComponentsBuilder.fromUri(this.baseUrl).path(path).build().encode().toUri();
	}

	URI endpoint(String path, String id) {
		return UriComponentsBuilder.fromUri(this.baseUrl).path(path).path("/").pathSegment(id).build().encode().toUri();
	}

	private static boolean isLoopback(String host) {
		return "localhost".equalsIgnoreCase(host) || "127.0.0.1".equals(host) || "::1".equals(host)
				|| "[::1]".equals(host);
	}

}
