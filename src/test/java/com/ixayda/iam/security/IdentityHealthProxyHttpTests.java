package com.ixayda.iam.security;

import java.util.Map;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.*;

class IdentityHealthProxyHttpTests {

	@Test
	void trustedProxyCanReachHealthWithoutCreatingACookie() throws Exception {
		try (var server = server("127\\.0\\.0\\.1")) {
			for (String path : IdentityHealthRequestFilter.PATHS) {
				var response = server.get(path, Map.of("X-Forwarded-Proto", "https", "Cookie", "__Host-IAMSESSION=stale-probe"));
				assertThat(response.statusCode()).isEqualTo(200); assertThat(response.headers().allValues("Set-Cookie")).isEmpty();
			}
		}
	}

	@Test
	void aNonProxyPeerCannotUseHealthByForgingHttps() throws Exception {
		try (var server = server("192\\.0\\.2\\.10")) {
			assertThat(server.get("/readyz", Map.of("X-Forwarded-Proto", "https")).statusCode()).isEqualTo(400);
		}
	}

	@Test
	void aTrustedPeerStillNeedsToReportHttpsForHealth() throws Exception {
		try (var server = server("127\\.0\\.0\\.1")) {
			assertThat(server.get("/readyz", Map.of()).statusCode()).isEqualTo(400);
		}
	}

	private static TransportHttpTestSupport server(String proxies) throws Exception {
		return new TransportHttpTestSupport(Map.of("server.forward-headers-strategy", "NATIVE", "server.tomcat.remoteip.internal-proxies", proxies),
				new IdentityHealthRequestFilter((request, response) -> { }));
	}
}
