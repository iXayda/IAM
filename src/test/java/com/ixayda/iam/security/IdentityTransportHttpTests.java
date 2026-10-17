package com.ixayda.iam.security;

import java.util.Map;

import com.ixayda.iam.service.IdentityBrowserSessions;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

class IdentityTransportHttpTests {

	@Test
	void trustedProxyRestoresHttpsAndTheClientAddressWithoutTrustingForwardedHost() throws Exception {
		try (var server = server("NATIVE", "127\\.0\\.0\\.1|192\\.0\\.2\\.10")) {
			var response = server.get("/api/csrf", Map.of("X-Forwarded-Proto", "https", "X-Forwarded-For", "198.51.100.42, 192.0.2.10",
					"Forwarded", "for=203.0.113.99;proto=http;host=attacker.invalid", "X-Forwarded-Host", "attacker.invalid"));
			assertThat(response.statusCode()).isEqualTo(200);
			assertThat(response.body()).isEqualTo("198.51.100.42|true|127.0.0.1");
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "http", "https,http", "http,https", "" })
	void trustedProxyMustReportAnUnambiguousHttpsConnection(String protocol) throws Exception {
		try (var server = server("NATIVE", "127\\.0\\.0\\.1")) {
			assertThat(server.get("/api/csrf", protocol.isEmpty() ? Map.of() : Map.of("X-Forwarded-Proto", protocol)).statusCode()).isEqualTo(400);
		}
	}

	@Test
	void nonProxyPeerCannotForgeTheProtocolOrBecomeATrustedHop() throws Exception {
		try (var server = server("NATIVE", "192\\.0\\.2\\.10")) {
			var response = server.get("/api/csrf", Map.of("X-Forwarded-Proto", "https", "X-Forwarded-For", "192.0.2.10",
					"Forwarded", "for=192.0.2.10;proto=https"));
			assertThat(response.statusCode()).isEqualTo(400); assertThat(response.headers().allValues("Set-Cookie")).isEmpty();
		}
	}

	@Test
	void defaultTransportIgnoresForwardedHeadersOnARealHttpConnection() throws Exception {
		try (var server = server("NONE", "127\\.0\\.0\\.1")) {
			assertThat(server.get("/api/csrf", Map.of("X-Forwarded-Proto", "https", "X-Forwarded-For", "198.51.100.42")).statusCode()).isEqualTo(400);
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "127.0.0.1", "192.0.2.10" })
	void environmentAllowlistAndRuntimeValveUseTheSamePropertyBinding(String proxy) throws Exception {
		var boundary = new IdentityBrowserBoundaryFilter(mock(IdentityBrowserSessions.class), 100, 1, (request, response) -> { });
		try (var server = new TransportHttpTestSupport(Map.of("SERVER_FORWARD_HEADERS_STRATEGY", "NATIVE",
				"SERVER_TOMCAT_REMOTEIP_INTERNAL_PROXIES", java.util.regex.Pattern.quote(proxy)), boundary, true)) {
			var response = server.get("/api/csrf", Map.of("X-Forwarded-Proto", "https", "X-Forwarded-For", "198.51.100.42"));
			assertThat(response.statusCode()).isEqualTo(proxy.equals("127.0.0.1") ? 200 : 400);
			if (response.statusCode() == 200) { assertThat(response.body()).isEqualTo("198.51.100.42|true|127.0.0.1"); }
		}
	}

	private static TransportHttpTestSupport server(String strategy, String proxies) throws Exception {
		var boundary = new IdentityBrowserBoundaryFilter(mock(IdentityBrowserSessions.class), 100, 1, (request, response) -> { });
		return new TransportHttpTestSupport(Map.of("server.forward-headers-strategy", strategy, "server.tomcat.remoteip.internal-proxies", proxies), boundary);
	}
}
