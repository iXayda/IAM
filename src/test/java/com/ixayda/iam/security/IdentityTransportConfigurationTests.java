package com.ixayda.iam.security;

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.web.server.servlet.ConfigurableServletWebServerFactory;
import org.springframework.mock.env.MockEnvironment;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

class IdentityTransportConfigurationTests {

	@Test
	void defaultTransportDoesNotProcessForwardedHeaders() { validate(Map.of()); }

	@Test
	void nativeTransportRequiresOnlyTheExplicitProxyAddressPattern() {
		validate(Map.of("server.forward-headers-strategy", "NATIVE", "server.tomcat.remoteip.internal-proxies", "127\\.0\\.0\\.1|192\\.0\\.2\\.10"));
	}

	@ParameterizedTest
	@ValueSource(strings = { "", " ", ".*", ".+", "[" })
	void missingUnrestrictedAndInvalidAllowlistsAreRejected(String proxies) {
		assertThatIllegalArgumentException().isThrownBy(() -> validate(Map.of("server.forward-headers-strategy", "NATIVE", "server.tomcat.remoteip.internal-proxies", proxies)));
	}

	@Test
	void nativeTransportCannotUseTomcatsImplicitPrivateNetworkTrust() {
		assertThatIllegalArgumentException().isThrownBy(() -> validate(Map.of("server.forward-headers-strategy", "NATIVE")));
	}

	@Test
	void frameworkTransportCannotTrustHeadersWithoutCheckingThePeer() {
		assertThatIllegalArgumentException().isThrownBy(() -> validate(Map.of("server.forward-headers-strategy", "FRAMEWORK")));
	}

	@ParameterizedTest
	@ValueSource(strings = { "protocol-header", "remote-ip-header", "trusted-proxies" })
	void nativeTomcatOverridesCannotSilentlyEnableForwardingInNoneMode(String property) {
		assertThatIllegalArgumentException().isThrownBy(() -> validate(Map.of("server.tomcat.remoteip." + property, "untrusted")));
	}

	@ParameterizedTest
	@ValueSource(strings = { "protocol-header", "remote-ip-header", "protocol-header-https-value", "host-header", "port-header", "trusted-proxies" })
	void unsupportedHeaderAndTrustOverridesAreRejected(String property) {
		var settings = new HashMap<>(Map.of("server.forward-headers-strategy", "NATIVE", "server.tomcat.remoteip.internal-proxies", "127\\.0\\.0\\.1"));
		settings.put("server.tomcat.remoteip." + property, "untrusted");
		assertThatIllegalArgumentException().isThrownBy(() -> validate(settings));
	}

	private static void validate(Map<String, String> settings) {
		var environment = new MockEnvironment().withProperty("server.tomcat.remoteip.host-header", "").withProperty("server.tomcat.remoteip.port-header", "");
		settings.forEach(environment::setProperty);
		new IdentityTransportConfiguration().transportPolicy(environment).customize(mock(ConfigurableServletWebServerFactory.class));
	}
}
