package com.ixayda.iam.authorization.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.URI;

import org.junit.jupiter.api.Test;

class AuthorizationServerPropertiesTests {

	private static final URI SERVICE_AUDIENCE = URI.create("https://scim.example.test/scim/v2");

	@Test
	void acceptsHttpsAndLoopbackDevelopmentIssuers() {
		assertThat(new AuthorizationServerProperties(URI.create("https://issuer.example.test/iam"), SERVICE_AUDIENCE).issuer())
			.isEqualTo(URI.create("https://issuer.example.test/iam"));
		assertThat(new AuthorizationServerProperties(URI.create("http://127.0.0.1:8080"),
				URI.create("http://127.0.0.1:8080/scim/v2")).issuer())
			.isEqualTo(URI.create("http://127.0.0.1:8080"));
		assertThat(new AuthorizationServerProperties(URI.create("http://[::1]:8080"),
				URI.create("http://[::1]:8080/scim/v2")).issuer())
			.isEqualTo(URI.create("http://[::1]:8080"));
		assertThat(new AuthorizationServerProperties(URI.create("https://issuer.example.test"), SERVICE_AUDIENCE)
			.serviceTokenAudience()).isEqualTo(SERVICE_AUDIENCE);
	}

	@Test
	void rejectsUntrustedOrAmbiguousIssuers() {
		assertThatThrownBy(() -> new AuthorizationServerProperties(null, SERVICE_AUDIENCE))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new AuthorizationServerProperties(URI.create("/relative"), SERVICE_AUDIENCE))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new AuthorizationServerProperties(URI.create("http://issuer.example.test"),
				SERVICE_AUDIENCE))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessageContaining("HTTPS");
		assertThatThrownBy(() -> new AuthorizationServerProperties(URI.create("https://user@issuer.example.test"),
				SERVICE_AUDIENCE))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new AuthorizationServerProperties(URI.create("https://issuer.example.test?q=1"),
				SERVICE_AUDIENCE))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new AuthorizationServerProperties(URI.create("https://issuer.example.test#part"),
				SERVICE_AUDIENCE))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new AuthorizationServerProperties(URI.create("https://issuer.example.test"), null))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new AuthorizationServerProperties(URI.create("https://issuer.example.test"),
				URI.create("http://scim.example.test/scim/v2")))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessageContaining("HTTPS");
	}

}
