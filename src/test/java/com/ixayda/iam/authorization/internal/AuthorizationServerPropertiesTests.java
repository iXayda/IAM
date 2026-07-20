package com.ixayda.iam.authorization.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.URI;

import org.junit.jupiter.api.Test;

class AuthorizationServerPropertiesTests {

	private static final URI SERVICE_AUDIENCE = URI.create("https://scim.example.test/scim/v2");

	private static final URI ADMIN_AUDIENCE = URI.create("https://admin.example.test/iam/admin");

	@Test
	void acceptsHttpsAndLoopbackDevelopmentIssuers() {
		assertThat(new AuthorizationServerProperties(URI.create("https://issuer.example.test/iam"), SERVICE_AUDIENCE,
				ADMIN_AUDIENCE).issuer())
			.isEqualTo(URI.create("https://issuer.example.test/iam"));
		assertThat(new AuthorizationServerProperties(URI.create("http://127.0.0.1:8080"),
				URI.create("http://127.0.0.1:8080/scim/v2"), URI.create("http://127.0.0.1:8080/iam/admin")).issuer())
			.isEqualTo(URI.create("http://127.0.0.1:8080"));
		assertThat(new AuthorizationServerProperties(URI.create("http://[::1]:8080"),
				URI.create("http://[::1]:8080/scim/v2"), URI.create("http://[::1]:8080/iam/admin")).issuer())
			.isEqualTo(URI.create("http://[::1]:8080"));
		assertThat(new AuthorizationServerProperties(URI.create("https://issuer.example.test"), SERVICE_AUDIENCE,
				ADMIN_AUDIENCE)
			.serviceTokenAudience()).isEqualTo(SERVICE_AUDIENCE);
		assertThat(new AuthorizationServerProperties(URI.create("https://issuer.example.test"), SERVICE_AUDIENCE,
				ADMIN_AUDIENCE).adminTokenAudience()).isEqualTo(ADMIN_AUDIENCE);
	}

	@Test
	void rejectsUntrustedOrAmbiguousIssuers() {
		assertThatThrownBy(() -> new AuthorizationServerProperties(null, SERVICE_AUDIENCE, ADMIN_AUDIENCE))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new AuthorizationServerProperties(URI.create("/relative"), SERVICE_AUDIENCE,
				ADMIN_AUDIENCE))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new AuthorizationServerProperties(URI.create("http://issuer.example.test"),
				SERVICE_AUDIENCE, ADMIN_AUDIENCE))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessageContaining("HTTPS");
		assertThatThrownBy(() -> new AuthorizationServerProperties(URI.create("https://user@issuer.example.test"),
				SERVICE_AUDIENCE, ADMIN_AUDIENCE))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new AuthorizationServerProperties(URI.create("https://issuer.example.test?q=1"),
				SERVICE_AUDIENCE, ADMIN_AUDIENCE))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new AuthorizationServerProperties(URI.create("https://issuer.example.test#part"),
				SERVICE_AUDIENCE, ADMIN_AUDIENCE))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new AuthorizationServerProperties(URI.create("https://issuer.example.test"), null,
				ADMIN_AUDIENCE))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new AuthorizationServerProperties(URI.create("https://issuer.example.test"),
				URI.create("http://scim.example.test/scim/v2"), ADMIN_AUDIENCE))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessageContaining("HTTPS");
		assertThatThrownBy(() -> new AuthorizationServerProperties(URI.create("https://issuer.example.test"),
				SERVICE_AUDIENCE, null)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new AuthorizationServerProperties(URI.create("https://issuer.example.test"),
				SERVICE_AUDIENCE, URI.create("http://admin.example.test/iam/admin")))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessageContaining("HTTPS");
		assertThatThrownBy(() -> new AuthorizationServerProperties(URI.create("https://issuer.example.test"),
				SERVICE_AUDIENCE, SERVICE_AUDIENCE))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessageContaining("different");
	}

}
