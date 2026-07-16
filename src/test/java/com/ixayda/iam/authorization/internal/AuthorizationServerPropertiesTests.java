package com.ixayda.iam.authorization.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.URI;

import org.junit.jupiter.api.Test;

class AuthorizationServerPropertiesTests {

	@Test
	void acceptsHttpsAndLoopbackDevelopmentIssuers() {
		assertThat(new AuthorizationServerProperties(URI.create("https://issuer.example.test/iam")).issuer())
			.isEqualTo(URI.create("https://issuer.example.test/iam"));
		assertThat(new AuthorizationServerProperties(URI.create("http://127.0.0.1:8080")).issuer())
			.isEqualTo(URI.create("http://127.0.0.1:8080"));
		assertThat(new AuthorizationServerProperties(URI.create("http://[::1]:8080")).issuer())
			.isEqualTo(URI.create("http://[::1]:8080"));
	}

	@Test
	void rejectsUntrustedOrAmbiguousIssuers() {
		assertThatThrownBy(() -> new AuthorizationServerProperties(null))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new AuthorizationServerProperties(URI.create("/relative")))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new AuthorizationServerProperties(URI.create("http://issuer.example.test")))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessageContaining("HTTPS");
		assertThatThrownBy(() -> new AuthorizationServerProperties(URI.create("https://user@issuer.example.test")))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new AuthorizationServerProperties(URI.create("https://issuer.example.test?q=1")))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new AuthorizationServerProperties(URI.create("https://issuer.example.test#part")))
			.isInstanceOf(IllegalArgumentException.class);
	}

}
