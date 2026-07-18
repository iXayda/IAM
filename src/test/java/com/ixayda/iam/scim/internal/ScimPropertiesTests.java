package com.ixayda.iam.scim.internal;

import java.net.URI;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ScimPropertiesTests {

	@Test
	void acceptsHttpsAndLoopbackBaseUrls() {
		assertThat(new ScimProperties(URI.create("https://iam.example.test/scim/v2")).baseUrl())
			.isEqualTo(URI.create("https://iam.example.test/scim/v2"));
		assertThat(new ScimProperties(URI.create("http://127.0.0.1:8080/scim/v2")).baseUrl())
			.isEqualTo(URI.create("http://127.0.0.1:8080/scim/v2"));
		assertThat(new ScimProperties(URI.create("http://[::1]:8080/scim/v2")).baseUrl())
			.isEqualTo(URI.create("http://[::1]:8080/scim/v2"));
	}

	@Test
	void buildsCanonicalEndpointsAndEncodesItemIdentifiers() {
		ScimProperties properties = new ScimProperties(URI.create("https://iam.example.test/scim/v2"));

		assertThat(properties.endpoint("/Schemas"))
			.isEqualTo(URI.create("https://iam.example.test/scim/v2/Schemas"));
		assertThat(properties.endpoint("/Schemas", "urn:ietf:params:scim:schemas:core:2.0:User"))
			.isEqualTo(URI.create(
					"https://iam.example.test/scim/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:User"));
	}

	@Test
	void rejectsUntrustedOrAmbiguousBaseUrls() {
		assertThatThrownBy(() -> new ScimProperties(null)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new ScimProperties(URI.create("/scim/v2")))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new ScimProperties(URI.create("http://iam.example.test/scim/v2")))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessageContaining("HTTPS");
		assertThatThrownBy(() -> new ScimProperties(URI.create("https://user@iam.example.test/scim/v2")))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new ScimProperties(URI.create("https://iam.example.test/scim/v2?q=1")))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new ScimProperties(URI.create("https://iam.example.test/scim/v2#part")))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new ScimProperties(URI.create("https://iam.example.test/scim/v2/")))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new ScimProperties(URI.create("https://iam.example.test/api")))
			.isInstanceOf(IllegalArgumentException.class);
	}

}
