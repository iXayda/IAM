package com.ixayda.iam.authorization.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.dao.DataRetrievalFailureException;

class AuthorizationJsonCodecTests {

	private final AuthorizationJsonCodec codec = new AuthorizationJsonCodec();

	@Test
	void roundTripsOnlyJsonValuesAndExplicitInstants() {
		Instant issuedAt = Instant.parse("2026-01-01T00:00:00Z");
		Date authenticationTime = Date.from(issuedAt.minusSeconds(60));
		Map<String, Object> values = Map.of(
				"sub", "user-id",
				"iat", issuedAt,
				"auth_time", authenticationTime,
				"aud", List.of("client-id"),
				"address", Map.of("country", "CN"));

		String json = this.codec.write(values);

		assertThat(json).contains("$iam_type", "instant", "date")
			.doesNotContain(Instant.class.getName(), Date.class.getName());
		assertThat(this.codec.read(json)).isEqualTo(values);
	}

	@Test
	void preservesExplicitJsonNulls() {
		Map<String, Object> values = new LinkedHashMap<>();
		values.put("sub", "user-id");
		values.put("optional", null);
		String json = this.codec.write(values);

		assertThat(this.codec.read(json)).containsEntry("optional", null);
	}

	@Test
	void rejectsUnknownObjectGraphsAndMalformedTemporalMarkers() {
		assertThatThrownBy(() -> this.codec.write(Map.of("principal", new Object())))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessageContaining("Unsupported authorization JSON value type");
		assertThatThrownBy(() -> this.codec.write(Map.of("$iam_type", "instant", "value", "2026-01-01T00:00:00Z")))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("Authorization JSON type markers are reserved");
		assertThatThrownBy(() -> this.codec.read("""
				{"iat":{"$iam_type":"instant","value":"not-an-instant"}}
				"""))
			.isInstanceOf(DataRetrievalFailureException.class)
			.hasMessage("Authorization JSON contains an invalid temporal value");
		assertThatThrownBy(() -> this.codec.read("{\"claim\":{\"$iam_type\":\"unknown\",\"value\":\"value\"}}"))
			.isInstanceOf(DataRetrievalFailureException.class)
			.hasMessage("Authorization JSON contains an unsupported type marker");
	}

}
