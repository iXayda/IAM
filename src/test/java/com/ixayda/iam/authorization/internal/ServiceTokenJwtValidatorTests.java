package com.ixayda.iam.authorization.internal;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class ServiceTokenJwtValidatorTests {

	private static final Instant NOW = Instant.parse("2026-07-18T12:00:00Z");

	private static final String AUDIENCE = "https://scim.example.test/scim/v2";

	private static final String TENANT_ID = "00000000-0000-0000-0000-000000000001";

	private static final String CLIENT_ID = "scim-service-client";

	private final ServiceTokenJwtValidator validator = new ServiceTokenJwtValidator(URI.create(AUDIENCE),
			Clock.fixed(NOW, ZoneOffset.UTC));

	@Test
	void acceptsTheExactServiceTokenProfile() {
		assertThat(this.validator.validate(token(NOW.minusSeconds(1), NOW.plusSeconds(299), (claims) -> {
		})).hasErrors()).isFalse();
	}

	@ParameterizedTest(name = "{0}")
	@MethodSource("invalidIdentityClaims")
	void rejectsInvalidAudienceAndIdentityClaims(String description, Consumer<Map<String, Object>> mutation) {
		OAuth2TokenValidatorResult result =
				this.validator.validate(token(NOW.minusSeconds(1), NOW.plusSeconds(299), mutation));

		assertInvalid(result);
	}

	@ParameterizedTest(name = "{0}")
	@MethodSource("invalidLifetimes")
	void rejectsInvalidServiceTokenLifetimes(String description, Instant issuedAt, Instant expiresAt) {
		assertInvalid(this.validator.validate(token(issuedAt, expiresAt, (claims) -> {
		})));
	}

	private static Stream<Arguments> invalidIdentityClaims() {
		return Stream.of(
				arguments("missing audience", mutation((claims) -> claims.remove("aud"))),
				arguments("wrong audience", mutation((claims) -> claims.put("aud", List.of("https://api.example.test")))),
				arguments("additional audience", mutation((claims) -> claims.put("aud", List.of(AUDIENCE,
						"https://api.example.test")))),
				arguments("missing tenant", mutation((claims) -> claims.remove(ServiceTokenJwtCustomizer.TENANT_ID_CLAIM))),
				arguments("malformed tenant", mutation((claims) -> claims.put(ServiceTokenJwtCustomizer.TENANT_ID_CLAIM,
						"not-a-uuid"))),
				arguments("non-canonical tenant", mutation((claims) -> claims.put(ServiceTokenJwtCustomizer.TENANT_ID_CLAIM,
						"019C61D7-47D1-79CA-8052-1B731E742901"))),
				arguments("missing client", mutation((claims) -> claims.remove(ServiceTokenJwtCustomizer.CLIENT_ID_CLAIM))),
				arguments("invalid client", mutation((claims) -> claims.put(ServiceTokenJwtCustomizer.CLIENT_ID_CLAIM,
						"client id"))),
				arguments("missing subject", mutation((claims) -> claims.remove("sub"))),
				arguments("mismatched subject", mutation((claims) -> claims.put("sub", "another-client"))));
	}

	private static Stream<Arguments> invalidLifetimes() {
		return Stream.of(arguments("missing issued at", null, NOW.plusSeconds(300)),
				arguments("missing expiration", NOW, null),
				arguments("lifetime over five minutes", NOW, NOW.plusSeconds(301)),
				arguments("issued too far in the future", NOW.plusSeconds(31), NOW.plusSeconds(300)));
	}

	private static Consumer<Map<String, Object>> mutation(Consumer<Map<String, Object>> mutation) {
		return mutation;
	}

	private static Jwt token(Instant issuedAt, Instant expiresAt, Consumer<Map<String, Object>> mutation) {
		Map<String, Object> claims = new LinkedHashMap<>();
		claims.put("iss", "https://issuer.example.test");
		claims.put("sub", CLIENT_ID);
		claims.put("aud", List.of(AUDIENCE));
		claims.put(ServiceTokenJwtCustomizer.TENANT_ID_CLAIM, TENANT_ID);
		claims.put(ServiceTokenJwtCustomizer.CLIENT_ID_CLAIM, CLIENT_ID);
		mutation.accept(claims);
		return new Jwt("token", issuedAt, expiresAt, Map.of("alg", "RS256"), claims);
	}

	private static void assertInvalid(OAuth2TokenValidatorResult result) {
		assertThat(result.hasErrors()).isTrue();
		assertThat(result.getErrors()).singleElement()
			.extracting((error) -> error.getErrorCode())
			.isEqualTo(OAuth2ErrorCodes.INVALID_TOKEN);
	}

}
