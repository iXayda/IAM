package com.ixayda.iam.authorization.internal;

import java.net.URI;
import java.time.Clock;
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

class AdminTokenJwtValidatorTests {

	private static final Instant NOW = Instant.parse("2026-07-20T12:00:00Z");

	private static final String AUDIENCE = "https://admin.example.test/iam/admin";

	private static final String TENANT_ID = "00000000-0000-0000-0000-000000000001";

	private static final String USER_ID = "019c61d7-47d1-79ca-8052-1b731e742901";

	private static final String SESSION_ID = "019c61d7-47d1-79ca-8052-1b731e742902";

	private final AdminTokenJwtValidator validator = new AdminTokenJwtValidator(URI.create(AUDIENCE),
			Clock.fixed(NOW, ZoneOffset.UTC));

	@Test
	void acceptsTheExactAdminTokenProfile() {
		assertThat(this.validator.validate(token(NOW.minusSeconds(1), NOW.plusSeconds(299), (claims) -> {
		})).hasErrors()).isFalse();
	}

	@ParameterizedTest(name = "{0}")
	@MethodSource("invalidClaims")
	void rejectsInvalidAdminTokenClaims(String description, Consumer<Map<String, Object>> mutation) {
		assertInvalid(this.validator.validate(token(NOW.minusSeconds(1), NOW.plusSeconds(299), mutation)));
	}

	@ParameterizedTest(name = "{0}")
	@MethodSource("invalidLifetimes")
	void rejectsInvalidAdminTokenLifetimes(String description, Instant issuedAt, Instant expiresAt) {
		assertInvalid(this.validator.validate(token(issuedAt, expiresAt, (claims) -> {
		})));
	}

	private static Stream<Arguments> invalidClaims() {
		return Stream.of(
				arguments("missing audience", mutation((claims) -> claims.remove("aud"))),
				arguments("wrong audience", mutation((claims) -> claims.put("aud", List.of("https://api.example.test")))),
				arguments("additional audience", mutation((claims) -> claims.put("aud", List.of(AUDIENCE,
						"https://api.example.test")))),
				arguments("non-list audience", mutation((claims) -> claims.put("aud", AUDIENCE))),
				arguments("missing tenant", mutation((claims) -> claims.remove(ServiceTokenJwtCustomizer.TENANT_ID_CLAIM))),
				arguments("non-string tenant", mutation((claims) -> claims.put(ServiceTokenJwtCustomizer.TENANT_ID_CLAIM,
						List.of(TENANT_ID)))),
				arguments("malformed tenant", mutation((claims) -> claims.put(ServiceTokenJwtCustomizer.TENANT_ID_CLAIM,
						"not-a-uuid"))),
				arguments("non-canonical tenant", mutation((claims) -> claims.put(ServiceTokenJwtCustomizer.TENANT_ID_CLAIM,
						"00000000-0000-0000-0000-00000000000A"))),
				arguments("missing user", mutation((claims) -> claims.remove(AdminTokenJwtCustomizer.USER_ID_CLAIM))),
				arguments("non-string subject", mutation((claims) -> claims.put("sub", List.of(USER_ID)))),
				arguments("mismatched subject", mutation((claims) -> claims.put("sub",
						"019c61d7-47d1-79ca-8052-1b731e742999"))),
				arguments("missing session", mutation((claims) -> claims.remove(AdminTokenJwtCustomizer.SESSION_ID_CLAIM))),
				arguments("missing scope", mutation((claims) -> claims.remove("scope"))),
				arguments("missing admin scope", mutation((claims) -> claims.put("scope", List.of("openid")))),
				arguments("non-list scope", mutation((claims) -> claims.put("scope", AdminTokenJwtCustomizer.ADMIN_SCOPE))),
				arguments("missing authentication method", mutation((claims) ->
						claims.remove(AdminTokenJwtCustomizer.AUTHENTICATION_METHOD_CLAIM))),
				arguments("unknown authentication method", mutation((claims) -> claims.put(
						AdminTokenJwtCustomizer.AUTHENTICATION_METHOD_CLAIM, "unknown"))),
				arguments("missing authentication time", mutation((claims) ->
						claims.remove(AdminTokenJwtCustomizer.AUTHENTICATION_TIME_CLAIM))),
				arguments("malformed authentication time", mutation((claims) -> claims.put(
						AdminTokenJwtCustomizer.AUTHENTICATION_TIME_CLAIM, "not-a-time"))),
				arguments("authentication after issuance", mutation((claims) -> claims.put(
						AdminTokenJwtCustomizer.AUTHENTICATION_TIME_CLAIM, NOW))));
	}

	private static Stream<Arguments> invalidLifetimes() {
		return Stream.of(arguments("missing issued at", null, NOW.plusSeconds(300)),
				arguments("missing expiration", NOW, null),
				arguments("lifetime over one hour", NOW, NOW.plusSeconds(3601)),
				arguments("issued too far in the future", NOW.plusSeconds(31), NOW.plusSeconds(300)));
	}

	private static Consumer<Map<String, Object>> mutation(Consumer<Map<String, Object>> mutation) {
		return mutation;
	}

	private static Jwt token(Instant issuedAt, Instant expiresAt, Consumer<Map<String, Object>> mutation) {
		Map<String, Object> claims = new LinkedHashMap<>();
		claims.put("iss", "https://issuer.example.test");
		claims.put("sub", USER_ID);
		claims.put("aud", List.of(AUDIENCE));
		claims.put("scope", List.of("openid", AdminTokenJwtCustomizer.ADMIN_SCOPE));
		claims.put(ServiceTokenJwtCustomizer.TENANT_ID_CLAIM, TENANT_ID);
		claims.put(AdminTokenJwtCustomizer.USER_ID_CLAIM, USER_ID);
		claims.put(AdminTokenJwtCustomizer.SESSION_ID_CLAIM, SESSION_ID);
		claims.put(AdminTokenJwtCustomizer.AUTHENTICATION_METHOD_CLAIM, "password");
		claims.put(AdminTokenJwtCustomizer.AUTHENTICATION_TIME_CLAIM, NOW.minusSeconds(60).getEpochSecond());
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
