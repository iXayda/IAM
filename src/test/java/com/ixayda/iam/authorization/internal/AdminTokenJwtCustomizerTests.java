package com.ixayda.iam.authorization.internal;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.ixayda.iam.authorization.AdminAccessTokenClaims;
import com.ixayda.iam.authorization.AdminMfaPolicy;
import com.ixayda.iam.authorization.AuthorizationPrincipal;
import com.ixayda.iam.authorization.AuthorizationUserAuthentication;
import com.ixayda.iam.client.OAuthClientSettings;
import com.ixayda.iam.session.SessionAuthenticationMethod;
import com.ixayda.iam.session.SessionId;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AdminTokenJwtCustomizerTests {

	private static final Instant NOW = Instant.parse("2026-07-20T00:00:00Z");

	private static final Duration VALID_DURATION = Duration.ofMinutes(15);

	private static final UserId USER_ID = UserId.from("019f5aff-f979-7653-8001-67ea4274f902");

	private static final SessionId SESSION_ID = SessionId.from("019f5aff-f979-7653-8001-67ea4274f903");

	private final AdminTokenJwtCustomizer customizer = new AdminTokenJwtCustomizer(
			URI.create("https://admin.example.test/iam/admin"), new AdminMfaPolicy(VALID_DURATION),
			Clock.fixed(NOW, ZoneOffset.UTC));

	@Test
	void addsAdminClaimsWhenTheSecondFactorIsRecent() {
		JwtClaimsSet.Builder claims = JwtClaimsSet.builder();
		JwtEncodingContext context = context(authentication(NOW.minusSeconds(60)), claims,
				Set.of(AdminAccessTokenClaims.SCOPE));

		this.customizer.customize(context);

		assertThat(claims.build().getClaims())
			.containsEntry(AdminAccessTokenClaims.USER_ID, USER_ID.toString())
			.containsEntry(AdminAccessTokenClaims.SESSION_ID, SESSION_ID.toString());
	}

	@Test
	void rejectsAdminTokensWithoutARecentSecondFactor() {
		JwtEncodingContext missing = context(authentication(null), JwtClaimsSet.builder(),
				Set.of(AdminAccessTokenClaims.SCOPE));
		JwtEncodingContext expired = context(authentication(NOW.minus(VALID_DURATION)), JwtClaimsSet.builder(),
				Set.of(AdminAccessTokenClaims.SCOPE));

		assertThatThrownBy(() -> this.customizer.customize(missing))
			.isInstanceOfSatisfying(OAuth2AuthenticationException.class,
					(error) -> assertThat(error.getError().getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_GRANT));
		assertThatThrownBy(() -> this.customizer.customize(expired))
			.isInstanceOfSatisfying(OAuth2AuthenticationException.class,
					(error) -> assertThat(error.getError().getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_GRANT));
	}

	@Test
	void leavesTokensWithoutTheAdminScopeUntouched() {
		JwtClaimsSet.Builder claims = JwtClaimsSet.builder().claim("existing", "value");
		this.customizer.customize(context(authentication(null), claims, Set.of("openid")));

		assertThat(claims.build().getClaims()).isEqualTo(Map.of("existing", "value"));
	}

	private static JwtEncodingContext context(AuthorizationUserAuthentication authentication,
			JwtClaimsSet.Builder claims, Set<String> scopes) {
		JwtEncodingContext context = mock(JwtEncodingContext.class);
		RegisteredClient client = mock(RegisteredClient.class);
		when(client.getClientSettings()).thenReturn(ClientSettings.builder()
			.setting(OAuthClientSettings.TENANT_ID, TenantId.DEFAULT.toString())
			.build());
		when(context.getTokenType()).thenReturn(OAuth2TokenType.ACCESS_TOKEN);
		when(context.getAuthorizedScopes()).thenReturn(scopes);
		when(context.getAuthorizationGrantType()).thenReturn(AuthorizationGrantType.AUTHORIZATION_CODE);
		when(context.getPrincipal()).thenReturn(authentication);
		when(context.getRegisteredClient()).thenReturn(client);
		when(context.getClaims()).thenReturn(claims);
		return context;
	}

	private static AuthorizationUserAuthentication authentication(Instant secondFactorAt) {
		AuthorizationPrincipal principal = new AuthorizationPrincipal(TenantId.DEFAULT, USER_ID, SESSION_ID,
				SessionAuthenticationMethod.PASSWORD, NOW.minusSeconds(120));
		FactorGrantedAuthority password = FactorGrantedAuthority
			.withAuthority(FactorGrantedAuthority.PASSWORD_AUTHORITY)
			.issuedAt(NOW.minusSeconds(120))
			.build();
		if (secondFactorAt == null) {
			return AuthorizationUserAuthentication.authenticated(principal, List.of(password));
		}
		return AuthorizationUserAuthentication.authenticated(principal,
				List.of(password, FactorGrantedAuthority.withAuthority(FactorGrantedAuthority.OTT_AUTHORITY)
					.issuedAt(secondFactorAt).build()));
	}

}
