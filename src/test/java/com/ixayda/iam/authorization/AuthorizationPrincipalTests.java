package com.ixayda.iam.authorization;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.List;

import com.ixayda.iam.session.SessionAuthenticationMethod;
import com.ixayda.iam.session.SessionId;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

class AuthorizationPrincipalTests {

	@Test
	void createsAnAuthenticatedCredentialFreePrincipal() {
		AuthorizationPrincipal principal = new AuthorizationPrincipal(TenantId.DEFAULT, UserId.random(),
				SessionId.random(), SessionAuthenticationMethod.PASSWORD, Instant.parse("2026-01-01T00:00:00Z"));

		AuthorizationUserAuthentication authentication = AuthorizationUserAuthentication.authenticated(principal,
				List.of(new SimpleGrantedAuthority("ROLE_USER")));

		assertThat(authentication.isAuthenticated()).isTrue();
		assertThat(authentication.getName()).isEqualTo(principal.userId().toString());
		assertThat(authentication.getPrincipal()).isSameAs(principal);
		assertThat(authentication.getCredentials()).isNull();
		assertThat(authentication.getDetails()).isNull();
		assertThat(authentication.getAuthorities()).extracting("authority").containsExactly("ROLE_USER");
	}

	@Test
	void cannotBeMarkedAuthenticatedThroughTheMutableBaseApi() {
		AuthorizationPrincipal principal = new AuthorizationPrincipal(TenantId.DEFAULT, UserId.random(),
				SessionId.random(), SessionAuthenticationMethod.PASSWORD, Instant.parse("2026-01-01T00:00:00Z"));
		AuthorizationUserAuthentication authentication = AuthorizationUserAuthentication.authenticated(principal,
				List.of());

		authentication.setAuthenticated(false);

		assertThat(authentication.isAuthenticated()).isFalse();
		assertThatThrownBy(() -> authentication.setAuthenticated(true))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("Use authenticated() to create an authenticated principal");
	}

}
