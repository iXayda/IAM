package com.ixayda.iam.admin.internal;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

import com.ixayda.iam.admin.AdminRoleOperations;
import com.ixayda.iam.authorization.AdminAccessTokenClaims;
import com.ixayda.iam.authorization.AuthorizationPrincipal;
import com.ixayda.iam.authorization.AuthorizationUserAuthentication;
import com.ixayda.iam.session.SessionAuthenticationMethod;
import com.ixayda.iam.session.SessionId;
import com.ixayda.iam.session.SessionOperations;
import com.ixayda.iam.session.UserSession;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;

final class AdminJwtAuthenticationConverter implements Converter<Jwt, AuthorizationUserAuthentication> {

	private final SessionOperations sessions;

	private final AdminRoleOperations roles;

	AdminJwtAuthenticationConverter(SessionOperations sessions, AdminRoleOperations roles) {
		this.sessions = sessions;
		this.roles = roles;
	}

	@Override
	public AuthorizationUserAuthentication convert(Jwt jwt) {
		TokenIdentity identity = identity(jwt);
		UserSession session = this.sessions.findUsable(identity.tenantId(), identity.sessionId())
			.orElseThrow(AdminJwtAuthenticationConverter::invalidToken);
		if (!session.userId().equals(identity.userId())
				|| session.authenticationMethod() != identity.authenticationMethod()
				|| !session.authenticatedAt().truncatedTo(ChronoUnit.SECONDS).equals(identity.authenticatedAt())) {
			throw invalidToken();
		}
		List<SimpleGrantedAuthority> authorities = this.roles
			.findEffectivePermissions(identity.tenantId(), identity.userId())
			.stream()
			.map(permission -> new SimpleGrantedAuthority(permission.value()))
			.sorted((left, right) -> left.getAuthority().compareTo(right.getAuthority()))
			.toList();
		AuthorizationPrincipal principal = new AuthorizationPrincipal(identity.tenantId(), identity.userId(),
				identity.sessionId(), identity.authenticationMethod(), session.authenticatedAt());
		return AuthorizationUserAuthentication.authenticated(principal, authorities);
	}

	private static TokenIdentity identity(Jwt jwt) {
		try {
			TenantId tenantId = TenantId.from(jwt.getClaimAsString(AdminAccessTokenClaims.TENANT_ID));
			UserId userId = UserId.from(jwt.getClaimAsString(AdminAccessTokenClaims.USER_ID));
			SessionId sessionId = SessionId.from(jwt.getClaimAsString(AdminAccessTokenClaims.SESSION_ID));
			SessionAuthenticationMethod authenticationMethod = SessionAuthenticationMethod.valueOf(jwt
				.getClaimAsString(AdminAccessTokenClaims.AUTHENTICATION_METHOD)
				.toUpperCase(Locale.ROOT));
			Instant authenticatedAt = jwt.getClaimAsInstant(AdminAccessTokenClaims.AUTHENTICATION_TIME);
			return new TokenIdentity(tenantId, userId, sessionId, authenticationMethod,
					Objects.requireNonNull(authenticatedAt, "Admin authentication time must not be null"));
		}
		catch (NullPointerException | IllegalArgumentException exception) {
			throw invalidToken();
		}
	}

	private static InvalidBearerTokenException invalidToken() {
		return new InvalidBearerTokenException("The admin token session is invalid.");
	}

	private record TokenIdentity(TenantId tenantId, UserId userId, SessionId sessionId,
			SessionAuthenticationMethod authenticationMethod, Instant authenticatedAt) {
	}

}
