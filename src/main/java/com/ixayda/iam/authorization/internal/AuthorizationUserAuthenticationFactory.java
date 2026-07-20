package com.ixayda.iam.authorization.internal;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.ixayda.iam.authorization.AuthorizationPrincipal;
import com.ixayda.iam.authorization.AuthorizationUserAuthentication;
import com.ixayda.iam.session.SessionAuthenticationFactorType;
import com.ixayda.iam.session.SessionAuthenticationMethod;
import com.ixayda.iam.session.SessionStatus;
import com.ixayda.iam.session.UserSession;
import com.ixayda.iam.tenant.TenantId;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.authority.FactorGrantedAuthority;

final class AuthorizationUserAuthenticationFactory {

	private AuthorizationUserAuthenticationFactory() {
	}

	static AuthorizationUserAuthentication fromPasswordSession(TenantId tenantId, UserSession session) {
		if (!tenantId.equals(session.tenantId())
				|| session.authenticationMethod() != SessionAuthenticationMethod.PASSWORD
				|| session.status() != SessionStatus.ACTIVE) {
			throw new AuthenticationServiceException("Authentication returned an invalid password session");
		}
		AuthorizationPrincipal principal = new AuthorizationPrincipal(session.tenantId(), session.userId(), session.id(),
				session.authenticationMethod(), session.authenticatedAt());
		Map<String, Instant> factorTimes = new LinkedHashMap<>();
		session.authenticationFactors().forEach(factor -> factorTimes.merge(authority(factor.type()),
				factor.issuedAt(), (first, second) -> first.isAfter(second) ? first : second));
		List<FactorGrantedAuthority> authorities = factorTimes.entrySet().stream()
			.map(entry -> FactorGrantedAuthority.withAuthority(entry.getKey()).issuedAt(entry.getValue()).build())
			.toList();
		return AuthorizationUserAuthentication.authenticated(principal, authorities);
	}

	private static String authority(SessionAuthenticationFactorType factor) {
		return switch (factor) {
			case PASSWORD -> FactorGrantedAuthority.PASSWORD_AUTHORITY;
			case TOTP, RECOVERY_CODE -> FactorGrantedAuthority.OTT_AUTHORITY;
		};
	}

}
