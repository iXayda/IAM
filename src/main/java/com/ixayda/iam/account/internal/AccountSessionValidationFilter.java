package com.ixayda.iam.account.internal;

import java.io.IOException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import com.ixayda.iam.authorization.AuthorizationPrincipal;
import com.ixayda.iam.authorization.AuthorizationUserAuthentication;
import com.ixayda.iam.session.SessionAuthenticationFactorType;
import com.ixayda.iam.session.SessionOperations;
import com.ixayda.iam.session.UserSession;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.web.filter.OncePerRequestFilter;

final class AccountSessionValidationFilter extends OncePerRequestFilter {

	private final SessionOperations sessions;

	private final AuthenticationEntryPoint authenticationEntryPoint =
			new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED);

	AccountSessionValidationFilter(SessionOperations sessions) {
		this.sessions = sessions;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication == null) {
			filterChain.doFilter(request, response);
			return;
		}
		if (!(authentication instanceof AuthorizationUserAuthentication userAuthentication)
				|| !valid(userAuthentication)) {
			reject(request, response);
			return;
		}
		filterChain.doFilter(request, response);
	}

	private boolean valid(AuthorizationUserAuthentication authentication) {
		if (!authentication.isAuthenticated()) {
			return false;
		}
		AuthorizationPrincipal principal = authentication.getPrincipal();
		return this.sessions.findUsable(principal.tenantId(), principal.sessionId())
			.filter(session -> identityMatches(principal, session))
			.filter(session -> factorTimes(session).equals(factorTimes(authentication)))
			.isPresent();
	}

	private void reject(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
		SecurityContextHolder.clearContext();
		HttpSession session = request.getSession(false);
		if (session != null) {
			session.invalidate();
		}
		this.authenticationEntryPoint.commence(request, response,
				new InsufficientAuthenticationException("The account session is invalid"));
	}

	private static boolean identityMatches(AuthorizationPrincipal principal, UserSession session) {
		return principal.tenantId().equals(session.tenantId()) && principal.userId().equals(session.userId())
				&& principal.sessionId().equals(session.id())
				&& principal.authenticationMethod() == session.authenticationMethod()
				&& principal.authenticatedAt().equals(session.authenticatedAt());
	}

	private static Map<String, Instant> factorTimes(UserSession session) {
		Map<String, Instant> factors = new LinkedHashMap<>();
		session.authenticationFactors().forEach(factor -> factors.merge(authority(factor.type()), factor.issuedAt(),
				(first, second) -> first.isAfter(second) ? first : second));
		return factors;
	}

	private static Map<String, Instant> factorTimes(AuthorizationUserAuthentication authentication) {
		Map<String, Instant> factors = new LinkedHashMap<>();
		for (GrantedAuthority authority : authentication.getAuthorities()) {
			if (authority instanceof FactorGrantedAuthority factor
					&& (FactorGrantedAuthority.PASSWORD_AUTHORITY.equals(factor.getAuthority())
							|| FactorGrantedAuthority.OTT_AUTHORITY.equals(factor.getAuthority()))) {
				factors.merge(factor.getAuthority(), factor.getIssuedAt(),
						(first, second) -> first.isAfter(second) ? first : second);
			}
		}
		return factors;
	}

	private static String authority(SessionAuthenticationFactorType factor) {
		return switch (factor) {
			case PASSWORD -> FactorGrantedAuthority.PASSWORD_AUTHORITY;
			case TOTP, RECOVERY_CODE -> FactorGrantedAuthority.OTT_AUTHORITY;
		};
	}

}
