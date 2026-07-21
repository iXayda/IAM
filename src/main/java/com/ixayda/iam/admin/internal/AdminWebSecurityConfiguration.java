package com.ixayda.iam.admin.internal;

import com.ixayda.iam.admin.AdminPermissionCode;
import com.ixayda.iam.admin.AdminRoleOperations;
import com.ixayda.iam.authorization.AdminMfaPolicy;
import com.ixayda.iam.session.SessionOperations;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationManagers;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.BearerTokenErrors;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

@Configuration(proxyBeanMethods = false)
class AdminWebSecurityConfiguration {

	static final String BASE_PATH = "/iam/admin";

	static final String ROLES_PATH = BASE_PATH + "/roles";

	static final String AUDIT_EVENTS_PATH = BASE_PATH + "/audit-events";

	static final String AUDIT_EVENT_EXPORT_PATH = AUDIT_EVENTS_PATH + "/export";

	@Bean
	AdminJwtAuthenticationConverter adminJwtAuthenticationConverter(SessionOperations sessions,
			AdminRoleOperations roles) {
		return new AdminJwtAuthenticationConverter(sessions, roles);
	}

	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE + 3)
	SecurityFilterChain adminSecurityFilterChain(HttpSecurity http,
			@Qualifier("adminJwtDecoder") JwtDecoder adminJwtDecoder,
			AdminJwtAuthenticationConverter authenticationConverter, AdminMfaPolicy mfaPolicy) throws Exception {
		AuthorizationManager<RequestAuthorizationContext> mfa = mfaPolicy.authorizationManager();
		AuthorizationManager<RequestAuthorizationContext> readRoles = AuthorizationManagers.allOf(
				AuthorityAuthorizationManager.hasAuthority(AdminPermissionCode.READ_ROLES.value()), mfa);
		AuthorizationManager<RequestAuthorizationContext> readAudit = AuthorizationManagers.allOf(
				AuthorityAuthorizationManager.hasAuthority(AdminPermissionCode.READ_AUDIT.value()), mfa);
		AuthorizationManager<RequestAuthorizationContext> exportAudit = AuthorizationManagers.allOf(
				AuthorityAuthorizationManager.hasAuthority(AdminPermissionCode.EXPORT_AUDIT.value()), mfa);
		http.securityMatcher(BASE_PATH + "/**");
		http.authorizeHttpRequests((authorize) -> authorize
			.requestMatchers(HttpMethod.GET, ROLES_PATH)
			.access(readRoles)
			.requestMatchers(HttpMethod.GET, AUDIT_EVENT_EXPORT_PATH)
			.access(exportAudit)
			.requestMatchers(HttpMethod.GET, AUDIT_EVENTS_PATH)
			.access(readAudit)
			.anyRequest()
			.denyAll());
		http.csrf(AbstractHttpConfigurer::disable);
		http.requestCache(AbstractHttpConfigurer::disable);
		http.sessionManagement((sessions) -> sessions.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
		http.oauth2ResourceServer((resourceServer) -> resourceServer
			.bearerTokenResolver(bearerTokenResolver())
			.jwt((jwt) -> jwt.decoder(adminJwtDecoder).jwtAuthenticationConverter(authenticationConverter)));
		return http.build();
	}

	private static BearerTokenResolver bearerTokenResolver() {
		DefaultBearerTokenResolver delegate = new DefaultBearerTokenResolver();
		delegate.setAllowFormEncodedBodyParameter(false);
		delegate.setAllowUriQueryParameter(false);
		return (request) -> {
			var headers = request.getHeaders(HttpHeaders.AUTHORIZATION).asIterator();
			if (headers.hasNext()) {
				headers.next();
				if (headers.hasNext()) {
					throw new OAuth2AuthenticationException(
							BearerTokenErrors.invalidRequest("Multiple authorization headers are not allowed."));
				}
			}
			return delegate.resolve(request);
		};
	}

}
