package com.ixayda.iam.admin.internal;

import com.ixayda.iam.admin.AdminRoleOperations;
import com.ixayda.iam.session.SessionOperations;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.BearerTokenErrors;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.security.web.SecurityFilterChain;

@Configuration(proxyBeanMethods = false)
class AdminWebSecurityConfiguration {

	static final String BASE_PATH = "/iam/admin";

	@Bean
	AdminJwtAuthenticationConverter adminJwtAuthenticationConverter(SessionOperations sessions,
			AdminRoleOperations roles) {
		return new AdminJwtAuthenticationConverter(sessions, roles);
	}

	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE + 3)
	SecurityFilterChain adminSecurityFilterChain(HttpSecurity http,
			@Qualifier("adminJwtDecoder") JwtDecoder adminJwtDecoder,
			AdminJwtAuthenticationConverter authenticationConverter) throws Exception {
		http.securityMatcher(BASE_PATH + "/**");
		http.authorizeHttpRequests((authorize) -> authorize.anyRequest().denyAll());
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
