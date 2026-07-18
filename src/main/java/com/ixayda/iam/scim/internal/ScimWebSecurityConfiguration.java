package com.ixayda.iam.scim.internal;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportRuntimeHints;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.BearerTokenErrors;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.security.web.SecurityFilterChain;

@Configuration(proxyBeanMethods = false)
@ImportRuntimeHints(ScimRuntimeHints.class)
class ScimWebSecurityConfiguration {

	private static final String READ_AUTHORITY = "SCOPE_scim.read";

	private static final String WRITE_AUTHORITY = "SCOPE_scim.write";

	private static final String[] PROVISIONING_PATHS = { ScimMetadataController.BASE_PATH + "/Users",
			ScimMetadataController.BASE_PATH + "/Users/*", ScimMetadataController.BASE_PATH + "/Groups",
			ScimMetadataController.BASE_PATH + "/Groups/*" };

	private static final String[] PROVISIONING_COLLECTION_PATHS = { ScimMetadataController.BASE_PATH + "/Users",
			ScimMetadataController.BASE_PATH + "/Groups" };

	private static final String[] PROVISIONING_RESOURCE_PATHS = { ScimMetadataController.BASE_PATH + "/Users/*",
			ScimMetadataController.BASE_PATH + "/Groups/*" };

	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE + 2)
	SecurityFilterChain scimSecurityFilterChain(HttpSecurity http, ScimJsonCodec codec,
			@Qualifier("serviceJwtDecoder") JwtDecoder serviceJwtDecoder) throws Exception {
		ScimErrorResponseWriter errors = new ScimErrorResponseWriter(codec);
		http.securityMatcher(ScimMetadataController.BASE_PATH + "/**");
		http.authorizeHttpRequests((authorize) -> authorize
			.requestMatchers(HttpMethod.GET, ScimMetadataController.BASE_PATH
					+ ScimMetadataController.SERVICE_PROVIDER_CONFIG_PATH,
					ScimMetadataController.BASE_PATH + ScimMetadataController.SCHEMAS_PATH,
					ScimMetadataController.BASE_PATH + ScimMetadataController.SCHEMAS_PATH + "/*",
					ScimMetadataController.BASE_PATH + ScimMetadataController.RESOURCE_TYPES_PATH,
					ScimMetadataController.BASE_PATH + ScimMetadataController.RESOURCE_TYPES_PATH + "/*")
			.permitAll()
			.requestMatchers(HttpMethod.GET, PROVISIONING_PATHS)
			.hasAuthority(READ_AUTHORITY)
			.requestMatchers(HttpMethod.HEAD, PROVISIONING_PATHS)
			.hasAuthority(READ_AUTHORITY)
			.requestMatchers(HttpMethod.POST, PROVISIONING_COLLECTION_PATHS)
			.hasAuthority(WRITE_AUTHORITY)
			.requestMatchers(HttpMethod.PUT, PROVISIONING_RESOURCE_PATHS)
			.hasAuthority(WRITE_AUTHORITY)
			.requestMatchers(HttpMethod.PATCH, PROVISIONING_RESOURCE_PATHS)
			.hasAuthority(WRITE_AUTHORITY)
			.requestMatchers(HttpMethod.DELETE, PROVISIONING_RESOURCE_PATHS)
			.hasAuthority(WRITE_AUTHORITY)
			.anyRequest()
			.denyAll());
		http.csrf(AbstractHttpConfigurer::disable);
		http.requestCache(AbstractHttpConfigurer::disable);
		http.sessionManagement((sessions) -> sessions.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
		http.exceptionHandling((exceptions) -> exceptions.authenticationEntryPoint(errors).accessDeniedHandler(errors));
		http.oauth2ResourceServer((resourceServer) -> resourceServer
			.authenticationEntryPoint(errors)
			.accessDeniedHandler(errors)
			.bearerTokenResolver(bearerTokenResolver())
			.jwt((jwt) -> jwt.decoder(serviceJwtDecoder).jwtAuthenticationConverter(jwtAuthenticationConverter())));
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

	private static JwtAuthenticationConverter jwtAuthenticationConverter() {
		JwtGrantedAuthoritiesConverter authorities = new JwtGrantedAuthoritiesConverter();
		authorities.setAuthoritiesClaimName("scope");
		authorities.setAuthorityPrefix("SCOPE_");
		JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
		converter.setJwtGrantedAuthoritiesConverter(authorities);
		return converter;
	}

}
