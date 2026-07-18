package com.ixayda.iam.scim.internal;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportRuntimeHints;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration(proxyBeanMethods = false)
@ImportRuntimeHints(ScimRuntimeHints.class)
class ScimWebSecurityConfiguration {

	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE + 2)
	SecurityFilterChain scimSecurityFilterChain(HttpSecurity http, ScimJsonCodec codec) throws Exception {
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
			.anyRequest()
			.denyAll());
		http.csrf(AbstractHttpConfigurer::disable);
		http.requestCache(AbstractHttpConfigurer::disable);
		http.sessionManagement((sessions) -> sessions.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
		http.exceptionHandling((exceptions) -> exceptions.authenticationEntryPoint(errors).accessDeniedHandler(errors));
		return http.build();
	}

}
