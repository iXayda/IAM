package com.ixayda.iam.security;

import com.ixayda.iam.service.IdentityReadiness;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.health.contributor.HealthIndicator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.NullSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.header.HeaderWriter;

@Configuration(proxyBeanMethods = false)
public class IdentityHealthConfiguration {

	@Bean
	HealthIndicator identityReadinessHealthIndicator(ObjectProvider<IdentityReadiness> readiness) { return new IdentityReadinessHealthIndicator(readiness::getObject); }

	@Bean
	@Order(-1)
	@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
	SecurityFilterChain healthSecurity(HttpSecurity http, HeaderWriter browserSecurityHeaders) throws Exception {
		http.securityMatcher(IdentityHealthRequestFilter.PATHS.toArray(String[]::new))
				.securityContext(context -> context.securityContextRepository(new NullSecurityContextRepository()))
				.sessionManagement(session -> session.disable()).requestCache(cache -> cache.disable())
				.httpBasic(basic -> basic.disable()).csrf(csrf -> csrf.disable()).headers(headers -> headers.disable())
				.authorizeHttpRequests(authorize -> authorize.anyRequest().permitAll())
				.addFilterBefore(new IdentityHealthRequestFilter(browserSecurityHeaders), SecurityContextHolderFilter.class);
		return http.build();
	}
}
