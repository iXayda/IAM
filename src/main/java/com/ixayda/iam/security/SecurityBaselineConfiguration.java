package com.ixayda.iam.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration(proxyBeanMethods = false)
class SecurityBaselineConfiguration {

	@Bean
	@Order(Ordered.LOWEST_PRECEDENCE)
	SecurityFilterChain applicationSecurityFilterChain(HttpSecurity http) throws Exception {
		http.authorizeHttpRequests((requests) -> requests
			.requestMatchers("/actuator/health", "/actuator/health/**", "/actuator/prometheus", "/livez", "/readyz")
			.permitAll()
			.anyRequest()
			.denyAll());
		return http.build();
	}

}
