package com.ixayda.iam.account.internal;

import com.ixayda.iam.session.SessionOperations;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;

@Configuration(proxyBeanMethods = false)
class AccountMfaWebSecurityConfiguration {

	static final String BASE_PATH = "/iam/account";

	static final String CSRF_PATH = BASE_PATH + "/csrf";

	static final String MFA_PATH = BASE_PATH + "/mfa";

	static final String TOTP_PATH = MFA_PATH + "/totp";

	static final String TOTP_ENROLLMENTS_PATH = TOTP_PATH + "/enrollments";

	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE + 4)
	SecurityFilterChain accountMfaSecurityFilterChain(HttpSecurity http, SessionOperations sessions,
			AccountMfaProperties properties) throws Exception {
		http.securityMatcher(BASE_PATH + "/**");
		http.authorizeHttpRequests((authorize) -> authorize
			.requestMatchers(HttpMethod.GET, CSRF_PATH, MFA_PATH)
			.authenticated()
			.requestMatchers(HttpMethod.POST, TOTP_ENROLLMENTS_PATH, TOTP_ENROLLMENTS_PATH + "/*/activation")
			.access(properties.primaryAuthenticationAuthorizationManager())
			.requestMatchers(HttpMethod.DELETE, TOTP_PATH)
			.access(properties.primaryAuthenticationAuthorizationManager())
			.anyRequest()
			.denyAll());
		http.requestCache(AbstractHttpConfigurer::disable);
		http.exceptionHandling((exceptions) -> exceptions
			.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)));
		http.addFilterBefore(new AccountSessionValidationFilter(sessions), AuthorizationFilter.class);
		return http.build();
	}

}
