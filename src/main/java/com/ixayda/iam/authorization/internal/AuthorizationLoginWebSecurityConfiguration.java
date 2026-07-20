package com.ixayda.iam.authorization.internal;

import com.ixayda.iam.auth.LocalPasswordLoginOperations;
import com.ixayda.iam.auth.MfaLoginOperations;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;

@Configuration(proxyBeanMethods = false)
class AuthorizationLoginWebSecurityConfiguration {

	@Bean
	HttpSessionRequestCache authorizationRequestCache() {
		HttpSessionRequestCache requestCache = new HttpSessionRequestCache();
		requestCache.setSessionAttrName(AuthorizationLoginDetailsSource.SAVED_REQUEST_ATTRIBUTE);
		requestCache.setRequestMatcher(PathPatternRequestMatcher.withDefaults()
			.matcher(HttpMethod.GET, "/oauth2/authorize"));
		return requestCache;
	}

	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE + 1)
	SecurityFilterChain authorizationLoginSecurityFilterChain(HttpSecurity http,
			HttpSessionRequestCache authorizationRequestCache, AuthorizationLoginDetailsSource detailsSource,
			LocalPasswordLoginOperations logins, MfaLoginOperations mfaLogins,
			AuthorizationServerSettings authorizationServerSettings) {
		http.securityMatcher("/login", AuthorizationMfaLoginPageController.PATH,
			AuthorizationConsentController.CONSENT_PATH, AuthorizationConsentController.DENIAL_PATH);
		http.authorizeHttpRequests((authorize) -> authorize
			.requestMatchers("/login", AuthorizationMfaLoginPageController.PATH)
			.permitAll()
			.anyRequest()
			.authenticated());
		http.authenticationProvider(new AuthorizationLocalPasswordAuthenticationProvider(logins));
		http.requestCache((requestCache) -> requestCache.requestCache(authorizationRequestCache));
		AuthorizationSavedRequestAuthenticationSuccessHandler successHandler =
				new AuthorizationSavedRequestAuthenticationSuccessHandler(authorizationRequestCache,
						authorizationServerSettings);
		http.formLogin((formLogin) -> formLogin.authenticationDetailsSource(detailsSource)
			.successHandler(successHandler)
			.failureHandler(new AuthorizationMfaRequiredAuthenticationFailureHandler())
			.permitAll());
		AuthenticationFilter mfaFilter = new AuthenticationFilter(
				new ProviderManager(new AuthorizationMfaAuthenticationProvider(mfaLogins)),
				new AuthorizationMfaAuthenticationConverter(detailsSource));
		mfaFilter.setRequestMatcher(PathPatternRequestMatcher.withDefaults()
			.matcher(HttpMethod.POST, AuthorizationMfaLoginPageController.PATH));
		mfaFilter.setSecurityContextRepository(new HttpSessionSecurityContextRepository());
		mfaFilter.setSuccessHandler(new AuthorizationMfaAuthenticationSuccessHandler(successHandler));
		mfaFilter.setFailureHandler(new AuthorizationMfaAuthenticationFailureHandler());
		http.addFilterAfter(mfaFilter, UsernamePasswordAuthenticationFilter.class);
		return http.build();
	}

}
