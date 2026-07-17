package com.ixayda.iam.authorization.internal;

import com.ixayda.iam.auth.LocalPasswordLoginOperations;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;
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
			LocalPasswordLoginOperations logins, AuthorizationServerSettings authorizationServerSettings) {
		http.securityMatcher("/login");
		http.authorizeHttpRequests((authorize) -> authorize.anyRequest().permitAll());
		http.authenticationProvider(new AuthorizationLocalPasswordAuthenticationProvider(logins));
		http.requestCache((requestCache) -> requestCache.requestCache(authorizationRequestCache));
		http.formLogin((formLogin) -> formLogin.authenticationDetailsSource(detailsSource)
			.successHandler(new AuthorizationSavedRequestAuthenticationSuccessHandler(authorizationRequestCache,
					authorizationServerSettings))
			.permitAll());
		return http.build();
	}

}
