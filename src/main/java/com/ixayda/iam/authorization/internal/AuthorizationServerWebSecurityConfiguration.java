package com.ixayda.iam.authorization.internal;

import java.util.List;
import java.util.Set;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationConsentAuthenticationProvider;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration(proxyBeanMethods = false)
class AuthorizationServerWebSecurityConfiguration {

	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE)
	SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http,
			HttpSessionRequestCache authorizationRequestCache, PlatformTransactionManager transactionManager) {
		http.oauth2AuthorizationServer((authorizationServer) -> {
			http.securityMatcher(authorizationServer.getEndpointsMatcher());
			authorizationServer.authorizationEndpoint((authorizationEndpoint) -> authorizationEndpoint
				.authorizationRequestConverter(new AllowlistedAuthorizationRequestConverter())
				.authenticationProviders((providers) -> configureConsentTransaction(providers, transactionManager)));
			authorizationServer.oidc(withDefaults());
		});
		http.authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated());
		http.requestCache((requestCache) -> requestCache.requestCache(authorizationRequestCache));
		http.oauth2ResourceServer((resourceServer) -> resourceServer.jwt(withDefaults()));
		http.exceptionHandling((exceptions) -> exceptions.defaultAuthenticationEntryPointFor(
				new LoginUrlAuthenticationEntryPoint("/login"), htmlRequestMatcher()));
		return http.build();
	}

	private static void configureConsentTransaction(List<AuthenticationProvider> providers,
			PlatformTransactionManager transactionManager) {
		TransactionTemplate transactions = new TransactionTemplate(transactionManager);
		transactions.setIsolationLevel(TransactionDefinition.ISOLATION_READ_COMMITTED);
		int providerCount = 0;
		for (int index = 0; index < providers.size(); index++) {
			AuthenticationProvider provider = providers.get(index);
			if (provider instanceof OAuth2AuthorizationConsentAuthenticationProvider) {
				providers.set(index, new TransactionalAuthorizationConsentAuthenticationProvider(provider, transactions));
				providerCount++;
			}
		}
		if (providerCount != 1) {
			throw new IllegalStateException("Expected exactly one OAuth authorization consent provider");
		}
	}

	private static RequestMatcher htmlRequestMatcher() {
		MediaTypeRequestMatcher requestMatcher = new MediaTypeRequestMatcher(MediaType.TEXT_HTML);
		requestMatcher.setIgnoredMediaTypes(Set.of(MediaType.ALL));
		return requestMatcher;
	}

}
