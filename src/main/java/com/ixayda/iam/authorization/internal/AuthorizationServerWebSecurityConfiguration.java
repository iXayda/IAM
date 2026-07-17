package com.ixayda.iam.authorization.internal;

import java.util.Set;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration(proxyBeanMethods = false)
class AuthorizationServerWebSecurityConfiguration {

	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE)
	SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) {
		http.oauth2AuthorizationServer((authorizationServer) -> {
			http.securityMatcher(authorizationServer.getEndpointsMatcher());
			authorizationServer.authorizationEndpoint((authorizationEndpoint) -> authorizationEndpoint
				.authorizationRequestConverter(new AllowlistedAuthorizationRequestConverter()));
			authorizationServer.oidc(withDefaults());
		});
		http.authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated());
		http.oauth2ResourceServer((resourceServer) -> resourceServer.jwt(withDefaults()));
		http.exceptionHandling((exceptions) -> exceptions.defaultAuthenticationEntryPointFor(
				new LoginUrlAuthenticationEntryPoint("/login"), htmlRequestMatcher()));
		return http.build();
	}

	private static RequestMatcher htmlRequestMatcher() {
		MediaTypeRequestMatcher requestMatcher = new MediaTypeRequestMatcher(MediaType.TEXT_HTML);
		requestMatcher.setIgnoredMediaTypes(Set.of(MediaType.ALL));
		return requestMatcher;
	}

}
