package com.ixayda.iam.security;

import com.ixayda.iam.service.IdentityAuthorizationBindings;
import com.ixayda.iam.service.IdentityAuthorizationInteractions;
import com.ixayda.iam.service.IdentityAuthorizationSessions;
import com.ixayda.iam.service.IdentityBrowserSessions;
import com.ixayda.iam.service.IdentityProtocolClients;
import com.ixayda.iam.service.SecurityAudits;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.context.NullSecurityContextRepository;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.transaction.PlatformTransactionManager;

/** Browser protocol endpoints use the same session and CSRF identity as the independent frontend. */
@Configuration(proxyBeanMethods = false)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnProperty(name = { "iam.protocol.issuer", "iam.protocol.identity-frontend-uri" })
public class IdentityAuthorizationConfiguration {

	@Bean
	@Lazy(false)
	IdentityAuthorizationEndpoint authorizationEndpoint(AuthorizationServerSettings settings, @Value("${iam.protocol.identity-frontend-uri}") String frontend,
			IdentityProtocolClients clients, IdentityAuthorizationSessions sessions, IdentityAuthorizationBindings bindings,
			IdentityAuthorizationInteractions interactions, IdentityBrowserSessions browser, SecurityAudits audits, PlatformTransactionManager transactions) {
		var provider = new IdentityAuthorizationRequestProvider(clients, sessions, bindings, interactions, audits, transactions);
		return new IdentityAuthorizationEndpoint(settings, frontend, provider, clients, browser, interactions, audits, transactions);
	}

	@Bean
	@Order(3)
	SecurityFilterChain authorizationSecurity(HttpSecurity http, AuthorizationServerSettings settings, IdentityAuthorizationEndpoint endpoint,
			CsrfTokenRepository csrfTokens) throws Exception {
		var paths = PathPatternRequestMatcher.withDefaults();
		http.securityMatcher(new OrRequestMatcher(paths.matcher(IdentityProtocolResponses.AUTHORIZATION_ENDPOINT),
				paths.matcher(IdentityProtocolResponses.INTERACTION_ENDPOINT + "/{handle}"), paths.matcher(IdentityProtocolResponses.INTERACTION_ENDPOINT + "/{handle}/complete")))
				.securityContext(context -> context.requireExplicitSave(true))
				.sessionManagement(session -> session.disable()).requestCache(cache -> cache.disable()).httpBasic(basic -> basic.disable())
				.csrf(csrf -> csrf.csrfTokenRepository(csrfTokens))
				.authorizeHttpRequests(authorize -> authorize.anyRequest().permitAll())
				.exceptionHandling(errors -> errors.authenticationEntryPoint((request, response, failure) -> endpoint.writeFailure(response, endpoint.rejected(request, 401, "login_required")))
						.accessDeniedHandler((request, response, failure) -> endpoint.writeFailure(response, endpoint.rejected(request, 403, "invalid_request"))))
				.headers(headers -> headers.disable())
				.addFilterBefore(new IdentityAuthorizationRequestFilter(endpoint, settings), SecurityContextHolderFilter.class)
				.addFilterAfter(endpoint.filter(), AuthorizationFilter.class);
		return http.build();
	}

	@Bean
	@Order(4)
	SecurityFilterChain discoverySecurity(HttpSecurity http, AuthorizationServerSettings settings) throws Exception {
		var paths = PathPatternRequestMatcher.withDefaults();
		http.securityMatcher(new OrRequestMatcher(paths.matcher(IdentityProtocolResponses.OIDC_DISCOVERY_ENDPOINT), paths.matcher(IdentityProtocolResponses.OAUTH_DISCOVERY_ENDPOINT)))
				.securityContext(context -> context.securityContextRepository(new NullSecurityContextRepository()))
				.sessionManagement(session -> session.disable()).requestCache(cache -> cache.disable()).httpBasic(basic -> basic.disable())
				.csrf(csrf -> csrf.disable()).authorizeHttpRequests(authorize -> authorize.anyRequest().permitAll())
				.headers(headers -> headers.disable())
				.addFilterBefore(new IdentityDiscoveryRequestFilter(settings), SecurityContextHolderFilter.class);
		return http.build();
	}

}
