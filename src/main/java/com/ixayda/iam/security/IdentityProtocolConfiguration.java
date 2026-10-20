package com.ixayda.iam.security;

import java.util.List;

import com.ixayda.iam.service.IdentityAccessTokens;
import com.ixayda.iam.service.IdentityApplicationRoles;
import com.ixayda.iam.service.IdentityAuthorizationBindings;
import com.ixayda.iam.service.IdentityAuthorizationSessions;
import com.ixayda.iam.service.IdentityAuthorizations;
import com.ixayda.iam.service.IdentityProtocolClients;
import com.ixayda.iam.service.IdentityRefreshTokens;
import com.ixayda.iam.service.IdentitySigningKeys;
import com.ixayda.iam.service.IdentityUsers;
import com.ixayda.iam.service.SecurityAudits;

import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.sql.init.dependency.DependsOnDatabaseInitialization;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.web.OAuth2TokenEndpointFilter;
import org.springframework.security.oauth2.server.authorization.web.authentication.ClientSecretBasicAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationCodeAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2RefreshTokenAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.NullSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.transaction.PlatformTransactionManager;

/** Fixed-issuer protocol entrypoints; browser authentication remains in its own security chain. */
@Configuration(proxyBeanMethods = false)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnProperty(name = "iam.protocol.issuer")
public class IdentityProtocolConfiguration {

	@Bean
	@Lazy(false)
	AuthorizationServerSettings protocolSettings(@Value("${iam.protocol.issuer}") String issuer) {
		return AuthorizationServerSettings.builder().issuer(IdentityTokenRequests.requireIssuer(issuer)).build();
	}

	@Bean
	@Lazy(false)
	@DependsOnDatabaseInitialization
	SmartInitializingSingleton protocolInitializer(IdentityAuthorizations authorizations, IdentitySigningKeys keys) {
		return () -> {
			authorizations.requireConfigured();
			keys.initialize().orElseThrow(() -> new IllegalStateException("Protocol HTTP requires a configured signing key"));
		};
	}

	@Bean
	@Order(0)
	SecurityFilterChain publicKeySecurity(HttpSecurity http, IdentityJwkSource source) throws Exception {
		// The public native read terminates before any browser context or session strategy.
		http.securityMatcher(PathPatternRequestMatcher.withDefaults().matcher(IdentityProtocolResponses.JWK_SET_ENDPOINT))
				.securityContext(context -> context.securityContextRepository(new NullSecurityContextRepository()))
				.sessionManagement(session -> session.disable()).requestCache(cache -> cache.disable())
				.httpBasic(basic -> basic.disable()).csrf(csrf -> csrf.disable())
				.authorizeHttpRequests(authorize -> authorize.anyRequest().permitAll())
				.headers(headers -> headers.disable())
				.addFilterBefore(new IdentityJwkRequestFilter(source), SecurityContextHolderFilter.class);
		return http.build();
	}

	@Bean
	@Order(2)
	SecurityFilterChain userInfoSecurity(HttpSecurity http, AuthorizationServerSettings settings, IdentityAccessTokens tokens,
			IdentityUsers users, SecurityAudits audits, PlatformTransactionManager transactions) throws Exception {
		var provider = new IdentityUserInfoProvider(new IdentityAccessTokenVerifier(tokens, settings.getIssuer()), users);
		http.securityMatcher(PathPatternRequestMatcher.withDefaults().matcher(IdentityProtocolResponses.USER_INFO_ENDPOINT))
				.securityContext(context -> context.securityContextRepository(new NullSecurityContextRepository()))
				.sessionManagement(session -> session.disable()).requestCache(cache -> cache.disable())
				.httpBasic(basic -> basic.disable()).csrf(csrf -> csrf.disable())
				.authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
				.headers(headers -> headers.disable())
				.addFilterBefore(new IdentityUserInfoRequestFilter(provider, audits, transactions), SecurityContextHolderFilter.class);
		return http.build();
	}

	@Bean
	@Order(1)
	SecurityFilterChain protocolSecurity(HttpSecurity http, AuthorizationServerSettings settings, IdentityProtocolClients clients,
			IdentityApplicationRoles applications, IdentityAuthorizationSessions sessions, IdentityAuthorizations authorizations,
			IdentityAuthorizationBindings bindings, IdentityRefreshTokens refresh, IdentitySigningKeys keys,
			SecurityAudits audits, PlatformTransactionManager transactions) throws Exception {
		var store = new IdentityProtocolAuthorizations(authorizations);
		var client = new IdentityClientAuthenticationProvider(clients, store);
		var code = new IdentityAuthorizationCodeProvider(applications, sessions, authorizations, bindings, refresh, keys, audits, transactions);
		var renewal = new IdentityRefreshTokenProvider(applications, authorizations, bindings, refresh, keys, audits, transactions);
		var requests = new IdentityTokenRequestFilter(audits, transactions);
		var server = new OAuth2AuthorizationServerConfigurer();
		server.withObjectPostProcessor(new ObjectPostProcessor<OAuth2TokenEndpointFilter>() {
			@Override public <O extends OAuth2TokenEndpointFilter> O postProcess(O filter) {
				filter.setAuthenticationDetailsSource(requests::grantEvidence); return filter;
			}
		});
		http.securityMatcher(PathPatternRequestMatcher.withDefaults().matcher(IdentityProtocolResponses.TOKEN_ENDPOINT))
				// No parent manager or default provider may turn a failed bound decision into a different grant.
				.authenticationManager(new ProviderManager(List.of(client, code, renewal)))
				.with(server, protocol -> protocol.authorizationServerSettings(settings)
						.registeredClientRepository(new IdentityRegisteredClientRepository(clients)).authorizationService(store)
						.clientAuthentication(endpoint -> endpoint
								.authenticationConverters(converters -> {
									converters.clear();
									var basic = new ClientSecretBasicAuthenticationConverter();
									converters.add(request -> {
										var proof = basic.convert(request);
										if (proof == null) { throw new OAuth2AuthenticationException("invalid_client"); }
										return proof;
									});
								})
								.authenticationProviders(providers -> { providers.clear(); providers.add(client); })
								.errorResponseHandler(requests.failureHandler()))
						.tokenEndpoint(endpoint -> endpoint
								.accessTokenRequestConverters(converters -> {
									converters.clear(); converters.add(new OAuth2AuthorizationCodeAuthenticationConverter()); converters.add(new OAuth2RefreshTokenAuthenticationConverter());
								})
								.authenticationProviders(providers -> { providers.clear(); providers.add(code); providers.add(renewal); })
								.errorResponseHandler(requests.failureHandler())))
				.securityContext(context -> context.securityContextRepository(new NullSecurityContextRepository()))
				.sessionManagement(session -> session.disable())
				.requestCache(cache -> cache.disable()).httpBasic(basic -> basic.disable())
				.authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
				.exceptionHandling(errors -> errors.authenticationEntryPoint((request, response, failure) ->
						IdentityProtocolResponses.error(response, 401, "invalid_client")))
				.headers(headers -> headers.disable())
				.addFilterBefore(requests, CsrfFilter.class);
		return http.build();
	}

}
