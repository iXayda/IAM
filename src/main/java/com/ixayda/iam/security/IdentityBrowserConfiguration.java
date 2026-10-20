package com.ixayda.iam.security;

import java.util.List;
import java.util.UUID;

import com.ixayda.iam.model.PasswordAuthenticationResult;
import com.ixayda.iam.service.IdentityAdministratorSessions;
import com.ixayda.iam.service.IdentityBrowserSessions;

import jakarta.servlet.DispatcherType;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationManagers;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.authentication.session.ChangeSessionIdAuthenticationStrategy;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.csrf.CsrfException;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.security.web.header.HeaderWriter;
import org.springframework.security.web.header.writers.CacheControlHeadersWriter;
import org.springframework.security.web.header.writers.CompositeHeaderWriter;
import org.springframework.security.web.header.writers.ContentSecurityPolicyHeaderWriter;
import org.springframework.security.web.header.writers.HstsHeaderWriter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter.ReferrerPolicy;
import org.springframework.security.web.header.writers.XContentTypeOptionsHeaderWriter;
import org.springframework.security.web.header.writers.XXssProtectionHeaderWriter;
import org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter;
import org.springframework.session.FlushMode;
import org.springframework.session.SaveMode;
import org.springframework.session.config.SessionRepositoryCustomizer;
import org.springframework.session.jdbc.JdbcIndexedSessionRepository;
import org.springframework.session.web.http.CookieSerializer;
import org.springframework.session.web.http.DefaultCookieSerializer;
import org.springframework.session.web.http.SessionRepositoryFilter;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionOperations;
import org.springframework.transaction.support.TransactionTemplate;

@Configuration(proxyBeanMethods = false)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@EnableScheduling
public class IdentityBrowserConfiguration {

	@Bean
	SecurityFilterChain browserSecurity(HttpSecurity http, AuthenticationManager manager,
			IdentityBrowserSessions sessions, IdentityAdministratorSessions administrators, CsrfTokenRepository csrfTokens) throws Exception {
		var fixation = new ChangeSessionIdAuthenticationStrategy();
		AuthorizationManager<RequestAuthorizationContext> administrator = (authentication, context) -> {
			var current = authentication.get();
			return new AuthorizationDecision(current.isAuthenticated() && current.getPrincipal() instanceof UUID id && administrators.isAdministrator(id));
		};
		AuthorizationManager<RequestAuthorizationContext> management = AuthorizationManagers.allOf(
				AuthorityAuthorizationManager.<RequestAuthorizationContext>hasAuthority(IdentityAdministratorSessions.ADMINISTRATOR_AUTHORITY),
				AuthorityAuthorizationManager.<RequestAuthorizationContext>hasAuthority(FactorGrantedAuthority.PASSWORD_AUTHORITY),
				AuthorityAuthorizationManager.<RequestAuthorizationContext>hasAuthority(IdentityAdministratorSessions.TOTP_AUTHORITY));
		http.authenticationManager(manager)
				.authorizeHttpRequests(authorize -> authorize
						.requestMatchers(HttpMethod.GET, "/api/csrf").permitAll()
						.requestMatchers(HttpMethod.POST, "/login", "/logout").permitAll()
						.requestMatchers(HttpMethod.POST, "/api/account-setup/complete", "/api/password-recovery/complete").permitAll()
						.requestMatchers(HttpMethod.POST, "/admin/mfa").access(administrator)
						.requestMatchers(HttpMethod.GET, "/api/admin/clients", "/api/admin/clients/{clientId}").access(management)
						.requestMatchers(HttpMethod.POST, "/api/admin/clients", "/api/admin/clients/{clientId}/configuration", "/api/admin/clients/{clientId}/disable", "/api/admin/clients/{clientId}/enable", "/api/admin/clients/{clientId}/secret/rotate").access(management)
						.requestMatchers(HttpMethod.GET, "/api/admin/resources/{resourceId}/validation-credential").access(management)
						.requestMatchers(HttpMethod.POST, "/api/admin/resources/{resourceId}/validation-credential/rotate", "/api/admin/resources/{resourceId}/validation-credential/disable").access(management)
						.requestMatchers(HttpMethod.GET, "/api/admin/users/{userId}/resources/{resourceId}/roles").access(management)
						.requestMatchers(HttpMethod.POST, "/api/admin/users/{userId}/roles/{roleId}/grant", "/api/admin/users/{userId}/roles/{roleId}/revoke").access(management)
						.requestMatchers(HttpMethod.POST, "/api/admin/resources/{resourceId}/roles", "/api/admin/resource-roles/{roleId}/name", "/api/admin/resource-roles/{roleId}/disable", "/api/admin/resource-roles/{roleId}/enable").access(management)
						.requestMatchers(HttpMethod.POST, "/api/admin/resources", "/api/admin/resources/{resourceId}/name", "/api/admin/resources/{resourceId}/disable", "/api/admin/resources/{resourceId}/enable").access(management)
						.requestMatchers(HttpMethod.POST, "/api/admin/users", "/api/admin/users/{userId}/disable", "/api/admin/users/{userId}/enable", "/api/admin/users/{userId}/profile").access(management)
						.requestMatchers(HttpMethod.POST, "/api/admin/users/{userId}/sessions/revoke-all").access(management)
						.requestMatchers(HttpMethod.POST, "/api/admin/users/{userId}/setup", "/api/admin/users/{userId}/setup/cancel").access(management)
						.requestMatchers(HttpMethod.POST, "/api/admin/users/{userId}/password-recovery", "/api/admin/users/{userId}/password-recovery/cancel").access(management)
						.requestMatchers(HttpMethod.GET, "/api/admin/me", "/api/admin/users", "/api/admin/users/{userId}", "/api/admin/audits", "/api/admin/resources", "/api/admin/resources/{resourceId}", "/api/admin/resources/{resourceId}/roles", "/api/admin/resource-roles/{roleId}").access(management)
						.requestMatchers(HttpMethod.GET, "/api/me", "/v3/api-docs", "/v3/api-docs.yaml").authenticated()
						.requestMatchers(HttpMethod.GET, "/api/me/authorizations").authenticated()
						.requestMatchers(HttpMethod.POST, "/api/me/authorizations/{authorizationId}/revoke").authenticated()
						.requestMatchers(HttpMethod.GET, "/api/me/sessions").authenticated()
						.requestMatchers(HttpMethod.POST, "/api/me/sessions/{sessionId}/revoke", "/api/me/sessions/revoke-all").authenticated()
						.requestMatchers(HttpMethod.POST, "/api/me/profile", "/api/me/password", "/api/me/mfa/recovery-codes").authenticated()
						.requestMatchers(HttpMethod.POST, "/api/me/mfa/totp/enrollment", "/api/me/mfa/totp/enrollment/confirm", "/api/me/mfa/totp/enrollment/cancel").authenticated()
						.requestMatchers(HttpMethod.POST, "/api/me/mfa/totp/replacement", "/api/me/mfa/totp/replacement/complete").authenticated()
						.requestMatchers(HttpMethod.POST, "/api/me/mfa/totp/recovery", "/api/me/mfa/totp/recovery/complete").authenticated()
						.anyRequest().denyAll())
				.requestCache(cache -> cache.disable())
				.httpBasic(basic -> basic.disable())
				.csrf(csrf -> csrf.csrfTokenRepository(csrfTokens))
				.exceptionHandling(errors -> errors.defaultAuthenticationEntryPointFor(
						(request, response, failure) -> {
							if (isAdministratorPath(request.getServletPath())) {
								administrators.recordAccessDenied(null, IdentityBrowserDiagnostics.correlationId(request));
							}
							IdentityBrowserResponses.error(response, IdentityBrowserResponses.Error.UNAUTHENTICATED);
						}, request -> true).accessDeniedHandler((request, response, failure) -> {
							if (isAdministratorPath(request.getServletPath())) {
								var authentication = SecurityContextHolder.getContext().getAuthentication();
								administrators.recordAccessDenied(authentication != null && authentication.getPrincipal() instanceof UUID id ? id : null,
										IdentityBrowserDiagnostics.correlationId(request));
							}
							IdentityBrowserResponses.error(response, failure instanceof CsrfException
								? IdentityBrowserResponses.Error.CSRF_INVALID : IdentityBrowserResponses.Error.FORBIDDEN);
						}))
				.sessionManagement(session -> session.sessionAuthenticationStrategy((authentication, request, response) -> {
					if (!(authentication.getDetails() instanceof PasswordAuthenticationResult verified)
							|| !verified.userId().equals(authentication.getPrincipal())) {
						throw new AuthenticationServiceException("Verified password version is required");
					}
					String originalId = request.getSession().getId();
					fixation.onAuthentication(authentication, request, response);
					request.getSession().setAttribute(IdentityBrowserSessions.ORIGINAL_ID, originalId);
					request.getSession().setAttribute(IdentityBrowserSessions.LOGIN_PENDING, true);
					request.getSession().setAttribute(IdentityBrowserSessions.CREDENTIAL_VERSION, verified.credentialVersion());
					request.getSession().removeAttribute(IdentityAdministratorSessions.AUTHENTICATION);
				}))
				.with(new IdentityBrowserAuthenticationConfigurer(), login -> login
						.successHandler((request, response, authentication) -> {
							if (!(request.getAttribute(CsrfToken.class.getName()) instanceof CsrfToken token)) {
								throw new IllegalStateException("Browser CSRF token is unavailable");
							}
							token.getToken();
							response.setStatus(204);
						})
						.failureHandler((request, response, exception) -> {
							if (exception instanceof IdentityBrowserAuthenticationConfigurer.InvalidRequest invalid) {
								IdentityBrowserResponses.error(response, invalid.error());
							}
							else if (exception instanceof AuthenticationServiceException) {
								IdentityBrowserDiagnostics.recordFailure(request, IdentityBrowserDiagnostics.Stage.AUTHENTICATION, exception);
								IdentityBrowserResponses.error(response, IdentityBrowserResponses.Error.AUTHENTICATION_UNAVAILABLE);
							}
							else {
								IdentityBrowserResponses.error(response, IdentityBrowserResponses.Error.INVALID_CREDENTIALS);
							}
						}))
				.logout(logout -> logout.logoutSuccessHandler((request, response, authentication) -> response.setStatus(204)).permitAll())
				// The outer admission boundary applies the shared policy, including early and rollback responses.
				.headers(headers -> headers.disable())
				.addFilterAfter(new IdentityBrowserSessionValidationFilter(sessions, administrators), SecurityContextHolderFilter.class);
		return http.build();
	}

	private static boolean isAdministratorPath(String path) {
		return path.startsWith("/admin/") || path.startsWith("/api/admin/");
	}

	@Bean
	CsrfTokenRepository browserCsrfTokens() { return new HttpSessionCsrfTokenRepository(); }

	@Bean
	CookieSerializer browserCookieSerializer() {
		var serializer = new DefaultCookieSerializer();
		serializer.setCookieName("__Host-IAMSESSION");
		serializer.setCookiePath("/");
		serializer.setUseSecureCookie(true);
		serializer.setUseHttpOnlyCookie(true);
		serializer.setSameSite("Lax");
		serializer.setUseBase64Encoding(false);
		return serializer;
	}

	@Bean
	SessionRepositoryCustomizer<JdbcIndexedSessionRepository> browserSessionPolicy(IdentityBrowserSessions sessions) {
		return repository -> {
			repository.setDefaultMaxInactiveInterval(sessions.idleTimeout());
			repository.setSaveMode(SaveMode.ON_SET_ATTRIBUTE);
			repository.setFlushMode(FlushMode.ON_SAVE);
			// Independent snapshots may create the same immutable interaction owner.
			// A collision must not overwrite another value; the audited adapter verifies every requested attribute after saving.
			repository.setCreateSessionAttributeQuery("""
					INSERT INTO %TABLE_NAME%_ATTRIBUTES (SESSION_PRIMARY_ID, ATTRIBUTE_NAME, ATTRIBUTE_BYTES)
					VALUES (?, ?, ?) ON CONFLICT (SESSION_PRIMARY_ID, ATTRIBUTE_NAME) DO NOTHING
					""");
		};
	}

	@Bean
	TransactionOperations springSessionTransactionOperations(PlatformTransactionManager manager) {
		// Lifecycle operations open their own transaction; JDBC writes and mandatory audit join that transaction.
		return new TransactionTemplate(manager);
	}

	@Bean
	static BeanPostProcessor auditedSessionRepository(ObjectProvider<IdentityBrowserSessions> sessions) {
		return new IdentityBrowserSessionRepositoryAdapter(sessions);
	}

	@Bean
	HeaderWriter browserSecurityHeaders() {
		String policy = "default-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";
		return new CompositeHeaderWriter(List.of(new CacheControlHeadersWriter(),
				new XContentTypeOptionsHeaderWriter(), new XXssProtectionHeaderWriter(), new HstsHeaderWriter(),
				new XFrameOptionsHeaderWriter(), new ContentSecurityPolicyHeaderWriter(policy),
				new ReferrerPolicyHeaderWriter(ReferrerPolicy.NO_REFERRER)));
	}

	@Bean
	FilterRegistrationBean<IdentityBrowserBoundaryFilter> browserBoundary(IdentityBrowserSessions sessions,
			@Value("${iam.browser.requests-per-second:100}") int requestsPerSecond,
			@Value("${iam.browser.concurrent-requests:8}") int concurrentRequests, HeaderWriter browserSecurityHeaders,
			ObjectProvider<IdentityIntrospectionFailures> introspectionFailures) {
		var registration = new FilterRegistrationBean<>(new IdentityBrowserBoundaryFilter(sessions, requestsPerSecond, concurrentRequests, browserSecurityHeaders, introspectionFailures.getIfAvailable()));
		registration.setOrder(SessionRepositoryFilter.DEFAULT_ORDER - 1);
		registration.setDispatcherTypes(DispatcherType.REQUEST);
		registration.setAsyncSupported(false);
		return registration;
	}
}
