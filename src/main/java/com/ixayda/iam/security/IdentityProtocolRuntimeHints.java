package com.ixayda.iam.security;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.aot.hint.BindingReflectionHintsRegistrar;
import org.springframework.aot.hint.MemberCategory;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.RuntimeHintsRegistrar;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.jackson.CoreJacksonModule;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.jackson.OAuth2AuthorizationServerJacksonModule;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.web.jackson.WebJacksonModule;
import org.springframework.security.web.jackson.WebServletJacksonModule;
import org.springframework.util.ClassUtils;

/** SecurityJacksonModules loads the installed JDBC serialization modules by name. */
final class IdentityProtocolRuntimeHints implements RuntimeHintsRegistrar {

	@Override
	public void registerHints(RuntimeHints hints, ClassLoader classLoader) {
		for (Class<?> module : new Class<?>[] { CoreJacksonModule.class, WebJacksonModule.class,
				WebServletJacksonModule.class, OAuth2AuthorizationServerJacksonModule.class }) {
			hints.reflection().registerType(module, MemberCategory.INVOKE_DECLARED_CONSTRUCTORS);
		}
		// JDBC JSON embeds these type ids; its private mappers are outside Spring MVC's binding analysis.
		var bindings = new BindingReflectionHintsRegistrar();
		bindings.registerReflectionHints(hints.reflection(), OAuth2TokenFormat.class, SignatureAlgorithm.class,
				OAuth2AuthorizationRequest.class, UsernamePasswordAuthenticationToken.class, FactorGrantedAuthority.class,
				Duration.class, Instant.class);
		for (String mixin : List.of("org.springframework.security.oauth2.server.authorization.jackson.OAuth2TokenFormatMixin",
				"org.springframework.security.oauth2.server.authorization.jackson.JwsAlgorithmMixin",
				"org.springframework.security.oauth2.server.authorization.jackson.OAuth2AuthorizationRequestMixin",
				"org.springframework.security.jackson.UsernamePasswordAuthenticationTokenMixin",
				"org.springframework.security.jackson.FactorGrantedAuthorityMixin")) {
			bindings.registerReflectionHints(hints.reflection(), ClassUtils.resolveClassName(mixin, classLoader));
		}
		Set.of(Map.of().getClass(), Map.of("key", "value").getClass(), List.of().getClass(), List.of("value").getClass(),
				Set.of().getClass(), Set.of("value").getClass()).forEach(type -> hints.reflection().registerType(type));
	}
}
