package com.ixayda.iam.security;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.UUID;

import com.ixayda.iam.model.IdentityAdministratorAuthentication;

import org.springframework.aop.SpringProxy;
import org.springframework.aop.framework.Advised;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.RuntimeHintsRegistrar;
import org.springframework.aot.hint.TypeReference;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.core.DecoratingProxy;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.session.FindByIndexNameSessionRepository;

/** Concrete values persisted in JDBC browser sessions, including administrator MFA evidence. */
final class IdentityBrowserRuntimeHints implements RuntimeHintsRegistrar {

	@Override
	public void registerHints(RuntimeHints hints, ClassLoader classLoader) {
		// The session audit adapter creates this interface proxy after Spring's AOT bean analysis.
		hints.proxies().registerJdkProxy(FindByIndexNameSessionRepository.class, InitializingBean.class,
				DisposableBean.class, SpringProxy.class, Advised.class, DecoratingProxy.class);
		for (Class<?> type : new Class<?>[] { IdentityAdministratorAuthentication.class, SecurityContextImpl.class,
				UsernamePasswordAuthenticationToken.class, FactorGrantedAuthority.class, SimpleGrantedAuthority.class,
				UUID.class, Instant.class, Long.class, Boolean.class, String.class, ArrayList.class,
				Collections.unmodifiableList(new ArrayList<>()).getClass() }) {
			hints.reflection().registerJavaSerialization(type);
		}
		// Instant uses this JDK serialization delegate; registering Instant alone does not make it loadable.
		hints.reflection().registerType(TypeReference.of("java.time.Ser"), hint -> hint.withJavaSerialization(true));
	}
}
