package com.ixayda.iam.security;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import com.ixayda.iam.service.IdentityBrowserSessions;

import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.aop.framework.ProxyFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.session.Session;
import org.springframework.session.jdbc.JdbcIndexedSessionRepository;

/** Adapts the official repository through its public interfaces and tracks session mutations. */
final class IdentityBrowserSessionRepositoryAdapter implements BeanPostProcessor {

	private final ObjectProvider<IdentityBrowserSessions> sessions;

	IdentityBrowserSessionRepositoryAdapter(ObjectProvider<IdentityBrowserSessions> sessions) {
		this.sessions = sessions;
	}

	@Override
	public Object postProcessAfterInitialization(Object bean, String beanName) {
		if (!(bean instanceof JdbcIndexedSessionRepository repository)) {
			return bean;
		}
		var proxy = new ProxyFactory(bean);
		// The public repository interfaces permit decorated Sessions; JdbcSession itself is final.
		proxy.setProxyTargetClass(false);
		proxy.addAdvice((MethodInterceptor) invocation -> {
			String method = invocation.getMethod().getName();
			if (method.equals("createSession") || method.equals("findById")) {
				Session loaded = (Session) invocation.proceed();
				return loaded == null ? null : new IdentityBrowserSession(loaded, method.equals("createSession"));
			}
			if (method.equals("findByIndexNameAndIndexValue") || method.equals("findByPrincipalName")) {
				Map<?, ?> found = (Map<?, ?>) invocation.proceed();
				Map<String, Session> decorated = new HashMap<>();
				found.forEach((id, value) -> decorated.put((String) id, new IdentityBrowserSession((Session) value, false)));
				return decorated;
			}
			if (method.equals("save")) {
				if (!(invocation.getArguments()[0] instanceof IdentityBrowserSession session)) {
					throw new IllegalArgumentException("Tracked browser session is required");
				}
				invocation.getArguments()[0] = session.delegate();
				this.sessions.getObject().save(session, () -> proceed(invocation), () -> repository.findById(session.getId()), session::changedAttributes);
				session.saved();
				return null;
			}
			if (method.equals("deleteById")) {
				Authentication caller = SecurityContextHolder.getContext().getAuthentication();
				UUID actor = caller != null && caller.isAuthenticated() && caller.getPrincipal() instanceof UUID id ? id : null;
				this.sessions.getObject().delete((String) invocation.getArguments()[0], actor, () -> proceed(invocation));
				return null;
			}
			return invocation.proceed();
		});
		return proxy.getProxy();
	}

	private static void proceed(MethodInvocation invocation) {
		try {
			invocation.proceed();
		}
		catch (RuntimeException ex) {
			throw ex;
		}
		catch (Throwable ex) {
			throw new IllegalStateException("Browser session storage failed", ex);
		}
	}
}
