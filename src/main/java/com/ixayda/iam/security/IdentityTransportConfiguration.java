package com.ixayda.iam.security;

import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.boot.web.server.autoconfigure.ServerProperties.ForwardHeadersStrategy;
import org.springframework.boot.web.server.servlet.ConfigurableServletWebServerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.util.StringUtils;

/** Keep the proxy trust boundary explicit before the Web listener is created. */
@Configuration(proxyBeanMethods = false)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
public class IdentityTransportConfiguration {

	private static final String REMOTE_IP = "server.tomcat.remoteip.";

	@Bean
	WebServerFactoryCustomizer<ConfigurableServletWebServerFactory> transportPolicy(Environment environment) {
		// Read at server creation, so one AOT artifact supports either runtime configuration.
		return factory -> validate(environment);
	}

	private static void validate(Environment environment) {
		var properties = Binder.get(environment);
		var strategy = properties.bind("server.forward-headers-strategy", ForwardHeadersStrategy.class).orElse(ForwardHeadersStrategy.NONE);
		if (strategy != ForwardHeadersStrategy.NONE && strategy != ForwardHeadersStrategy.NATIVE) {
			throw new IllegalArgumentException("IAM supports NONE or NATIVE forwarded headers with an explicit proxy allowlist");
		}
		if (strategy == ForwardHeadersStrategy.NONE) {
			// Tomcat can install RemoteIpValve from these properties even with strategy NONE.
			for (String property : new String[] { "protocol-header", "remote-ip-header", "trusted-proxies" }) {
				if (StringUtils.hasText(properties.bind(REMOTE_IP + property, String.class).orElse(null))) {
					throw new IllegalArgumentException("Tomcat forwarded headers require NATIVE strategy and an explicit proxy allowlist");
				}
			}
			return;
		}
		String proxies = properties.bind(REMOTE_IP + "internal-proxies", String.class).orElse(null);
		if (!StringUtils.hasText(proxies)) { throw new IllegalArgumentException("NATIVE forwarded headers require an explicit proxy allowlist"); }
		try {
			var pattern = Pattern.compile(proxies);
			if (pattern.matcher("").matches() || pattern.matcher("not-an-ip-address").matches()) {
				throw new IllegalArgumentException("The proxy allowlist must restrict proxy addresses");
			}
		}
		catch (PatternSyntaxException ex) { throw new IllegalArgumentException("The proxy allowlist must be a valid address pattern"); }
		if (StringUtils.hasText(properties.bind(REMOTE_IP + "trusted-proxies", String.class).orElse(null))) {
			throw new IllegalArgumentException("Use internal-proxies as the single explicit proxy allowlist");
		}
		requireHeader(properties, "protocol-header", "X-Forwarded-Proto");
		requireHeader(properties, "remote-ip-header", "X-Forwarded-For");
		requireHeader(properties, "protocol-header-https-value", "https");
		if (!"".equals(properties.bind(REMOTE_IP + "host-header", String.class).orElse(null))
				|| !"".equals(properties.bind(REMOTE_IP + "port-header", String.class).orElse(null))) {
			throw new IllegalArgumentException("Forwarded host and port overrides must be explicitly disabled");
		}
	}

	private static void requireHeader(Binder properties, String property, String expected) {
		if (!expected.equalsIgnoreCase(properties.bind(REMOTE_IP + property, String.class).orElse(expected))) {
			throw new IllegalArgumentException("Proxy transport requires " + property + "=" + expected);
		}
	}
}
