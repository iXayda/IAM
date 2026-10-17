package com.ixayda.iam.security;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;

import com.ixayda.iam.model.PasswordAuthenticationContext;

import tools.jackson.core.JacksonException;
import tools.jackson.core.StreamReadFeature;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.json.JsonMapper;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

/** Uses Spring Security's session and CSRF lifecycle with JSON credentials. */
final class IdentityBrowserAuthenticationConfigurer extends AbstractAuthenticationFilterConfigurer<HttpSecurity,
		IdentityBrowserAuthenticationConfigurer, IdentityBrowserAuthenticationConfigurer.JsonAuthenticationFilter> {

	IdentityBrowserAuthenticationConfigurer() {
		setAuthenticationFilter(new JsonAuthenticationFilter());
	}

	@Override
	protected RequestMatcher createLoginProcessingUrlMatcher(String url) {
		return getRequestMatcherBuilder().matcher(HttpMethod.POST, url);
	}

	static final class JsonAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

		private static final JsonMapper JSON = JsonMapper.builder()
				.enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
				.enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS).build();

		@Override
		public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
			try {
				byte[] bytes = request.getInputStream().readNBytes(8193);
				if (bytes.length > 8192) {
					throw new InvalidRequest(IdentityBrowserResponses.Error.PAYLOAD_TOO_LARGE);
				}
				var body = JSON.readTree(bytes);
				if (body == null || !body.isObject() || body.size() != 2
						|| !body.path("username").isString() || !body.path("password").isString()) {
					throw new InvalidRequest(IdentityBrowserResponses.Error.BAD_REQUEST);
				}
				var authentication = UsernamePasswordAuthenticationToken.unauthenticated(
						body.path("username").asText(), body.path("password").asText());
				try {
					authentication.setDetails(new PasswordAuthenticationContext("browser:password",
							InetAddress.getByName(request.getRemoteAddr()), IdentityBrowserDiagnostics.correlationId(request)));
					return getAuthenticationManager().authenticate(authentication);
				}
				finally { authentication.eraseCredentials(); }
			}
			catch (JacksonException ex) {
				throw new InvalidRequest(IdentityBrowserResponses.Error.BAD_REQUEST);
			}
			catch (UnknownHostException ex) {
				throw new AuthenticationServiceException("Trusted transport address is unavailable");
			}
			catch (IOException ex) {
				throw new InvalidRequest(IdentityBrowserResponses.Error.BAD_REQUEST);
			}
		}
	}

	static final class InvalidRequest extends AuthenticationException {
		private final IdentityBrowserResponses.Error error;

		InvalidRequest(IdentityBrowserResponses.Error error) {
			super("Invalid browser authentication request");
			this.error = error;
		}

		IdentityBrowserResponses.Error error() { return this.error; }
	}
}
