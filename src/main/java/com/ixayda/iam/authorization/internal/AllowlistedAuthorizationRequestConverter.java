package com.ixayda.iam.authorization.internal;

import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationCodeRequestAuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.StringUtils;

final class AllowlistedAuthorizationRequestConverter implements AuthenticationConverter {

	private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1";

	static final String CONTINUE_PARAMETER = "continue";

	private static final Set<String> ALLOWED_PARAMETERS = Set.of(OAuth2ParameterNames.RESPONSE_TYPE,
			OAuth2ParameterNames.CLIENT_ID, OAuth2ParameterNames.REDIRECT_URI, OAuth2ParameterNames.SCOPE,
			OAuth2ParameterNames.STATE, PkceParameterNames.CODE_CHALLENGE,
			PkceParameterNames.CODE_CHALLENGE_METHOD, "nonce", "prompt");

	private final AuthenticationConverter delegate;

	AllowlistedAuthorizationRequestConverter() {
		this(new OAuth2AuthorizationCodeRequestAuthenticationConverter());
	}

	AllowlistedAuthorizationRequestConverter(AuthenticationConverter delegate) {
		this.delegate = Objects.requireNonNull(delegate, "Authorization request converter must not be null");
	}

	@Override
	public Authentication convert(HttpServletRequest request) {
		Authentication authentication = this.delegate.convert(withoutContinueParameter(request));
		if (authentication == null) {
			return null;
		}
		if (!hasValidParameters(request.getParameterMap())) {
			throw invalidRequest();
		}
		return authentication;
	}

	static boolean hasValidParameters(Map<String, String[]> parameters) {
		for (Map.Entry<String, String[]> parameter : parameters.entrySet()) {
			String[] values = parameter.getValue();
			if (CONTINUE_PARAMETER.equals(parameter.getKey())) {
				if (values == null || values.length != 1 || !values[0].isEmpty()) {
					return false;
				}
				continue;
			}
			if (!ALLOWED_PARAMETERS.contains(parameter.getKey()) || values == null || values.length != 1
					|| !StringUtils.hasText(values[0])) {
				return false;
			}
		}
		return true;
	}

	private static OAuth2AuthorizationCodeRequestAuthenticationException invalidRequest() {
		OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST,
				"Authorization request parameters are invalid or unsupported", ERROR_URI);
		return new OAuth2AuthorizationCodeRequestAuthenticationException(error, null);
	}

	private static HttpServletRequest withoutContinueParameter(HttpServletRequest request) {
		return request.getParameterMap().containsKey(CONTINUE_PARAMETER)
				? new FilteredParameterRequest(request, CONTINUE_PARAMETER) : request;
	}

	private static final class FilteredParameterRequest extends HttpServletRequestWrapper {

		private final Map<String, String[]> parameters;

		private FilteredParameterRequest(HttpServletRequest request, String excludedParameter) {
			super(request);
			Map<String, String[]> filtered = new LinkedHashMap<>(request.getParameterMap());
			filtered.remove(excludedParameter);
			this.parameters = Collections.unmodifiableMap(filtered);
		}

		@Override
		public String getParameter(String name) {
			String[] values = getParameterValues(name);
			return values == null || values.length == 0 ? null : values[0];
		}

		@Override
		public Map<String, String[]> getParameterMap() {
			return this.parameters;
		}

		@Override
		public Enumeration<String> getParameterNames() {
			return Collections.enumeration(this.parameters.keySet());
		}

		@Override
		public String[] getParameterValues(String name) {
			String[] values = this.parameters.get(name);
			return values == null ? null : values.clone();
		}

	}

}
