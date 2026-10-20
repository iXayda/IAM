package com.ixayda.iam.security;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.converter.FormHttpMessageConverter;

/** Reads only the introspection form under its larger budget, leaving Tomcat's browser form limit unchanged. */
final class IdentityIntrospectionFormRequest extends HttpServletRequestWrapper {

	static final int MAX_BYTES = 20_480;
	private final Map<String, String[]> parameters;

	IdentityIntrospectionFormRequest(HttpServletRequest request) throws IOException {
		super(request);
		byte[] body = request.getInputStream().readNBytes(MAX_BYTES + 1);
		if (body.length > MAX_BYTES) { throw new TooLargeException(); }
		var headers = new HttpHeaders(); headers.set(HttpHeaders.CONTENT_TYPE, request.getContentType());
		org.springframework.util.MultiValueMap<String, String> form;
		try { form = new FormHttpMessageConverter().read(null, new HttpInputMessage() {
			@Override public HttpHeaders getHeaders() { return headers; }
			@Override public InputStream getBody() { return new ByteArrayInputStream(body); }
		}); }
		catch (org.springframework.http.converter.HttpMessageNotReadableException ex) { throw new IllegalArgumentException("Malformed introspection form", ex); }
		var values = new LinkedHashMap<String, String[]>();
		form.forEach((key, entries) -> values.put(key, entries.toArray(String[]::new)));
		this.parameters = Collections.unmodifiableMap(values);
	}

	@Override public String getParameter(String name) {
		String[] values = this.parameters.get(name); return values == null || values.length == 0 ? null : values[0];
	}
	@Override public String[] getParameterValues(String name) {
		String[] values = this.parameters.get(name); return values == null ? null : values.clone();
	}
	@Override public Map<String, String[]> getParameterMap() {
		var copy = new LinkedHashMap<String, String[]>(); this.parameters.forEach((key, values) -> copy.put(key, values.clone()));
		return Collections.unmodifiableMap(copy);
	}
	@Override public Enumeration<String> getParameterNames() { return Collections.enumeration(this.parameters.keySet()); }

	static final class TooLargeException extends IllegalArgumentException { }
}
