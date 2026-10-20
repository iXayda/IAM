package com.ixayda.iam.controller;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import com.ixayda.iam.dto.IdentityClientChangeRequest;
import com.ixayda.iam.dto.IdentityClientConfigurationRequest;
import com.ixayda.iam.dto.IdentityClientCreateRequest;
import com.ixayda.iam.dto.IdentityClientUpdateRequest;

import tools.jackson.core.JacksonException;
import tools.jackson.core.StreamReadFeature;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import jakarta.servlet.http.HttpServletRequest;

/** Parses the bounded client JSON contract without scalar coercion or ignored fields. */
final class IdentityClientRequests {

	private static final JsonMapper JSON = JsonMapper.builder().enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
			.enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS).build();

	private IdentityClientRequests() { }

	static IdentityClientCreateRequest create(HttpServletRequest request) {
		var body = body(request, Set.of("configuration", "code"));
		return new IdentityClientCreateRequest(configuration(body.path("configuration")), text(body.path("code")));
	}

	static IdentityClientUpdateRequest update(HttpServletRequest request) {
		var body = body(request, Set.of("version", "configuration", "code"));
		return new IdentityClientUpdateRequest(version(body.path("version")), configuration(body.path("configuration")), text(body.path("code")));
	}

	static IdentityClientChangeRequest change(HttpServletRequest request) {
		var body = body(request, Set.of("version", "code"));
		return new IdentityClientChangeRequest(version(body.path("version")), text(body.path("code")));
	}

	static UUID id(String value) {
		UUID id = UUID.fromString(value);
		if (!id.toString().equalsIgnoreCase(value)) { throw invalid(); }
		return id;
	}

	private static JsonNode body(HttpServletRequest request, Set<String> fields) {
		if (request.getQueryString() != null) { throw invalid(); }
		try {
			byte[] bytes = request.getInputStream().readNBytes(8193);
			if (bytes.length > 8192) { throw new BodyTooLargeException(); }
			var body = JSON.readTree(bytes);
			requireFields(body, fields);
			return body;
		}
		catch (JacksonException | IOException ex) { throw invalid(); }
	}

	private static IdentityClientConfigurationRequest configuration(JsonNode node) {
		requireFields(node, Set.of("displayName", "resourceId", "redirectUris", "scopes", "allowedRoleIds"));
		var roles = strings(node.path("allowedRoleIds")).stream().map(IdentityClientRequests::id).toList();
		if (roles.stream().distinct().count() != roles.size()) { throw invalid(); }
		return new IdentityClientConfigurationRequest(text(node.path("displayName")), id(text(node.path("resourceId"))),
				strings(node.path("redirectUris")), strings(node.path("scopes")), roles);
	}

	private static void requireFields(JsonNode node, Set<String> fields) {
		if (node == null || !node.isObject() || node.size() != fields.size() || !fields.containsAll(node.propertyNames())) { throw invalid(); }
	}

	private static String text(JsonNode node) { if (!node.isString()) { throw invalid(); } return node.asText(); }
	private static long version(JsonNode node) {
		if (!node.isIntegralNumber() || !node.canConvertToLong() || node.longValue() < 1) { throw invalid(); }
		return node.longValue();
	}

	private static List<String> strings(JsonNode node) {
		if (!node.isArray()) { throw invalid(); }
		var values = new ArrayList<String>(node.size());
		for (int i = 0; i < node.size(); i++) { values.add(text(node.path(i))); }
		if (values.stream().distinct().count() != values.size()) { throw invalid(); }
		return List.copyOf(values);
	}

	private static IllegalArgumentException invalid() { return new IllegalArgumentException("Invalid client request"); }
	static final class BodyTooLargeException extends RuntimeException { }

}
