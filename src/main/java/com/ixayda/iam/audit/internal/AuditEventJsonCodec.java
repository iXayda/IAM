package com.ixayda.iam.audit.internal;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

import org.springframework.dao.DataRetrievalFailureException;
import tools.jackson.databind.json.JsonMapper;

final class AuditEventJsonCodec {

	private final JsonMapper jsonMapper = JsonMapper.builder().build();

	String write(Map<String, String> attributes) {
		Objects.requireNonNull(attributes, "Audit event attributes must not be null");
		try {
			return this.jsonMapper.writeValueAsString(attributes);
		}
		catch (Exception exception) {
			throw new IllegalArgumentException("Audit event attribute encoding failed", exception);
		}
	}

	Map<String, String> read(String json) {
		Objects.requireNonNull(json, "Audit event attributes JSON must not be null");
		try {
			Map<?, ?> decoded = this.jsonMapper.readValue(json, Map.class);
			Map<String, String> attributes = new LinkedHashMap<>();
			decoded.forEach((name, value) -> {
				if (!(name instanceof String key) || !(value instanceof String text)) {
					throw new DataRetrievalFailureException("Audit event attributes contain a non-string entry");
				}
				attributes.put(key, text);
			});
			return Map.copyOf(attributes);
		}
		catch (DataRetrievalFailureException exception) {
			throw exception;
		}
		catch (Exception exception) {
			throw new DataRetrievalFailureException("Audit event attribute decoding failed", exception);
		}
	}

}
