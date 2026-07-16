package com.ixayda.iam.authorization.internal;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.springframework.dao.DataRetrievalFailureException;
import tools.jackson.databind.json.JsonMapper;

final class AuthorizationJsonCodec {

	private static final int MAXIMUM_DEPTH = 8;

	private static final int MAXIMUM_COLLECTION_SIZE = 256;

	private static final String TYPE_PROPERTY = "$iam_type";

	private static final String VALUE_PROPERTY = "value";

	private static final String INSTANT_TYPE = "instant";

	private static final String DATE_TYPE = "date";

	private final JsonMapper jsonMapper;

	AuthorizationJsonCodec() {
		this.jsonMapper = JsonMapper.builder().build();
	}

	String write(Map<String, ?> values) {
		Objects.requireNonNull(values, "JSON values must not be null");
		try {
			return this.jsonMapper.writeValueAsString(normalizeMap(values, 0));
		}
		catch (IllegalArgumentException exception) {
			throw exception;
		}
		catch (Exception exception) {
			throw new IllegalArgumentException("Authorization JSON encoding failed", exception);
		}
	}

	Map<String, Object> read(String json) {
		Objects.requireNonNull(json, "JSON value must not be null");
		try {
			Map<?, ?> parsed = this.jsonMapper.readValue(json, Map.class);
			return restoreMap(parsed, 0);
		}
		catch (DataRetrievalFailureException exception) {
			throw exception;
		}
		catch (Exception exception) {
			throw new DataRetrievalFailureException("Authorization JSON decoding failed", exception);
		}
	}

	private static Map<String, Object> normalizeMap(Map<?, ?> values, int depth) {
		requireDepth(depth);
		requireSize(values.size());
		if (values.containsKey(TYPE_PROPERTY)) {
			throw new IllegalArgumentException("Authorization JSON type markers are reserved");
		}
		Map<String, Object> normalized = new LinkedHashMap<>();
		values.forEach((key, value) -> {
			if (!(key instanceof String name) || name.isEmpty() || name.length() > 256) {
				throw new IllegalArgumentException("Authorization JSON object keys must contain 1 to 256 characters");
			}
			normalized.put(name, normalize(value, depth + 1));
		});
		return normalized;
	}

	private static Object normalize(Object value, int depth) {
		requireDepth(depth);
		if (value == null || value instanceof String || value instanceof Boolean || value instanceof Byte
				|| value instanceof Short || value instanceof Integer || value instanceof Long || value instanceof Float
				|| value instanceof Double || value instanceof BigInteger || value instanceof BigDecimal) {
			return value;
		}
		if (value instanceof Instant instant) {
			return Map.of(TYPE_PROPERTY, INSTANT_TYPE, VALUE_PROPERTY, instant.toString());
		}
		if (value instanceof Date date) {
			return Map.of(TYPE_PROPERTY, DATE_TYPE, VALUE_PROPERTY, date.toInstant().toString());
		}
		if (value instanceof Map<?, ?> map) {
			return normalizeMap(map, depth);
		}
		if (value instanceof Collection<?> collection) {
			requireSize(collection.size());
			List<Object> normalized = new ArrayList<>(collection.size());
			collection.forEach(element -> normalized.add(normalize(element, depth + 1)));
			return normalized;
		}
		throw new IllegalArgumentException(
				"Unsupported authorization JSON value type: " + value.getClass().getName());
	}

	private static Map<String, Object> restoreMap(Map<?, ?> values, int depth) {
		requireDepthForRead(depth);
		requireSizeForRead(values.size());
		Map<String, Object> restored = new LinkedHashMap<>();
		values.forEach((key, value) -> {
			if (!(key instanceof String name) || name.isEmpty() || name.length() > 256) {
				throw new DataRetrievalFailureException("Authorization JSON contains an invalid object key");
			}
			restored.put(name, restore(value, depth + 1));
		});
		return Collections.unmodifiableMap(restored);
	}

	private static Object restore(Object value, int depth) {
		requireDepthForRead(depth);
		if (value == null || value instanceof String || value instanceof Boolean || value instanceof Number) {
			return value;
		}
		if (value instanceof Map<?, ?> map) {
			if (map.size() == 2 && map.get(VALUE_PROPERTY) instanceof String encodedTemporal
					&& (INSTANT_TYPE.equals(map.get(TYPE_PROPERTY)) || DATE_TYPE.equals(map.get(TYPE_PROPERTY)))) {
				try {
					Instant instant = Instant.parse(encodedTemporal);
					return DATE_TYPE.equals(map.get(TYPE_PROPERTY)) ? Date.from(instant) : instant;
				}
				catch (RuntimeException exception) {
					throw new DataRetrievalFailureException("Authorization JSON contains an invalid temporal value", exception);
				}
			}
			if (map.containsKey(TYPE_PROPERTY)) {
				throw new DataRetrievalFailureException("Authorization JSON contains an unsupported type marker");
			}
			return restoreMap(map, depth);
		}
		if (value instanceof Collection<?> collection) {
			requireSizeForRead(collection.size());
			List<Object> restored = new ArrayList<>(collection.size());
			collection.forEach(element -> restored.add(restore(element, depth + 1)));
			return Collections.unmodifiableList(restored);
		}
		throw new DataRetrievalFailureException(
				"Authorization JSON contains an unsupported value type: " + value.getClass().getName());
	}

	private static void requireDepth(int depth) {
		if (depth > MAXIMUM_DEPTH) {
			throw new IllegalArgumentException("Authorization JSON nesting must not exceed 8 levels");
		}
	}

	private static void requireDepthForRead(int depth) {
		if (depth > MAXIMUM_DEPTH) {
			throw new DataRetrievalFailureException("Authorization JSON nesting exceeds 8 levels");
		}
	}

	private static void requireSize(int size) {
		if (size > MAXIMUM_COLLECTION_SIZE) {
			throw new IllegalArgumentException("Authorization JSON collections must not exceed 256 entries");
		}
	}

	private static void requireSizeForRead(int size) {
		if (size > MAXIMUM_COLLECTION_SIZE) {
			throw new DataRetrievalFailureException("Authorization JSON collection exceeds 256 entries");
		}
	}

}
