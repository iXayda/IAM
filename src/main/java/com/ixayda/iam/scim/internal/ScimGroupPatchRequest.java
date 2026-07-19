package com.ixayda.iam.scim.internal;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import com.ixayda.iam.group.ReplaceGroupRequest;
import com.ixayda.iam.user.UserId;
import com.unboundid.scim2.common.Path;
import com.unboundid.scim2.common.exceptions.BadRequestException;
import com.unboundid.scim2.common.exceptions.ScimException;
import com.unboundid.scim2.common.filters.Filter;
import com.unboundid.scim2.common.filters.FilterType;
import com.unboundid.scim2.common.messages.PatchOperation;
import com.unboundid.scim2.common.utils.JsonUtils;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

final class ScimGroupPatchRequest {

	static final String SCHEMA_URN = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

	private static final String INVALID_SYNTAX_DETAIL = "The SCIM PATCH request structure is invalid.";

	private static final String INVALID_PATH_DETAIL = "The SCIM PATCH path is invalid or unsupported.";

	private static final String INVALID_FILTER_DETAIL = "The SCIM PATCH path filter is invalid or unsupported.";

	private static final String INVALID_VALUE_DETAIL = "The SCIM PATCH value is invalid or unsupported.";

	private static final String MUTABILITY_DETAIL = "The SCIM PATCH operation targets an attribute that cannot be modified.";

	private static final String NO_TARGET_DETAIL = "The SCIM PATCH path did not match a target value.";

	private static final String TOO_MANY_DETAIL = "The SCIM PATCH request exceeds the supported complexity limits.";

	private static final int MAX_OPERATIONS = 100;

	private static final int MAX_JSON_NODES = 2_048;

	private static final int MAX_TEXT_CHARACTERS = 65_536;

	private static final int MAX_PATH_CHARACTERS = 512;

	private static final Set<String> TOP_LEVEL_FIELDS = Set.of("schemas", "operations");

	private static final Set<String> OPERATION_FIELDS = Set.of("op", "path", "value");

	private static final Set<String> READ_ONLY_ATTRIBUTES = Set.of("schemas", "id", "meta");

	private static final Set<String> MEMBER_FIELDS = Set.of("value", "type", "$ref", "display");

	private final List<SdkOperation> operations;

	private ScimGroupPatchRequest(List<SdkOperation> operations) {
		this.operations = List.copyOf(operations);
	}

	static ScimGroupPatchRequest parse(ObjectNode source) throws BadRequestException {
		if (source == null) {
			throw invalidSyntax();
		}
		validateRequestComplexity(source);
		validateFields(source, TOP_LEVEL_FIELDS);
		JsonNode schemas = field(source, "schemas");
		if (!(schemas instanceof ArrayNode schemaValues) || schemaValues.size() != 1
				|| !schemaValues.get(0).isString() || !SCHEMA_URN.equals(schemaValues.get(0).stringValue())) {
			throw invalidSyntax();
		}
		JsonNode operationsNode = field(source, "operations");
		if (!(operationsNode instanceof ArrayNode operationValues) || operationValues.isEmpty()) {
			throw invalidSyntax();
		}
		if (operationValues.size() > MAX_OPERATIONS) {
			throw tooMany();
		}
		List<SdkOperation> operations = new ArrayList<>(operationValues.size());
		for (JsonNode operationValue : operationValues) {
			if (!(operationValue instanceof ObjectNode operation)) {
				throw invalidSyntax();
			}
			operations.add(parseOperation(operation));
		}
		return new ScimGroupPatchRequest(operations);
	}

	ReplaceGroupRequest apply(ScimGroupView current, ScimGroupMapper mapper, ScimJsonCodec codec,
			ScimProperties properties) throws BadRequestException {
		ObjectNode writable = codec.jsonMapper().valueToTree(mapper.mapWritable(current));
		try {
			for (SdkOperation sdkOperation : this.operations) {
				boolean targetExists = sdkOperation.path() != null
						&& JsonUtils.pathExists(sdkOperation.path(), writable);
				if (sdkOperation.requireTarget() && !targetExists) {
					throw BadRequestException.noTarget(NO_TARGET_DETAIL);
				}
				if (sdkOperation.immutableValueMismatch() && targetExists) {
					throw mutability();
				}
				PatchOperation actual = sdkOperation.missingTargetOperation() != null && !targetExists
						? sdkOperation.missingTargetOperation() : sdkOperation.operation();
				actual.apply(writable);
				ScimGroupCreateRequest.parse(writable, codec, properties);
			}
		}
		catch (BadRequestException exception) {
			throw safe(exception);
		}
		catch (ScimException | RuntimeException exception) {
			throw invalidValue();
		}
		return ScimGroupCreateRequest.parse(writable, codec, properties).replacement();
	}

	private static SdkOperation parseOperation(ObjectNode source) throws BadRequestException {
		validateFields(source, OPERATION_FIELDS);
		JsonNode opNode = field(source, "op");
		if (opNode == null || !opNode.isString()) {
			throw invalidSyntax();
		}
		OperationType type;
		try {
			type = OperationType.valueOf(opNode.stringValue().toUpperCase(Locale.ROOT));
		}
		catch (IllegalArgumentException exception) {
			throw invalidSyntax();
		}

		JsonNode pathNode = field(source, "path");
		Path path = null;
		if (pathNode != null) {
			if (!pathNode.isString() || pathNode.stringValue().isBlank()) {
				throw invalidPath();
			}
			if (pathNode.stringValue().length() > MAX_PATH_CHARACTERS) {
				throw tooMany();
			}
			try {
				path = normalizePath(Path.fromString(pathNode.stringValue()), type);
			}
			catch (BadRequestException exception) {
				throw safe(exception);
			}
		}

		JsonNode value = field(source, "value");
		if (type == OperationType.REMOVE) {
			if (path == null) {
				throw BadRequestException.noTarget(NO_TARGET_DETAIL);
			}
			if (value != null) {
				throw invalidSyntax();
			}
			return operation(PatchOperation.remove(path), path, false, null);
		}
		if (value == null) {
			throw invalidSyntax();
		}
		if (path == null) {
			if (!(value instanceof ObjectNode objectValue) || objectValue.isEmpty()) {
				throw invalidSyntax();
			}
			validateRootValue(objectValue, type);
			PatchOperation operation = type == OperationType.ADD ? PatchOperation.add(objectValue)
					: PatchOperation.replace(objectValue);
			return operation(operation, null, false, null);
		}

		value = normalizePathValue(path, value);
		if (type == OperationType.ADD && value.isNull()) {
			validateRemoval(path);
			throw invalidValue();
		}
		if (type == OperationType.REPLACE && isUnassigned(path, value)) {
			validateRemoval(path);
			boolean requireTarget = type == OperationType.REPLACE
					&& path.getElement(0).getValueFilter() != null;
			return operation(PatchOperation.remove(path), path, requireTarget, null);
		}
		if (type == OperationType.ADD && path.getElement(0).getValueFilter() != null) {
			return filteredAdd(path, value);
		}
		if (type == OperationType.REPLACE && path.getElement(0).getValueFilter() != null) {
			return filteredReplace(path, value);
		}
		boolean requireTarget = type == OperationType.REPLACE
				&& path.getElement(0).getValueFilter() != null;
		PatchOperation operation = type == OperationType.ADD ? PatchOperation.add(path, value)
				: PatchOperation.replace(path, value);
		return operation(operation, path, requireTarget, null);
	}

	private static Path normalizePath(Path path, OperationType type) throws BadRequestException {
		if (path.isRoot() || path.size() > 2
				|| path.getSchemaUrn() != null && !ScimGroupSchema.URN.equals(path.getSchemaUrn())) {
			throw invalidPath();
		}
		String attribute = path.getElement(0).getAttribute();
		String canonical = canonicalAttribute(attribute);
		if (canonical == null) {
			if (READ_ONLY_ATTRIBUTES.contains(attribute.toLowerCase(Locale.ROOT))) {
				throw mutability();
			}
			throw invalidPath();
		}
		if (path.size() == 2) {
			if (canonical.equals("members")) {
				throw mutability();
			}
			throw invalidPath();
		}
		Filter filter = path.getElement(0).getValueFilter();
		if (filter != null) {
			if (!canonical.equals("members")) {
				throw invalidFilter();
			}
			filter = normalizeMemberFilter(filter);
		}
		if (type == OperationType.REMOVE && canonical.equals("displayName")) {
			throw mutability();
		}
		return Path.root().attribute(canonical, filter);
	}

	private static Filter normalizeMemberFilter(Filter filter) throws BadRequestException {
		if (filter.getFilterType() != FilterType.EQUAL || filter.isCombiningFilter()
				|| filter.isNotFilter() || filter.isComplexValueFilter()) {
			throw invalidFilter();
		}
		Path attributePath = filter.getAttributePath();
		JsonNode comparison = filter.getComparisonValue();
		if (attributePath == null || attributePath.getSchemaUrn() != null || attributePath.size() != 1
				|| attributePath.getElement(0).getValueFilter() != null
				|| !attributePath.getElement(0).getAttribute().equalsIgnoreCase("value")
				|| comparison == null || !comparison.isString()) {
			throw invalidFilter();
		}
		try {
			String canonical = UserId.from(comparison.stringValue()).toString();
			return Filter.eq(Path.of("value"), JsonUtils.getJsonNodeFactory().textNode(canonical));
		}
		catch (RuntimeException exception) {
			throw invalidFilter();
		}
	}

	private static JsonNode normalizePathValue(Path path, JsonNode value) throws BadRequestException {
		String attribute = path.getElement(0).getAttribute();
		if (attribute.equals("displayName")) {
			if (!value.isNull() && !value.isString()) {
				throw invalidValue();
			}
			return value;
		}
		if (value.isNull()) {
			return value;
		}
		if (path.getElement(0).getValueFilter() != null) {
			if (!(value instanceof ObjectNode member)) {
				throw invalidValue();
			}
			return canonicalMember(member);
		}
		if (value instanceof ObjectNode member) {
			return JsonUtils.getJsonNodeFactory().arrayNode().add(canonicalMember(member));
		}
		if (!(value instanceof ArrayNode members)) {
			throw invalidValue();
		}
		return canonicalMembers(members);
	}

	private static void validateRootValue(ObjectNode value, OperationType type) throws BadRequestException {
		Set<String> seen = new HashSet<>();
		for (String name : List.copyOf(value.propertyNames())) {
			String normalized = name.toLowerCase(Locale.ROOT);
			if (!seen.add(normalized)) {
				throw invalidSyntax();
			}
			if (READ_ONLY_ATTRIBUTES.contains(normalized)) {
				throw mutability();
			}
			String canonical = canonicalAttribute(name);
			if (canonical == null) {
				throw invalidValue();
			}
			JsonNode attributeValue = value.get(name);
			if (canonical.equals("displayName")) {
				if (attributeValue.isNull()) {
					throw mutability();
				}
				if (!attributeValue.isString()) {
					throw invalidValue();
				}
			}
			else if (attributeValue.isNull() && type == OperationType.ADD) {
				throw invalidValue();
			}
			else if (!attributeValue.isNull()) {
				if (!(attributeValue instanceof ArrayNode members)) {
					throw invalidValue();
				}
				attributeValue = canonicalMembers(members);
			}
			if (!canonical.equals(name)) {
				value.remove(name);
			}
			value.set(canonical, attributeValue);
		}
	}

	private static ArrayNode canonicalMembers(ArrayNode members) throws BadRequestException {
		ArrayNode canonical = JsonUtils.getJsonNodeFactory().arrayNode();
		for (JsonNode member : members) {
			if (!(member instanceof ObjectNode object)) {
				throw invalidValue();
			}
			canonical.add(canonicalMember(object));
		}
		return canonical;
	}

	private static ObjectNode canonicalMember(ObjectNode member) throws BadRequestException {
		ObjectNode canonical = JsonUtils.getJsonNodeFactory().objectNode();
		Set<String> seen = new HashSet<>();
		for (String name : member.propertyNames()) {
			String field = MEMBER_FIELDS.stream().filter(name::equalsIgnoreCase).findFirst().orElse(null);
			if (field == null) {
				throw invalidValue();
			}
			if (!seen.add(field)) {
				throw invalidSyntax();
			}
			canonical.set(field, member.get(name).deepCopy());
		}
		JsonNode value = canonical.get("value");
		if (value != null && value.isString()) {
			try {
				canonical.put("value", UserId.from(value.stringValue()).toString());
			}
			catch (RuntimeException exception) {
				throw invalidValue();
			}
		}
		return canonical;
	}

	private static void validateRemoval(Path path) throws BadRequestException {
		if (path.getElement(0).getAttribute().equals("displayName")) {
			throw mutability();
		}
	}

	private static boolean isUnassigned(Path path, JsonNode value) {
		return value.isNull() || value instanceof ArrayNode array && array.isEmpty()
				&& path.getElement(0).getAttribute().equals("members");
	}

	private static SdkOperation filteredAdd(Path path, JsonNode value) throws BadRequestException {
		if (!(value instanceof ObjectNode member)) {
			throw invalidValue();
		}
		JsonNode memberValue = member.get("value");
		JsonNode selectorValue = path.getElement(0).getValueFilter().getComparisonValue();
		if (memberValue == null || !memberValue.isString() || selectorValue == null || !selectorValue.isString()) {
			throw invalidValue();
		}
		if (!memberValue.stringValue().equals(selectorValue.stringValue())) {
			throw mutability();
		}
		PatchOperation existingTarget = PatchOperation.replace(path, member);
		PatchOperation missingTarget = PatchOperation.add(Path.of("members"),
				JsonUtils.getJsonNodeFactory().arrayNode().add(member.deepCopy()));
		return operation(existingTarget, path, false, missingTarget);
	}

	private static SdkOperation filteredReplace(Path path, JsonNode value) throws BadRequestException {
		if (!(value instanceof ObjectNode member)) {
			throw invalidValue();
		}
		JsonNode memberValue = member.get("value");
		JsonNode selectorValue = path.getElement(0).getValueFilter().getComparisonValue();
		boolean immutableValueMismatch = memberValue != null
				&& (!memberValue.isString() || selectorValue == null || !selectorValue.isString()
						|| !memberValue.stringValue().equals(selectorValue.stringValue()));
		return new SdkOperation(PatchOperation.replace(path, member), path, true, null,
				immutableValueMismatch);
	}

	private static SdkOperation operation(PatchOperation operation, Path path, boolean requireTarget,
			PatchOperation missingTargetOperation) {
		return new SdkOperation(operation, path, requireTarget, missingTargetOperation, false);
	}

	private static String canonicalAttribute(String attribute) {
		return ScimGroupSchema.SUPPORTED_ATTRIBUTES.keySet().stream()
			.filter(attribute::equalsIgnoreCase)
			.findFirst()
			.orElse(null);
	}

	private static void validateRequestComplexity(ObjectNode source) throws BadRequestException {
		ArrayDeque<JsonNode> pending = new ArrayDeque<>();
		pending.add(source);
		int nodes = 0;
		long characters = 0;
		while (!pending.isEmpty()) {
			JsonNode node = pending.removeFirst();
			if (++nodes > MAX_JSON_NODES) {
				throw tooMany();
			}
			for (String name : node.propertyNames()) {
				characters += name.length();
			}
			if (node.isString()) {
				characters += node.stringValue().length();
			}
			if (characters > MAX_TEXT_CHARACTERS) {
				throw tooMany();
			}
			pending.addAll(node.values());
		}
	}

	private static void validateFields(ObjectNode source, Set<String> allowed) throws BadRequestException {
		for (String name : source.propertyNames()) {
			if (allowed.stream().noneMatch(name::equalsIgnoreCase)) {
				throw invalidSyntax();
			}
		}
		for (String name : allowed) {
			field(source, name);
		}
	}

	private static JsonNode field(ObjectNode source, String expected) throws BadRequestException {
		JsonNode value = null;
		for (String name : source.propertyNames()) {
			if (name.equalsIgnoreCase(expected)) {
				if (value != null) {
					throw invalidSyntax();
				}
				value = source.get(name);
			}
		}
		return value;
	}

	private static BadRequestException safe(BadRequestException exception) {
		String type = exception.getScimError().getScimType();
		return switch (type == null ? "" : type) {
			case BadRequestException.INVALID_FILTER -> invalidFilter();
			case BadRequestException.MUTABILITY -> mutability();
			case BadRequestException.INVALID_PATH -> invalidPath();
			case BadRequestException.NO_TARGET -> BadRequestException.noTarget(NO_TARGET_DETAIL);
			case BadRequestException.INVALID_SYNTAX -> invalidSyntax();
			default -> invalidValue();
		};
	}

	private static BadRequestException invalidSyntax() {
		return BadRequestException.invalidSyntax(INVALID_SYNTAX_DETAIL);
	}

	private static BadRequestException invalidPath() {
		return BadRequestException.invalidPath(INVALID_PATH_DETAIL);
	}

	private static BadRequestException invalidFilter() {
		return BadRequestException.invalidFilter(INVALID_FILTER_DETAIL);
	}

	private static BadRequestException invalidValue() {
		return BadRequestException.invalidValue(INVALID_VALUE_DETAIL);
	}

	private static BadRequestException mutability() {
		return BadRequestException.mutability(MUTABILITY_DETAIL);
	}

	private static BadRequestException tooMany() {
		return BadRequestException.tooMany(TOO_MANY_DETAIL);
	}

	private record SdkOperation(PatchOperation operation, Path path, boolean requireTarget,
			PatchOperation missingTargetOperation, boolean immutableValueMismatch) {
	}

	private enum OperationType {

		ADD,

		REMOVE,

		REPLACE
	}

}
