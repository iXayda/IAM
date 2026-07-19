package com.ixayda.iam.scim.internal;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import com.ixayda.iam.user.LoginIdentifier;
import com.ixayda.iam.user.LoginIdentifierType;
import com.ixayda.iam.user.ReplaceUserRequest;
import com.ixayda.iam.user.User;
import com.unboundid.scim2.common.Path;
import com.unboundid.scim2.common.exceptions.BadRequestException;
import com.unboundid.scim2.common.exceptions.ScimException;
import com.unboundid.scim2.common.filters.Filter;
import com.unboundid.scim2.common.messages.PatchOperation;
import com.unboundid.scim2.common.utils.JsonUtils;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

final class ScimUserPatchRequest {

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

	private static final int MAX_FILTER_NODES = 64;

	private static final int MAX_FILTER_DEPTH = 16;

	private static final Set<String> READ_ONLY_ATTRIBUTES = Set.of("schemas", "id", "meta", "groups");

	private static final Set<String> TOP_LEVEL_FIELDS = Set.of("schemas", "operations");

	private static final Set<String> OPERATION_FIELDS = Set.of("op", "path", "value");

	private final List<ParsedOperation> operations;

	private final Set<String> touchedAttributes;

	private ScimUserPatchRequest(List<ParsedOperation> operations, Set<String> touchedAttributes) {
		this.operations = List.copyOf(operations);
		this.touchedAttributes = Set.copyOf(touchedAttributes);
	}

	static ScimUserPatchRequest parse(ObjectNode source) throws BadRequestException {
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
		List<ParsedOperation> operations = new ArrayList<>(operationValues.size());
		Set<String> touchedAttributes = new LinkedHashSet<>();
		for (JsonNode operationValue : operationValues) {
			if (!(operationValue instanceof ObjectNode operation)) {
				throw invalidSyntax();
			}
			operations.add(parseOperation(operation, touchedAttributes));
		}
		return new ScimUserPatchRequest(operations, touchedAttributes);
	}

	ReplaceUserRequest apply(User current, ScimUserMapper mapper, ScimJsonCodec codec) throws BadRequestException {
		ObjectNode writable = codec.jsonMapper().valueToTree(mapper.mapWritable(current));
		try {
			for (ParsedOperation operation : this.operations) {
				AliasState before = AliasState.from(writable);
				for (SdkOperation sdkOperation : operation.operations()) {
					boolean targetExists = sdkOperation.path() != null
							&& JsonUtils.pathExists(sdkOperation.path(), writable);
					if (sdkOperation.requireTarget() && !targetExists) {
						throw BadRequestException.noTarget(NO_TARGET_DETAIL);
					}
					PatchOperation actual = sdkOperation.missingTargetOperation() != null && !targetExists
							? sdkOperation.missingTargetOperation()
							: sdkOperation.missingParentOperation() != null
							&& isMissingComplexParent(sdkOperation.path(), writable)
								? sdkOperation.missingParentOperation() : sdkOperation.operation();
					actual.apply(writable);
				}
				reconcileAliases(writable, before, operation.touchedAttributes());
				ScimUserCreateRequest.parse(writable, codec);
			}
		}
		catch (BadRequestException exception) {
			throw safe(exception);
		}
		catch (ScimException | RuntimeException exception) {
			throw invalidValue();
		}
		validateAliasInvariant(writable);
		ReplaceUserRequest replacement = ScimUserCreateRequest.parse(writable, codec).replacement();
		validatePrimaryRoundTrip(writable, replacement);
		return preserveUntouchedIdentifiers(current, replacement);
	}

	private static ParsedOperation parseOperation(ObjectNode source, Set<String> touchedAttributes)
			throws BadRequestException {
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
		Set<String> operationAttributes = new LinkedHashSet<>();
		if (pathNode != null) {
			if (!pathNode.isString() || pathNode.stringValue().isBlank()) {
				throw invalidPath();
			}
			if (pathNode.stringValue().length() > MAX_PATH_CHARACTERS) {
				throw tooMany();
			}
			try {
				path = Path.fromString(pathNode.stringValue());
			}
			catch (BadRequestException exception) {
				throw safe(exception);
			}
			validatePath(path, type);
			path = normalizePath(path);
			operationAttributes.add(path.getElement(0).getAttribute().toLowerCase(Locale.ROOT));
		}

		JsonNode value = field(source, "value");
		if (type == OperationType.REMOVE) {
			if (path == null) {
				throw BadRequestException.noTarget(NO_TARGET_DETAIL);
			}
			if (value != null) {
				throw invalidSyntax();
			}
		}
		else {
			if (value == null) {
				throw invalidSyntax();
			}
			if (path == null) {
				if (!(value instanceof ObjectNode objectValue) || objectValue.isEmpty()) {
					throw invalidSyntax();
				}
				validateRootValue(objectValue);
				objectValue.propertyNames().stream()
					.map((name) -> name.toLowerCase(Locale.ROOT))
					.forEach(operationAttributes::add);
			}
			else {
				value = normalizePathValue(path, value);
			}
		}
		touchedAttributes.addAll(operationAttributes);

		try {
			List<SdkOperation> sdkOperations;
			if (type == OperationType.REMOVE) {
				path = normalizeRemovalPath(path);
				sdkOperations = List.of(SdkOperation.apply(PatchOperation.remove(path), path));
			}
			else if (path == null) {
				sdkOperations = type == OperationType.ADD ? pathlessAddOperations((ObjectNode) value)
						: List.of(SdkOperation.apply(PatchOperation.replace((ObjectNode) value), null));
			}
			else if (isUnassigned(path, value)) {
				validatePath(path, OperationType.REMOVE);
				Path removalPath = normalizeRemovalPath(path);
				boolean requireTarget = type == OperationType.REPLACE
						&& removalPath.getElement(0).getValueFilter() != null;
				sdkOperations = List.of(
						new SdkOperation(PatchOperation.remove(removalPath), removalPath, requireTarget, null, null));
			}
			else {
				if (type == OperationType.ADD && path.getElement(0).getValueFilter() != null) {
					sdkOperations = List.of(filteredAddOperation(path, value));
				}
				else {
					PatchOperation sdkOperation = type == OperationType.ADD ? PatchOperation.add(path, value)
							: PatchOperation.replace(path, value);
					sdkOperations = List.of(new SdkOperation(sdkOperation, path, false,
							missingComplexParentOperation(path, value), null));
				}
			}
			return new ParsedOperation(sdkOperations, operationAttributes);
		}
		catch (BadRequestException exception) {
			throw safe(exception);
		}
		catch (RuntimeException exception) {
			throw invalidValue();
		}
	}

	private static List<SdkOperation> pathlessAddOperations(ObjectNode value) throws BadRequestException {
		ObjectNode additions = value.deepCopy();
		List<SdkOperation> removals = new ArrayList<>();
		for (String attribute : List.copyOf(additions.propertyNames())) {
			JsonNode attributeValue = additions.get(attribute);
			Path attributePath = Path.of(attribute);
			if (isUnassigned(attributePath, attributeValue)) {
				validatePath(attributePath, OperationType.REMOVE);
				additions.remove(attribute);
				removals.add(SdkOperation.apply(PatchOperation.remove(attributePath), attributePath));
				continue;
			}
			if (attribute.equals("name") && attributeValue instanceof ObjectNode name) {
				for (String subAttribute : List.copyOf(name.propertyNames())) {
					if (name.get(subAttribute).isNull()) {
						Path subPath = attributePath.attribute(subAttribute);
						name.remove(subAttribute);
						removals.add(SdkOperation.apply(PatchOperation.remove(subPath), subPath));
					}
				}
				if (name.isEmpty()) {
					additions.remove(attribute);
				}
			}
		}
		List<SdkOperation> operations = new ArrayList<>(removals.size() + 1);
		if (!additions.isEmpty()) {
			operations.add(SdkOperation.apply(PatchOperation.add(additions), null));
		}
		operations.addAll(removals);
		return List.copyOf(operations);
	}

	private static JsonNode normalizePathValue(Path path, JsonNode value) throws BadRequestException {
		String attribute = path.getElement(0).getAttribute();
		if (value instanceof ArrayNode array && array.isEmpty() && !isMultiValuedRoot(path)) {
			throw invalidValue();
		}
		if (path.size() == 2 && path.getElement(1).getAttribute().equals("value")
				&& isMultiValuedRoot(path.subPath(1)) && value.isString()) {
			return JsonUtils.getJsonNodeFactory().textNode(
					canonicalIdentifierValue(attribute, value.stringValue()));
		}
		if (path.size() == 1 && !isUnassigned(path, value)) {
			normalizeAttributeValue(attribute, value);
			if ((attribute.equals("emails") || attribute.equals("phoneNumbers"))
					&& path.getElement(0).getValueFilter() == null && value instanceof ObjectNode objectValue) {
				return JsonUtils.getJsonNodeFactory().arrayNode().add(objectValue);
			}
		}
		return value;
	}

	private static Path normalizeRemovalPath(Path path) {
		if (path.size() == 2 && path.getElement(1).getAttribute().equals("value")
				&& (path.getElement(0).getAttribute().equals("emails")
						|| path.getElement(0).getAttribute().equals("phoneNumbers"))) {
			return Path.root().attribute(path.getElement(0).getAttribute(), path.getElement(0).getValueFilter());
		}
		return path;
	}

	private static PatchOperation missingComplexParentOperation(Path path, JsonNode value) {
		if (path.size() != 2 || path.getElement(0).getValueFilter() != null
				|| !path.getElement(1).getAttribute().equals("value") || !isMultiValuedRoot(path.subPath(1))) {
			return null;
		}
		ObjectNode item = JsonUtils.getJsonNodeFactory().objectNode();
		item.set("value", value);
		return PatchOperation.add(path.subPath(1), JsonUtils.getJsonNodeFactory().arrayNode().add(item));
	}

	private static SdkOperation filteredAddOperation(Path path, JsonNode value) throws BadRequestException {
		PatchOperation existingTarget = PatchOperation.replace(path, value);
		ObjectNode item;
		if (path.size() == 1) {
			if (!(value instanceof ObjectNode objectValue)) {
				throw invalidValue();
			}
			item = objectValue.deepCopy();
		}
		else {
			item = JsonUtils.getJsonNodeFactory().objectNode();
			item.set(path.getElement(1).getAttribute(), value);
		}
		Path rootPath = Path.of(path.getElement(0).getAttribute());
		PatchOperation missingTarget = PatchOperation.add(rootPath,
				JsonUtils.getJsonNodeFactory().arrayNode().add(item));
		return new SdkOperation(existingTarget, path, false, null, missingTarget);
	}

	private static boolean isMissingComplexParent(Path path, ObjectNode writable) {
		JsonNode parent = writable.get(path.getElement(0).getAttribute());
		return parent == null || parent.isNull() || parent instanceof ArrayNode array && array.isEmpty();
	}

	private static boolean isUnassigned(Path path, JsonNode value) {
		return value.isNull() || value instanceof ArrayNode array && array.isEmpty() && isMultiValuedRoot(path);
	}

	private static boolean isMultiValuedRoot(Path path) {
		return path.size() == 1 && (path.getElement(0).getAttribute().equals("emails")
				|| path.getElement(0).getAttribute().equals("phoneNumbers"));
	}

	private static void reconcileAliases(ObjectNode writable, AliasState before, Set<String> touchedAttributes)
			throws BadRequestException {
		boolean userNameTouched = touchedAttributes.contains("username");
		if (!userNameTouched && before.linkedAttribute() != null
				&& touchedAttributes.contains(before.linkedAttribute().toLowerCase(Locale.ROOT))) {
			LoginIdentifier alias = singleAlias(writable, before.primary().type(), before.linkedAttribute());
			if (alias != null) {
				writable.put("userName", alias.value());
			}
		}

		if (!userNameTouched) {
			return;
		}
		LoginIdentifier primary = primaryIdentifier(writable);
		String linkedAttribute = linkedAttribute(primary.type());
		if (linkedAttribute == null) {
			return;
		}
		if (touchedAttributes.contains(linkedAttribute.toLowerCase(Locale.ROOT))) {
			LoginIdentifier alias = singleAlias(writable, primary.type(), linkedAttribute);
			if (alias == null || !alias.canonicalValue().equals(primary.canonicalValue())) {
				throw invalidValue();
			}
			return;
		}
		ensureAlias(writable, primary, linkedAttribute, before);
	}

	private static void validateAliasInvariant(ObjectNode writable) throws BadRequestException {
		LoginIdentifier primary = primaryIdentifier(writable);
		String attribute = linkedAttribute(primary.type());
		if (attribute == null) {
			return;
		}
		LoginIdentifier alias = singleAlias(writable, primary.type(), attribute);
		if (alias == null || !alias.canonicalValue().equals(primary.canonicalValue())) {
			throw invalidValue();
		}
	}

	private static void validatePrimaryRoundTrip(ObjectNode writable, ReplaceUserRequest replacement)
			throws BadRequestException {
		LoginIdentifier requested = primaryIdentifier(writable);
		LoginIdentifier persisted = replacement.identifiers().getFirst();
		if (requested.type() != persisted.type()
				|| !requested.canonicalValue().equals(persisted.canonicalValue())) {
			throw invalidValue();
		}
	}

	private static LoginIdentifier primaryIdentifier(ObjectNode writable) throws BadRequestException {
		JsonNode userName = writable.get("userName");
		if (userName == null || !userName.isString()) {
			throw invalidValue();
		}
		try {
			return ScimUserCreateRequest.primaryIdentifier(userName.stringValue());
		}
		catch (RuntimeException exception) {
			throw invalidValue();
		}
	}

	private static LoginIdentifier singleAlias(ObjectNode writable, LoginIdentifierType type, String attribute)
			throws BadRequestException {
		JsonNode values = writable.get(attribute);
		if (!(values instanceof ArrayNode array) || array.size() != 1
				|| !(array.get(0) instanceof ObjectNode objectValue)) {
			return null;
		}
		JsonNode value = objectValue.get("value");
		if (value == null || !value.isString()) {
			return null;
		}
		try {
			return switch (type) {
				case EMAIL -> LoginIdentifier.email(value.stringValue());
				case PHONE -> LoginIdentifier.phone(ScimUserCreateRequest.telephoneValue(value.stringValue()));
				case USERNAME -> null;
			};
		}
		catch (RuntimeException exception) {
			throw invalidValue();
		}
	}

	private static void ensureAlias(ObjectNode writable, LoginIdentifier primary, String attribute, AliasState before)
			throws BadRequestException {
		LoginIdentifier existing = singleAlias(writable, primary.type(), attribute);
		if (existing != null) {
			if (existing.canonicalValue().equals(primary.canonicalValue())) {
				return;
			}
			if (!attribute.equals(before.linkedAttribute()) || before.primary().type() != primary.type()
					|| !existing.canonicalValue().equals(before.primary().canonicalValue())) {
				throw invalidValue();
			}
		}
		else if (writable.has(attribute) && !writable.path(attribute).isNull()
				&& !(writable.path(attribute) instanceof ArrayNode array && array.isEmpty())) {
			throw invalidValue();
		}
		String value = primary.type() == LoginIdentifierType.PHONE ? "tel:+" + primary.canonicalValue()
				: primary.canonicalValue();
		ObjectNode item = JsonUtils.getJsonNodeFactory().objectNode().put("value", value);
		writable.set(attribute, JsonUtils.getJsonNodeFactory().arrayNode().add(item));
	}

	private static String linkedAttribute(LoginIdentifierType type) {
		return switch (type) {
			case EMAIL -> "emails";
			case PHONE -> "phoneNumbers";
			case USERNAME -> null;
		};
	}

	private ReplaceUserRequest preserveUntouchedIdentifiers(User current, ReplaceUserRequest replacement)
			throws BadRequestException {
		List<LoginIdentifier> identifiers = new ArrayList<>(replacement.identifiers());
		LoginIdentifier primary = current.identifiers().getFirst();
		for (LoginIdentifier existing : current.identifiers()) {
			int index = indexOfType(identifiers, existing.type());
			if (index >= 0 && identifiers.get(index).canonicalValue().equals(existing.canonicalValue())) {
				identifiers.set(index, existing);
				continue;
			}
			if (!identifierTouched(existing.type(), existing.equals(primary))) {
				throw invalidValue();
			}
		}
		return new ReplaceUserRequest(identifiers, replacement.profile(), replacement.active());
	}

	private boolean identifierTouched(LoginIdentifierType type, boolean primary) {
		return switch (type) {
			case USERNAME -> this.touchedAttributes.contains("username");
			case EMAIL -> this.touchedAttributes.contains("emails")
					|| primary && this.touchedAttributes.contains("username");
			case PHONE -> this.touchedAttributes.contains("phonenumbers")
					|| primary && this.touchedAttributes.contains("username");
		};
	}

	private static int indexOfType(List<LoginIdentifier> identifiers, LoginIdentifierType type) {
		for (int index = 0; index < identifiers.size(); index++) {
			if (identifiers.get(index).type() == type) {
				return index;
			}
		}
		return -1;
	}

	private static void validatePath(Path path, OperationType type) throws BadRequestException {
		if (path.isRoot() || path.size() > 2
				|| path.getSchemaUrn() != null && !ScimUserSchema.URN.equals(path.getSchemaUrn())) {
			throw invalidPath();
		}
		String attribute = path.getElement(0).getAttribute();
		String normalizedAttribute = attribute.toLowerCase(Locale.ROOT);
		if (READ_ONLY_ATTRIBUTES.contains(normalizedAttribute)) {
			throw mutability();
		}
		Set<String> subAttributes = supportedSubAttributes(attribute);
		if (subAttributes == null) {
			throw invalidPath();
		}
		if (type == OperationType.REMOVE && (normalizedAttribute.equals("username")
				|| normalizedAttribute.equals("active")) && path.size() == 1) {
			throw mutability();
		}

		Filter filter = path.getElement(0).getValueFilter();
		if (filter != null) {
			if (!(normalizedAttribute.equals("emails") || normalizedAttribute.equals("phonenumbers"))
					|| !filterUsesOnlyValue(filter)) {
				throw invalidFilter();
			}
		}
		if (path.size() == 2) {
			if (path.getElement(1).getValueFilter() != null
					|| subAttributes.stream().noneMatch(path.getElement(1).getAttribute()::equalsIgnoreCase)) {
				throw invalidPath();
			}
		}
	}

	private static void validateRootValue(ObjectNode value) throws BadRequestException {
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
			Path attributePath = Path.of(canonical);
			if (attributeValue instanceof ArrayNode array && array.isEmpty() && !isMultiValuedRoot(attributePath)) {
				throw invalidValue();
			}
			if ((normalized.equals("username") || normalized.equals("active"))
					&& isUnassigned(attributePath, attributeValue)) {
				throw mutability();
			}
			normalizeAttributeValue(canonical, value.get(name));
			if (!canonical.equals(name)) {
				value.set(canonical, value.remove(name));
			}
		}
	}

	private static Path normalizePath(Path path) {
		Path normalized = Path.root();
		for (Path.Element element : path) {
			String canonical = canonicalAttribute(element.getAttribute());
			if (canonical == null && normalized.size() > 0) {
				Set<String> subAttributes = supportedSubAttributes(normalized.getElement(0).getAttribute());
				canonical = subAttributes.stream()
					.filter(element.getAttribute()::equalsIgnoreCase)
					.findFirst()
					.orElse(element.getAttribute());
			}
			Filter filter = element.getValueFilter() == null ? null : normalizeFilter(element.getValueFilter());
			normalized = normalized.attribute(canonical == null ? element.getAttribute() : canonical, filter);
		}
		return normalized;
	}

	private static Filter normalizeFilter(Filter filter) {
		return switch (filter.getFilterType()) {
			case AND -> Filter.and(filter.getCombinedFilters().stream().map(ScimUserPatchRequest::normalizeFilter).toList());
			case OR -> Filter.or(filter.getCombinedFilters().stream().map(ScimUserPatchRequest::normalizeFilter).toList());
			case NOT -> Filter.not(normalizeFilter(filter.getInvertedFilter()));
			case EQUAL -> Filter.eq(Path.of("value"), filter.getComparisonValue());
			case NOT_EQUAL -> Filter.ne(Path.of("value"), filter.getComparisonValue());
			case CONTAINS -> Filter.co(Path.of("value"), filter.getComparisonValue());
			case STARTS_WITH -> Filter.sw(Path.of("value"), filter.getComparisonValue());
			case ENDS_WITH -> Filter.ew(Path.of("value"), filter.getComparisonValue());
			case PRESENT -> Filter.pr(Path.of("value"));
			case GREATER_THAN -> Filter.gt(Path.of("value"), filter.getComparisonValue());
			case GREATER_OR_EQUAL -> Filter.ge(Path.of("value"), filter.getComparisonValue());
			case LESS_THAN -> Filter.lt(Path.of("value"), filter.getComparisonValue());
			case LESS_OR_EQUAL -> Filter.le(Path.of("value"), filter.getComparisonValue());
			case COMPLEX_VALUE -> throw new IllegalArgumentException("Complex value filters are not supported");
		};
	}

	private static void normalizeAttributeValue(String attribute, JsonNode value) throws BadRequestException {
		if (attribute.equals("name") && value instanceof ObjectNode objectValue) {
			normalizeObjectFields(objectValue, ScimUserSchema.SUPPORTED_ATTRIBUTES.get(attribute));
		}
		if ((attribute.equals("emails") || attribute.equals("phoneNumbers")) && value instanceof ObjectNode objectValue) {
			normalizeObjectFields(objectValue, ScimUserSchema.SUPPORTED_ATTRIBUTES.get(attribute));
			normalizeIdentifierObject(attribute, objectValue);
		}
		if ((attribute.equals("emails") || attribute.equals("phoneNumbers")) && value instanceof ArrayNode values) {
			for (JsonNode item : values) {
				if (item instanceof ObjectNode objectValue) {
					normalizeObjectFields(objectValue, ScimUserSchema.SUPPORTED_ATTRIBUTES.get(attribute));
					normalizeIdentifierObject(attribute, objectValue);
				}
			}
		}
	}

	private static void normalizeIdentifierObject(String attribute, ObjectNode value) throws BadRequestException {
		JsonNode identifierValue = value.get("value");
		if (identifierValue != null && identifierValue.isString()) {
			value.put("value", canonicalIdentifierValue(attribute, identifierValue.stringValue()));
		}
	}

	private static String canonicalIdentifierValue(String attribute, String value) throws BadRequestException {
		try {
			return attribute.equals("emails") ? LoginIdentifier.email(value).canonicalValue()
					: "tel:+" + LoginIdentifier.phone(ScimUserCreateRequest.telephoneValue(value)).canonicalValue();
		}
		catch (RuntimeException exception) {
			throw invalidValue();
		}
	}

	private static void normalizeObjectFields(ObjectNode value, Set<String> supported) throws BadRequestException {
		Set<String> seen = new HashSet<>();
		for (String name : List.copyOf(value.propertyNames())) {
			String normalized = name.toLowerCase(Locale.ROOT);
			if (!seen.add(normalized)) {
				throw invalidSyntax();
			}
			String canonical = supported.stream().filter(name::equalsIgnoreCase).findFirst().orElse(null);
			if (canonical == null) {
				throw invalidValue();
			}
			JsonNode fieldValue = value.get(name);
			if (fieldValue instanceof ArrayNode array && array.isEmpty()) {
				throw invalidValue();
			}
			if (!canonical.equals(name)) {
				value.set(canonical, value.remove(name));
			}
		}
	}

	private static boolean filterUsesOnlyValue(Filter filter) {
		ArrayDeque<FilterNode> pending = new ArrayDeque<>();
		pending.add(new FilterNode(filter, 1));
		int nodes = 0;
		while (!pending.isEmpty()) {
			FilterNode candidate = pending.removeFirst();
			if (++nodes > MAX_FILTER_NODES || candidate.depth() > MAX_FILTER_DEPTH) {
				return false;
			}
			Filter current = candidate.filter();
			if (current.isCombiningFilter()) {
				current.getCombinedFilters()
					.forEach((child) -> pending.addLast(new FilterNode(child, candidate.depth() + 1)));
				continue;
			}
			if (current.isNotFilter()) {
				pending.addLast(new FilterNode(current.getInvertedFilter(), candidate.depth() + 1));
				continue;
			}
			if (current.isComplexValueFilter()) {
				return false;
			}
			Path attributePath = current.getAttributePath();
			if (attributePath == null || attributePath.getSchemaUrn() != null || attributePath.size() != 1
					|| attributePath.getElement(0).getValueFilter() != null
					|| !attributePath.getElement(0).getAttribute().equalsIgnoreCase("value")) {
				return false;
			}
		}
		return true;
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

	private static String canonicalAttribute(String attribute) {
		return ScimUserSchema.SUPPORTED_ATTRIBUTES.keySet().stream()
			.filter(attribute::equalsIgnoreCase)
			.findFirst()
			.orElse(null);
	}

	private static Set<String> supportedSubAttributes(String attribute) {
		return ScimUserSchema.SUPPORTED_ATTRIBUTES.entrySet().stream()
			.filter((entry) -> entry.getKey().equalsIgnoreCase(attribute))
			.map(java.util.Map.Entry::getValue)
			.findFirst()
			.orElse(null);
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

	private record FilterNode(Filter filter, int depth) {
	}

	private record ParsedOperation(List<SdkOperation> operations, Set<String> touchedAttributes) {

		private ParsedOperation {
			operations = List.copyOf(operations);
			touchedAttributes = Set.copyOf(touchedAttributes);
		}

	}

	private record SdkOperation(PatchOperation operation, Path path, boolean requireTarget,
			PatchOperation missingParentOperation, PatchOperation missingTargetOperation) {

		private static SdkOperation apply(PatchOperation operation, Path path) {
			return new SdkOperation(operation, path, false, null, null);
		}

	}

	private record AliasState(LoginIdentifier primary, String linkedAttribute) {

		private static AliasState from(ObjectNode writable) throws BadRequestException {
			LoginIdentifier primary = primaryIdentifier(writable);
			String attribute = ScimUserPatchRequest.linkedAttribute(primary.type());
			if (attribute == null) {
				return new AliasState(primary, null);
			}
			LoginIdentifier alias = singleAlias(writable, primary.type(), attribute);
			return new AliasState(primary,
					alias != null && alias.canonicalValue().equals(primary.canonicalValue()) ? attribute : null);
		}

	}

	private enum OperationType {

		ADD,

		REMOVE,

		REPLACE

	}

}
