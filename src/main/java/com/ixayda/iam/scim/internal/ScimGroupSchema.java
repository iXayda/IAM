package com.ixayda.iam.scim.internal;

import java.beans.IntrospectionException;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Stream;

import com.unboundid.scim2.common.types.AttributeDefinition;
import com.unboundid.scim2.common.types.GroupResource;
import com.unboundid.scim2.common.types.SchemaResource;
import com.unboundid.scim2.common.utils.SchemaUtils;

final class ScimGroupSchema {

	static final String URN = "urn:ietf:params:scim:schemas:core:2.0:Group";

	static final Map<String, Set<String>> SUPPORTED_ATTRIBUTES = Map.of(
			"displayName", Set.of(),
			"members", Set.of("value", "type", "$ref"));

	private static final List<AttributeDefinition> ATTRIBUTE_DEFINITIONS = Stream
		.concat(SchemaUtils.COMMON_ATTRIBUTE_DEFINITIONS.stream(), create().getAttributes().stream())
		.toList();

	private ScimGroupSchema() {
	}

	static SchemaResource create() {
		try {
			SchemaResource schema = Objects.requireNonNull(SchemaUtils.getSchema(GroupResource.class),
					"SCIM Group schema must be available");
			List<AttributeDefinition> attributes = schema.getAttributes().stream()
				.filter((attribute) -> SUPPORTED_ATTRIBUTES.containsKey(attribute.getName()))
				.map((attribute) -> ScimUserSchema.withSupportedSubAttributes(attribute,
						SUPPORTED_ATTRIBUTES.get(attribute.getName()), false))
				.map(ScimGroupSchema::withDirectUserMembers)
				.toList();
			return new SchemaResource(schema.getId(), schema.getName(), schema.getDescription(), attributes);
		}
		catch (IntrospectionException exception) {
			throw new IllegalStateException("Unable to generate the SCIM Group schema", exception);
		}
	}

	static List<AttributeDefinition> attributeDefinitions() {
		return ATTRIBUTE_DEFINITIONS;
	}

	private static AttributeDefinition withDirectUserMembers(AttributeDefinition definition) {
		if (!definition.getName().equals("members")) {
			return definition;
		}
		Collection<AttributeDefinition> subAttributes = definition.getSubAttributes();
		List<AttributeDefinition> directUserSubAttributes = subAttributes == null ? List.of()
				: subAttributes.stream().map(ScimGroupSchema::withDirectUserReference).toList();
		return copy(definition, directUserSubAttributes, definition.getCanonicalValues(), definition.getReferenceTypes());
	}

	private static AttributeDefinition withDirectUserReference(AttributeDefinition definition) {
		Collection<String> canonicalValues = definition.getName().equals("type") ? List.of("User")
				: definition.getCanonicalValues();
		Collection<String> referenceTypes = definition.getName().equals("$ref") ? List.of("User")
				: definition.getReferenceTypes();
		return copy(definition, definition.getSubAttributes(), canonicalValues, referenceTypes);
	}

	private static AttributeDefinition copy(AttributeDefinition definition,
			Collection<AttributeDefinition> subAttributes, Collection<String> canonicalValues,
			Collection<String> referenceTypes) {
		AttributeDefinition.Builder builder = new AttributeDefinition.Builder()
			.setName(definition.getName())
			.setType(definition.getType())
			.setMultiValued(definition.isMultiValued())
			.setDescription(definition.getDescription())
			.setRequired(definition.isRequired())
			.setCaseExact(definition.isCaseExact())
			.setMutability(definition.getMutability())
			.setReturned(definition.getReturned())
			.setUniqueness(definition.getUniqueness());
		if (subAttributes != null) {
			builder.addSubAttributes(subAttributes.toArray(AttributeDefinition[]::new));
		}
		if (canonicalValues != null) {
			builder.addCanonicalValues(canonicalValues.toArray(String[]::new));
		}
		if (referenceTypes != null) {
			builder.addReferenceTypes(referenceTypes.toArray(String[]::new));
		}
		return builder.build();
	}

}
