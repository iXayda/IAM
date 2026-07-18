package com.ixayda.iam.scim.internal;

import java.beans.IntrospectionException;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Stream;

import com.unboundid.scim2.common.types.AttributeDefinition;
import com.unboundid.scim2.common.types.SchemaResource;
import com.unboundid.scim2.common.types.UserResource;
import com.unboundid.scim2.common.utils.SchemaUtils;

final class ScimUserSchema {

	static final String URN = "urn:ietf:params:scim:schemas:core:2.0:User";

	private static final Map<String, Set<String>> SUPPORTED_ATTRIBUTES = Map.of(
			"userName", Set.of(),
			"name", Set.of("formatted", "givenName", "familyName"),
			"displayName", Set.of(),
			"active", Set.of(),
			"emails", Set.of("value"),
			"phoneNumbers", Set.of("value"));

	private static final List<AttributeDefinition> ATTRIBUTE_DEFINITIONS = Stream
		.concat(SchemaUtils.COMMON_ATTRIBUTE_DEFINITIONS.stream(), create().getAttributes().stream())
		.toList();

	private ScimUserSchema() {
	}

	static SchemaResource create() {
		try {
			SchemaResource schema = Objects.requireNonNull(SchemaUtils.getSchema(UserResource.class),
					"SCIM User schema must be available");
			List<AttributeDefinition> attributes = schema.getAttributes().stream()
				.filter((attribute) -> SUPPORTED_ATTRIBUTES.containsKey(attribute.getName()))
				.map((attribute) -> withSupportedSubAttributes(attribute,
						SUPPORTED_ATTRIBUTES.get(attribute.getName())))
				.toList();
			return new SchemaResource(schema.getId(), schema.getName(), schema.getDescription(), attributes);
		}
		catch (IntrospectionException exception) {
			throw new IllegalStateException("Unable to generate the SCIM User schema", exception);
		}
	}

	static List<AttributeDefinition> attributeDefinitions() {
		return ATTRIBUTE_DEFINITIONS;
	}

	private static AttributeDefinition withSupportedSubAttributes(AttributeDefinition definition,
			Set<String> supportedSubAttributes) {
		Collection<AttributeDefinition> subAttributes = definition.getSubAttributes();
		if (subAttributes == null) {
			return definition;
		}
		AttributeDefinition[] selected = subAttributes.stream()
			.filter((subAttribute) -> supportedSubAttributes.contains(subAttribute.getName()))
			.toArray(AttributeDefinition[]::new);
		AttributeDefinition.Builder builder = new AttributeDefinition.Builder()
			.setName(definition.getName())
			.setType(definition.getType())
			.addSubAttributes(selected)
			.setMultiValued(definition.isMultiValued())
			.setDescription(definition.getDescription())
			.setRequired(definition.isRequired())
			.setCaseExact(definition.isCaseExact())
			.setMutability(definition.getMutability())
			.setReturned(definition.getReturned())
			.setUniqueness(definition.getUniqueness());
		if (definition.getCanonicalValues() != null) {
			builder.addCanonicalValues(definition.getCanonicalValues().toArray(String[]::new));
		}
		if (definition.getReferenceTypes() != null) {
			builder.addReferenceTypes(definition.getReferenceTypes().toArray(String[]::new));
		}
		return builder.build();
	}

}
