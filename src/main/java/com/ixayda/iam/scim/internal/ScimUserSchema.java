package com.ixayda.iam.scim.internal;

import java.beans.IntrospectionException;
import java.util.List;
import java.util.Objects;
import java.util.stream.Stream;

import com.unboundid.scim2.common.types.AttributeDefinition;
import com.unboundid.scim2.common.types.SchemaResource;
import com.unboundid.scim2.common.types.UserResource;
import com.unboundid.scim2.common.utils.SchemaUtils;

final class ScimUserSchema {

	static final String URN = SchemaUtils.getSchemaUrn(UserResource.class);

	private static final List<AttributeDefinition> ATTRIBUTE_DEFINITIONS = Stream
		.concat(SchemaUtils.COMMON_ATTRIBUTE_DEFINITIONS.stream(), create().getAttributes().stream())
		.toList();

	private ScimUserSchema() {
	}

	static SchemaResource create() {
		try {
			return Objects.requireNonNull(SchemaUtils.getSchema(UserResource.class), "SCIM User schema must be available");
		}
		catch (IntrospectionException exception) {
			throw new IllegalStateException("Unable to generate the SCIM User schema", exception);
		}
	}

	static List<AttributeDefinition> attributeDefinitions() {
		return ATTRIBUTE_DEFINITIONS;
	}

}
