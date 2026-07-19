package com.ixayda.iam.scim.internal;

import java.net.URI;
import java.util.List;

import com.unboundid.scim2.common.exceptions.ForbiddenException;
import com.unboundid.scim2.common.exceptions.ResourceNotFoundException;
import com.unboundid.scim2.common.messages.ListResponse;
import com.unboundid.scim2.common.types.AuthenticationScheme;
import com.unboundid.scim2.common.types.BulkConfig;
import com.unboundid.scim2.common.types.ChangePasswordConfig;
import com.unboundid.scim2.common.types.ETagConfig;
import com.unboundid.scim2.common.types.FilterConfig;
import com.unboundid.scim2.common.types.Meta;
import com.unboundid.scim2.common.types.PatchConfig;
import com.unboundid.scim2.common.types.ResourceTypeResource;
import com.unboundid.scim2.common.types.SchemaResource;
import com.unboundid.scim2.common.types.ServiceProviderConfigResource;
import com.unboundid.scim2.common.types.SortConfig;
import org.springframework.stereotype.Component;

@Component
final class ScimMetadataCatalog {

	private static final List<AuthenticationScheme> AUTHENTICATION_SCHEMES = List.of(new AuthenticationScheme(
			"OAuth 2.0 Bearer Token", "OAuth 2.0 bearer tokens scoped to a tenant and the SCIM resource server.",
			URI.create("https://www.rfc-editor.org/rfc/rfc6750"), null, "oauthbearertoken", true));

	private final List<SchemaResource> schemas;

	private final List<ResourceTypeResource> resourceTypes;

	ScimMetadataCatalog(ScimProperties properties) {
		SchemaResource userSchema = ScimUserSchema.create();
		userSchema.setMeta(metadata("Schema", properties.endpoint(ScimMetadataController.SCHEMAS_PATH,
				ScimUserSchema.URN)));
		SchemaResource groupSchema = ScimGroupSchema.create();
		groupSchema.setMeta(metadata("Schema", properties.endpoint(ScimMetadataController.SCHEMAS_PATH,
				ScimGroupSchema.URN)));
		ResourceTypeResource userResourceType = new ResourceTypeResource("User", "User Account",
				URI.create(ScimUserController.USERS_PATH), URI.create(ScimUserSchema.URN));
		userResourceType.setMeta(metadata("ResourceType", properties.endpoint(
				ScimMetadataController.RESOURCE_TYPES_PATH, "User")));
		ResourceTypeResource groupResourceType = new ResourceTypeResource("Group", "Group",
				URI.create(ScimGroupController.GROUPS_PATH), URI.create(ScimGroupSchema.URN));
		groupResourceType.setMeta(metadata("ResourceType", properties.endpoint(
				ScimMetadataController.RESOURCE_TYPES_PATH, "Group")));
		this.schemas = List.of(userSchema, groupSchema);
		this.resourceTypes = List.of(userResourceType, groupResourceType);
	}

	ServiceProviderConfigResource serviceProviderConfig(URI location) {
		ServiceProviderConfigResource resource = new ServiceProviderConfigResource(null, new PatchConfig(true),
				new BulkConfig(false, 0, 0), new FilterConfig(false, 0), new ChangePasswordConfig(false),
				new SortConfig(false), new ETagConfig(false), null, AUTHENTICATION_SCHEMES);
		resource.setMeta(metadata("ServiceProviderConfig", location));
		return resource;
	}

	ListResponse<SchemaResource> schemas(String filter) throws ForbiddenException {
		rejectFilter(filter);
		return new ListResponse<>(this.schemas);
	}

	SchemaResource schema(String id) throws ResourceNotFoundException {
		return this.schemas.stream()
			.filter((schema) -> schema.getId().equals(id))
			.findFirst()
			.orElseThrow(() -> new ResourceNotFoundException("The requested SCIM schema was not found."));
	}

	ListResponse<ResourceTypeResource> resourceTypes(String filter) throws ForbiddenException {
		rejectFilter(filter);
		return new ListResponse<>(this.resourceTypes);
	}

	ResourceTypeResource resourceType(String id) throws ResourceNotFoundException {
		return this.resourceTypes.stream()
			.filter((resourceType) -> resourceType.getId().equals(id))
			.findFirst()
			.orElseThrow(() -> new ResourceNotFoundException("The requested SCIM resource type was not found."));
	}

	private static void rejectFilter(String filter) throws ForbiddenException {
		if (filter != null) {
			throw new ForbiddenException("Filtering SCIM discovery resources is not supported.");
		}
	}

	private static Meta metadata(String resourceType, URI location) {
		return new Meta().setResourceType(resourceType).setLocation(location);
	}

}
