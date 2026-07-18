package com.ixayda.iam.scim.internal;

import java.net.URI;
import java.util.List;

import com.unboundid.scim2.common.exceptions.ForbiddenException;
import com.unboundid.scim2.common.exceptions.ResourceNotFoundException;
import com.unboundid.scim2.common.messages.ListResponse;
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

	private static final List<SchemaResource> SCHEMAS = List.of();

	private static final List<ResourceTypeResource> RESOURCE_TYPES = List.of();

	ServiceProviderConfigResource serviceProviderConfig(URI location) {
		ServiceProviderConfigResource resource = new ServiceProviderConfigResource(null, new PatchConfig(false),
				new BulkConfig(false, 0, 0), new FilterConfig(false, 0), new ChangePasswordConfig(false),
				new SortConfig(false), new ETagConfig(false), null, List.of());
		resource.setMeta(metadata("ServiceProviderConfig", location));
		return resource;
	}

	ListResponse<SchemaResource> schemas(String filter) throws ForbiddenException {
		rejectFilter(filter);
		return new ListResponse<>(SCHEMAS);
	}

	SchemaResource schema(String id) throws ResourceNotFoundException {
		return SCHEMAS.stream()
			.filter((schema) -> schema.getId().equals(id))
			.findFirst()
			.orElseThrow(() -> new ResourceNotFoundException("The requested SCIM schema was not found."));
	}

	ListResponse<ResourceTypeResource> resourceTypes(String filter) throws ForbiddenException {
		rejectFilter(filter);
		return new ListResponse<>(RESOURCE_TYPES);
	}

	ResourceTypeResource resourceType(String id) throws ResourceNotFoundException {
		return RESOURCE_TYPES.stream()
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
