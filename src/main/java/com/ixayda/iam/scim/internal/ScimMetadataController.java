package com.ixayda.iam.scim.internal;

import java.net.URI;

import com.unboundid.scim2.common.exceptions.ScimException;
import com.unboundid.scim2.common.messages.ListResponse;
import com.unboundid.scim2.common.types.ResourceTypeResource;
import com.unboundid.scim2.common.types.SchemaResource;
import com.unboundid.scim2.common.types.ServiceProviderConfigResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(ScimMetadataController.BASE_PATH)
final class ScimMetadataController {

	static final String BASE_PATH = "/scim/v2";

	static final String SERVICE_PROVIDER_CONFIG_PATH = "/ServiceProviderConfig";

	static final String SCHEMAS_PATH = "/Schemas";

	static final String RESOURCE_TYPES_PATH = "/ResourceTypes";

	private final ScimMetadataCatalog catalog;
	private final ScimProperties properties;

	ScimMetadataController(ScimMetadataCatalog catalog, ScimProperties properties) {
		this.catalog = catalog;
		this.properties = properties;
	}

	@GetMapping(value = SERVICE_PROVIDER_CONFIG_PATH,
			produces = { ScimMediaTypes.SCIM_JSON_VALUE, MediaType.APPLICATION_JSON_VALUE })
	ResponseEntity<ServiceProviderConfigResource> serviceProviderConfig() {
		URI location = this.properties.endpoint(SERVICE_PROVIDER_CONFIG_PATH);
		return response(this.catalog.serviceProviderConfig(location), location);
	}

	@GetMapping(value = SCHEMAS_PATH,
			produces = { ScimMediaTypes.SCIM_JSON_VALUE, MediaType.APPLICATION_JSON_VALUE })
	ResponseEntity<ListResponse<SchemaResource>> schemas(
			@RequestParam(name = "filter", required = false) String filter) throws ScimException {
		URI location = this.properties.endpoint(SCHEMAS_PATH);
		return response(this.catalog.schemas(filter), location);
	}

	@GetMapping(value = SCHEMAS_PATH + "/{id}",
			produces = { ScimMediaTypes.SCIM_JSON_VALUE, MediaType.APPLICATION_JSON_VALUE })
	ResponseEntity<SchemaResource> schema(@PathVariable String id) throws ScimException {
		URI location = this.properties.endpoint(SCHEMAS_PATH, id);
		return response(this.catalog.schema(id), location);
	}

	@GetMapping(value = RESOURCE_TYPES_PATH,
			produces = { ScimMediaTypes.SCIM_JSON_VALUE, MediaType.APPLICATION_JSON_VALUE })
	ResponseEntity<ListResponse<ResourceTypeResource>> resourceTypes(
			@RequestParam(name = "filter", required = false) String filter) throws ScimException {
		URI location = this.properties.endpoint(RESOURCE_TYPES_PATH);
		return response(this.catalog.resourceTypes(filter), location);
	}

	@GetMapping(value = RESOURCE_TYPES_PATH + "/{id}",
			produces = { ScimMediaTypes.SCIM_JSON_VALUE, MediaType.APPLICATION_JSON_VALUE })
	ResponseEntity<ResourceTypeResource> resourceType(@PathVariable String id) throws ScimException {
		URI location = this.properties.endpoint(RESOURCE_TYPES_PATH, id);
		return response(this.catalog.resourceType(id), location);
	}

	private static <T> ResponseEntity<T> response(T body, URI location) {
		return ResponseEntity.ok()
			.header(HttpHeaders.CONTENT_LOCATION, location.toASCIIString())
			.body(body);
	}

}
