package com.ixayda.iam.scim.internal;

import java.net.URI;
import java.util.List;

import com.ixayda.iam.tenant.TenantId;
import com.unboundid.scim2.common.exceptions.ScimException;
import com.unboundid.scim2.common.messages.ListResponse;
import com.unboundid.scim2.common.types.GroupResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import tools.jackson.databind.node.ObjectNode;

@RestController
@RequestMapping(ScimMetadataController.BASE_PATH)
final class ScimGroupController {

	static final String GROUPS_PATH = "/Groups";

	private final ScimTenantResolver tenantResolver;

	private final ScimGroupService groups;

	private final ScimGroupMapper mapper;

	private final ScimProperties properties;

	private final ScimJsonCodec codec;

	ScimGroupController(ScimTenantResolver tenantResolver, ScimGroupService groups, ScimGroupMapper mapper,
			ScimProperties properties, ScimJsonCodec codec) {
		this.tenantResolver = tenantResolver;
		this.groups = groups;
		this.mapper = mapper;
		this.properties = properties;
		this.codec = codec;
	}

	@PostMapping(value = GROUPS_PATH,
			consumes = { ScimMediaTypes.SCIM_JSON_VALUE, MediaType.APPLICATION_JSON_VALUE },
			produces = { ScimMediaTypes.SCIM_JSON_VALUE, MediaType.APPLICATION_JSON_VALUE })
	ResponseEntity<GroupResource> createGroup(@AuthenticationPrincipal Jwt jwt, @RequestBody ObjectNode resource,
			@RequestParam(name = "attributes", required = false) List<String> attributes,
			@RequestParam(name = "excludedAttributes", required = false) List<String> excludedAttributes)
			throws ScimException {
		ScimGroupAttributeSelection selection = ScimGroupAttributeSelection.parse(attributes, excludedAttributes)
			.requiring("meta", "location");
		ScimGroupCreateRequest command = ScimGroupCreateRequest.parse(resource, this.codec, this.properties);
		TenantId tenantId = this.tenantResolver.resolve(jwt);
		ScimGroupView created = this.groups.create(tenantId, command);
		URI location = this.properties.endpoint(GROUPS_PATH, created.group().id().toString());
		return ResponseEntity.created(location)
			.header(HttpHeaders.CONTENT_LOCATION, location.toASCIIString())
			.body(this.mapper.map(created, location, selection));
	}

	@GetMapping(value = GROUPS_PATH,
			produces = { ScimMediaTypes.SCIM_JSON_VALUE, MediaType.APPLICATION_JSON_VALUE })
	ResponseEntity<ListResponse<GroupResource>> groups(@AuthenticationPrincipal Jwt jwt,
			@RequestParam(name = "startIndex", required = false) List<String> startIndexes,
			@RequestParam(name = "count", required = false) List<String> counts,
			@RequestParam(name = "filter", required = false) List<String> filters,
			@RequestParam(name = "sortBy", required = false) List<String> sortBy,
			@RequestParam(name = "sortOrder", required = false) List<String> sortOrder,
			@RequestParam(name = "attributes", required = false) List<String> attributes,
			@RequestParam(name = "excludedAttributes", required = false) List<String> excludedAttributes)
			throws ScimException {
		ScimGroupCollectionQuery query =
				ScimGroupCollectionQuery.parse(startIndexes, counts, filters, sortBy, sortOrder);
		ScimGroupAttributeSelection selection = ScimGroupAttributeSelection.parse(attributes, excludedAttributes);
		TenantId tenantId = this.tenantResolver.resolve(jwt);
		ScimGroupPage page = this.groups.findPage(tenantId, query.directoryQuery(), selection.includesMembers());
		List<GroupResource> resources = page.groups().stream().map((group) -> {
			URI location = this.properties.endpoint(GROUPS_PATH, group.group().id().toString());
			return this.mapper.map(group, location, selection);
		}).toList();
		ListResponse<GroupResource> response = new ListResponse<>(Math.toIntExact(page.totalResults()), resources,
				query.startIndex(), resources.size());
		URI location = this.properties.endpoint(GROUPS_PATH);
		return ResponseEntity.ok().header(HttpHeaders.CONTENT_LOCATION, location.toASCIIString()).body(response);
	}

	@GetMapping(value = GROUPS_PATH + "/{id}",
			produces = { ScimMediaTypes.SCIM_JSON_VALUE, MediaType.APPLICATION_JSON_VALUE })
	ResponseEntity<GroupResource> group(@PathVariable String id, @AuthenticationPrincipal Jwt jwt,
			@RequestParam(name = "attributes", required = false) List<String> attributes,
			@RequestParam(name = "excludedAttributes", required = false) List<String> excludedAttributes)
			throws ScimException {
		ScimGroupAttributeSelection selection = ScimGroupAttributeSelection.parse(attributes, excludedAttributes);
		TenantId tenantId = this.tenantResolver.resolve(jwt);
		ScimGroupView group = this.groups.find(tenantId, id);
		URI location = this.properties.endpoint(GROUPS_PATH, group.group().id().toString());
		return ResponseEntity.ok()
			.header(HttpHeaders.CONTENT_LOCATION, location.toASCIIString())
			.header(HttpHeaders.LOCATION, location.toASCIIString())
			.body(this.mapper.map(group, location, selection));
	}

}
