package com.ixayda.iam.scim.internal;

import java.net.URI;
import java.util.List;

import com.ixayda.iam.tenant.TenantId;
import com.unboundid.scim2.common.exceptions.ScimException;
import com.unboundid.scim2.common.types.GroupResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(ScimMetadataController.BASE_PATH)
final class ScimGroupController {

	static final String GROUPS_PATH = "/Groups";

	private final ScimTenantResolver tenantResolver;

	private final ScimGroupService groups;

	private final ScimGroupMapper mapper;

	private final ScimProperties properties;

	ScimGroupController(ScimTenantResolver tenantResolver, ScimGroupService groups, ScimGroupMapper mapper,
			ScimProperties properties) {
		this.tenantResolver = tenantResolver;
		this.groups = groups;
		this.mapper = mapper;
		this.properties = properties;
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
