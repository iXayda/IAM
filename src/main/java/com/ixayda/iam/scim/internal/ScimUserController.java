package com.ixayda.iam.scim.internal;

import java.net.URI;
import java.util.List;

import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.User;
import com.ixayda.iam.user.UserPage;
import com.unboundid.scim2.common.exceptions.ScimException;
import com.unboundid.scim2.common.messages.ListResponse;
import com.unboundid.scim2.common.types.UserResource;
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
final class ScimUserController {

	static final String USERS_PATH = "/Users";

	private final ScimTenantResolver tenantResolver;

	private final ScimUserService users;

	private final ScimUserMapper mapper;

	private final ScimProperties properties;

	ScimUserController(ScimTenantResolver tenantResolver, ScimUserService users, ScimUserMapper mapper,
			ScimProperties properties) {
		this.tenantResolver = tenantResolver;
		this.users = users;
		this.mapper = mapper;
		this.properties = properties;
	}

	@GetMapping(value = USERS_PATH,
			produces = { ScimMediaTypes.SCIM_JSON_VALUE, MediaType.APPLICATION_JSON_VALUE })
	ResponseEntity<ListResponse<UserResource>> users(@AuthenticationPrincipal Jwt jwt,
			@RequestParam(name = "startIndex", required = false) List<String> startIndexes,
			@RequestParam(name = "count", required = false) List<String> counts,
			@RequestParam(name = "filter", required = false) List<String> filters,
			@RequestParam(name = "sortBy", required = false) List<String> sortBy,
			@RequestParam(name = "sortOrder", required = false) List<String> sortOrder,
			@RequestParam(name = "attributes", required = false) List<String> attributes,
			@RequestParam(name = "excludedAttributes", required = false) List<String> excludedAttributes)
			throws ScimException {
		ScimUserCollectionQuery query = ScimUserCollectionQuery.parse(startIndexes, counts, filters, sortBy, sortOrder);
		ScimUserAttributeSelection selection = ScimUserAttributeSelection.parse(attributes, excludedAttributes);
		TenantId tenantId = this.tenantResolver.resolve(jwt);
		UserPage page = this.users.findPage(tenantId, query.directoryQuery());
		List<UserResource> resources = page.users().stream().map((user) -> {
			URI location = this.properties.endpoint(USERS_PATH, user.id().toString());
			return this.mapper.map(user, location, selection);
		}).toList();
		ListResponse<UserResource> response = new ListResponse<>(Math.toIntExact(page.totalResults()), resources,
				query.startIndex(), resources.size());
		URI location = this.properties.endpoint(USERS_PATH);
		return ResponseEntity.ok().header(HttpHeaders.CONTENT_LOCATION, location.toASCIIString()).body(response);
	}

	@GetMapping(value = USERS_PATH + "/{id}",
			produces = { ScimMediaTypes.SCIM_JSON_VALUE, MediaType.APPLICATION_JSON_VALUE })
	ResponseEntity<UserResource> user(@PathVariable String id, @AuthenticationPrincipal Jwt jwt,
			@RequestParam(name = "attributes", required = false) List<String> attributes,
			@RequestParam(name = "excludedAttributes", required = false) List<String> excludedAttributes)
			throws ScimException {
		ScimUserAttributeSelection selection = ScimUserAttributeSelection.parse(attributes, excludedAttributes);
		TenantId tenantId = this.tenantResolver.resolve(jwt);
		User user = this.users.find(tenantId, id);
		URI location = this.properties.endpoint(USERS_PATH, user.id().toString());
		return ResponseEntity.ok()
			.header(HttpHeaders.CONTENT_LOCATION, location.toASCIIString())
			.header(HttpHeaders.LOCATION, location.toASCIIString())
			.body(this.mapper.map(user, location, selection));
	}

}
