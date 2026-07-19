package com.ixayda.iam.scim.internal;

import java.net.URI;
import java.util.List;

import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.User;
import com.ixayda.iam.user.UserPage;
import com.unboundid.scim2.common.exceptions.BadRequestException;
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
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import tools.jackson.databind.node.ObjectNode;

@RestController
@RequestMapping(ScimMetadataController.BASE_PATH)
final class ScimUserController {

	static final String USERS_PATH = "/Users";

	private final ScimTenantResolver tenantResolver;

	private final ScimUserService users;

	private final ScimUserMapper mapper;

	private final ScimProperties properties;

	private final ScimJsonCodec codec;

	ScimUserController(ScimTenantResolver tenantResolver, ScimUserService users, ScimUserMapper mapper,
			ScimProperties properties, ScimJsonCodec codec) {
		this.tenantResolver = tenantResolver;
		this.users = users;
		this.mapper = mapper;
		this.properties = properties;
		this.codec = codec;
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

	@PostMapping(value = USERS_PATH,
			consumes = { ScimMediaTypes.SCIM_JSON_VALUE, MediaType.APPLICATION_JSON_VALUE },
			produces = { ScimMediaTypes.SCIM_JSON_VALUE, MediaType.APPLICATION_JSON_VALUE })
	ResponseEntity<UserResource> createUser(@AuthenticationPrincipal Jwt jwt, @RequestBody ObjectNode resource,
			@RequestParam(name = "attributes", required = false) List<String> attributes,
			@RequestParam(name = "excludedAttributes", required = false) List<String> excludedAttributes)
			throws ScimException {
		ScimUserAttributeSelection selection = ScimUserAttributeSelection.parse(attributes, excludedAttributes)
			.requiring("meta", "location");
		ScimUserCreateRequest command = ScimUserCreateRequest.parse(resource, this.codec);
		TenantId tenantId = this.tenantResolver.resolve(jwt);
		User created = this.users.create(tenantId, command);
		URI location = this.properties.endpoint(USERS_PATH, created.id().toString());
		UserResource response = this.mapper.map(created, location, selection);
		return ResponseEntity.created(location)
			.header(HttpHeaders.CONTENT_LOCATION, location.toASCIIString())
			.body(response);
	}

	@PutMapping(value = USERS_PATH + "/{id}",
			consumes = { ScimMediaTypes.SCIM_JSON_VALUE, MediaType.APPLICATION_JSON_VALUE },
			produces = { ScimMediaTypes.SCIM_JSON_VALUE, MediaType.APPLICATION_JSON_VALUE })
	ResponseEntity<UserResource> replaceUser(@PathVariable String id, @AuthenticationPrincipal Jwt jwt,
			@RequestBody ObjectNode resource,
			@RequestHeader(name = HttpHeaders.IF_MATCH, required = false) String ifMatch,
			@RequestParam(name = "attributes", required = false) List<String> attributes,
			@RequestParam(name = "excludedAttributes", required = false) List<String> excludedAttributes)
			throws ScimException {
		ScimUserAttributeSelection selection = ScimUserAttributeSelection.parse(attributes, excludedAttributes);
		if (ifMatch != null) {
			throw BadRequestException.invalidValue("SCIM entity tags are not supported.");
		}
		ScimUserCreateRequest command = ScimUserCreateRequest.parse(resource, this.codec);
		TenantId tenantId = this.tenantResolver.resolve(jwt);
		User replaced = this.users.replace(tenantId, id, command);
		URI location = this.properties.endpoint(USERS_PATH, replaced.id().toString());
		return ResponseEntity.ok()
			.header(HttpHeaders.LOCATION, location.toASCIIString())
			.header(HttpHeaders.CONTENT_LOCATION, location.toASCIIString())
			.body(this.mapper.map(replaced, location, selection));
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
