package com.ixayda.iam.scim.internal;

import java.net.URI;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import com.ixayda.iam.group.CreateGroupRequest;
import com.ixayda.iam.group.GroupOperations;
import com.ixayda.iam.group.ReplaceGroupRequest;
import com.ixayda.iam.user.UserId;
import com.unboundid.scim2.common.exceptions.BadRequestException;
import com.unboundid.scim2.common.types.Member;
import com.unboundid.scim2.common.utils.JsonUtils;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

record ScimGroupCreateRequest(CreateGroupRequest request, Set<UserId> memberIds) {

	private static final String INVALID_DETAIL = "The SCIM Group request contains an invalid or unsupported value.";

	private static final Map<String, String> RESOURCE_ATTRIBUTES = canonicalAttributes("schemas", "id", "meta",
			"externalId", "displayName", "members");

	private static final Map<String, String> MEMBER_ATTRIBUTES =
			canonicalAttributes("value", "type", "$ref", "display");

	ScimGroupCreateRequest {
		memberIds = Set.copyOf(memberIds);
	}

	ReplaceGroupRequest replacement() {
		return new ReplaceGroupRequest(this.request.displayName(), this.memberIds);
	}

	static ScimGroupCreateRequest parse(ObjectNode source, ScimJsonCodec codec, ScimProperties properties)
			throws BadRequestException {
		if (source == null) {
			throw invalid();
		}
		ObjectNode writable = canonicalize(source, RESOURCE_ATTRIBUTES);
		if (writable.has("members")) {
			writable.set("members", canonicalizeMembers(writable.get("members")));
		}
		writable.remove(List.of("id", "meta"));
		try {
			return parse(codec.jsonMapper().treeToValue(writable, ScimGroupCreateResource.class), properties);
		}
		catch (JacksonException exception) {
			throw invalid();
		}
	}

	static ScimGroupCreateRequest parse(ScimGroupCreateResource resource, ScimProperties properties)
			throws BadRequestException {
		if (resource == null || properties == null) {
			throw invalid();
		}
		validateSchemas(resource);
		if (resource.getExternalId() != null) {
			throw invalid();
		}
		try {
			CreateGroupRequest request = new CreateGroupRequest(resource.getDisplayName());
			Set<UserId> memberIds = members(resource.getMembers(), properties);
			if (memberIds.size() > GroupOperations.MAX_MEMBERS_PER_GROUP) {
				throw invalid();
			}
			return new ScimGroupCreateRequest(request, memberIds);
		}
		catch (BadRequestException exception) {
			throw exception;
		}
		catch (RuntimeException exception) {
			throw invalid();
		}
	}

	private static Set<UserId> members(List<Member> members, ScimProperties properties) throws BadRequestException {
		if (members == null || members.isEmpty()) {
			return Set.of();
		}
		LinkedHashSet<UserId> memberIds = new LinkedHashSet<>();
		for (Member member : members) {
			if (member == null || member.getValue() == null || member.getDisplay() != null
					|| member.getType() != null && !"User".equalsIgnoreCase(member.getType())) {
				throw invalid();
			}
			UserId userId = UserId.from(member.getValue());
			if (member.getRef() != null && !matches(member.getRef(), userId, properties)) {
				throw invalid();
			}
			memberIds.add(userId);
		}
		return Set.copyOf(memberIds);
	}

	private static boolean matches(URI reference, UserId userId, ScimProperties properties) {
		if (reference.getRawQuery() != null || reference.getRawFragment() != null
				|| !reference.isAbsolute() && reference.getRawAuthority() != null) {
			return false;
		}
		URI expected = properties.endpoint(ScimUserController.USERS_PATH, userId.toString());
		URI resolved = reference.isAbsolute() ? reference
				: URI.create(properties.baseUrl().toASCIIString() + "/").resolve(reference);
		return expected.equals(resolved.normalize());
	}

	private static void validateSchemas(ScimGroupCreateResource resource) throws BadRequestException {
		if (!resource.schemasProvided() || !resource.schemasValid()
				|| !resource.getSchemaUrns().equals(Set.of(ScimGroupSchema.URN))
				|| !resource.getExtensionObjectNode().isEmpty()) {
			throw invalid();
		}
	}

	private static JsonNode canonicalizeMembers(JsonNode members) throws BadRequestException {
		if (members == null || members.isNull()) {
			return members;
		}
		if (!members.isArray()) {
			throw invalid();
		}
		ArrayNode canonical = JsonUtils.getJsonNodeFactory().arrayNode();
		for (JsonNode member : members) {
			if (!(member instanceof ObjectNode object)) {
				throw invalid();
			}
			canonical.add(canonicalize(object, MEMBER_ATTRIBUTES));
		}
		return canonical;
	}

	private static ObjectNode canonicalize(ObjectNode source, Map<String, String> supported)
			throws BadRequestException {
		ObjectNode canonicalObject = JsonUtils.getJsonNodeFactory().objectNode();
		Set<String> seen = new HashSet<>();
		for (String name : source.propertyNames()) {
			String canonical = supported.get(name.toLowerCase(Locale.ROOT));
			if (canonical == null || !seen.add(canonical)) {
				throw invalid();
			}
			canonicalObject.set(canonical, source.get(name).deepCopy());
		}
		return canonicalObject;
	}

	private static Map<String, String> canonicalAttributes(String... names) {
		return java.util.Arrays.stream(names)
			.collect(java.util.stream.Collectors.toUnmodifiableMap((name) -> name.toLowerCase(Locale.ROOT),
					(name) -> name));
	}

	private static BadRequestException invalid() {
		return BadRequestException.invalidValue(INVALID_DETAIL);
	}

}
