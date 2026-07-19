package com.ixayda.iam.scim.internal;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import com.unboundid.scim2.common.Path;
import com.unboundid.scim2.common.exceptions.BadRequestException;
import com.unboundid.scim2.common.types.AttributeDefinition;

final class ScimGroupAttributeSelection {

	private static final String INVALID_SELECTION_DETAIL = "The SCIM Group attribute selection is invalid.";

	private enum Mode {

		ALL,

		INCLUDE,

		EXCLUDE

	}

	private final Mode mode;

	private final List<List<String>> paths;

	private final List<List<String>> requiredPaths;

	private ScimGroupAttributeSelection(Mode mode, List<List<String>> paths, List<List<String>> requiredPaths) {
		this.mode = mode;
		this.paths = List.copyOf(paths);
		this.requiredPaths = List.copyOf(requiredPaths);
	}

	static ScimGroupAttributeSelection parse(List<String> attributes, List<String> excludedAttributes)
			throws BadRequestException {
		if (attributes != null && excludedAttributes != null) {
			throw invalidSelection();
		}
		if (attributes == null && excludedAttributes == null) {
			return new ScimGroupAttributeSelection(Mode.ALL, List.of(), List.of());
		}
		return new ScimGroupAttributeSelection(attributes == null ? Mode.EXCLUDE : Mode.INCLUDE,
				parsePaths(attributes == null ? excludedAttributes : attributes), List.of());
	}

	ScimGroupAttributeSelection requiring(String... attributePath) {
		List<List<String>> required = new ArrayList<>(this.requiredPaths);
		required.add(normalize(attributePath));
		return new ScimGroupAttributeSelection(this.mode, this.paths, required);
	}

	boolean includes(String... attributePath) {
		List<String> candidate = normalize(attributePath);
		if (isAlwaysReturned(candidate) || this.requiredPaths.stream()
			.anyMatch((required) -> isPrefix(required, candidate) || isPrefix(candidate, required))) {
			return true;
		}
		return switch (this.mode) {
			case ALL -> true;
			case INCLUDE -> this.paths.stream()
				.anyMatch((selected) -> isPrefix(selected, candidate) || isPrefix(candidate, selected));
			case EXCLUDE -> this.paths.stream().noneMatch((selected) -> isPrefix(selected, candidate));
		};
	}

	boolean includesMembers() {
		return includes("members", "value") || includes("members", "type") || includes("members", "$ref");
	}

	private static List<List<String>> parsePaths(List<String> values) throws BadRequestException {
		List<List<String>> paths = new ArrayList<>();
		try {
			for (String value : values) {
				for (String candidate : value.split(",", -1)) {
					String trimmed = candidate.strip();
					if (trimmed.isEmpty()) {
						throw invalidSelection();
					}
					Path path = Path.fromString(trimmed);
					validate(path);
					paths.add(normalize(path));
				}
			}
		}
		catch (BadRequestException exception) {
			throw invalidSelection();
		}
		if (paths.isEmpty()) {
			throw invalidSelection();
		}
		return List.copyOf(paths);
	}

	private static void validate(Path path) throws BadRequestException {
		if (path.isRoot() || path.size() > 2
				|| path.getSchemaUrn() != null && !ScimGroupSchema.URN.equalsIgnoreCase(path.getSchemaUrn())) {
			throw invalidSelection();
		}
		for (Path.Element element : path) {
			if (element.getValueFilter() != null) {
				throw invalidSelection();
			}
		}
		AttributeDefinition definition = find(ScimGroupSchema.attributeDefinitions(),
				path.getElement(0).getAttribute());
		if (definition == null || path.size() == 2
				&& find(definition.getSubAttributes(), path.getElement(1).getAttribute()) == null) {
			throw invalidSelection();
		}
	}

	private static AttributeDefinition find(Iterable<AttributeDefinition> definitions, String name) {
		if (definitions == null) {
			return null;
		}
		for (AttributeDefinition definition : definitions) {
			if (definition.getName().equalsIgnoreCase(name)) {
				return definition;
			}
		}
		return null;
	}

	private static List<String> normalize(Path path) {
		List<String> normalized = new ArrayList<>(path.size());
		for (Path.Element element : path) {
			normalized.add(element.getAttribute().toLowerCase(Locale.ROOT));
		}
		return List.copyOf(normalized);
	}

	private static List<String> normalize(String... path) {
		return java.util.Arrays.stream(path).map((value) -> value.toLowerCase(Locale.ROOT)).toList();
	}

	private static boolean isAlwaysReturned(List<String> path) {
		return path.size() == 1 && (path.getFirst().equals("schemas") || path.getFirst().equals("id"));
	}

	private static boolean isPrefix(List<String> prefix, List<String> candidate) {
		return prefix.size() <= candidate.size() && prefix.equals(candidate.subList(0, prefix.size()));
	}

	private static BadRequestException invalidSelection() {
		return BadRequestException.invalidValue(INVALID_SELECTION_DETAIL);
	}

}
