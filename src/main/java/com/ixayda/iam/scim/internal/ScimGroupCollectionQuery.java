package com.ixayda.iam.scim.internal;

import java.util.List;

import com.ixayda.iam.group.GroupDirectoryQuery;
import com.ixayda.iam.group.GroupId;
import com.unboundid.scim2.common.Path;
import com.unboundid.scim2.common.exceptions.BadRequestException;
import com.unboundid.scim2.common.filters.EqualFilter;
import com.unboundid.scim2.common.filters.Filter;

record ScimGroupCollectionQuery(int startIndex, int count, GroupDirectoryQuery directoryQuery) {

	static final int DEFAULT_PAGE_SIZE = 100;

	static final int MAX_PAGE_SIZE = GroupDirectoryQuery.MAX_LIMIT;

	private static final int MAX_FILTER_LENGTH = 1024;

	private static final String INVALID_PAGINATION_DETAIL = "The SCIM Group pagination parameters are invalid.";

	private static final String INVALID_FILTER_DETAIL = "The SCIM Group filter is invalid or unsupported.";

	private static final String INVALID_SORT_DETAIL = "SCIM Group sorting is not supported.";

	static ScimGroupCollectionQuery parse(List<String> startIndexes, List<String> counts, List<String> filters,
			List<String> sortBy, List<String> sortOrder) throws BadRequestException {
		rejectSort(sortBy, sortOrder);
		int startIndex = startIndex(startIndexes);
		int count = count(counts);
		return new ScimGroupCollectionQuery(startIndex, count,
				directoryQuery(startIndex - 1, count, singleFilter(filters)));
	}

	private static int startIndex(List<String> values) throws BadRequestException {
		String value = single(values, "1");
		long parsed = parseInteger(value);
		if (parsed <= 1) {
			return 1;
		}
		if (parsed > Integer.MAX_VALUE) {
			throw invalidPagination();
		}
		return (int) parsed;
	}

	private static int count(List<String> values) throws BadRequestException {
		String value = single(values, Integer.toString(DEFAULT_PAGE_SIZE));
		long parsed = parseInteger(value);
		if (parsed <= 0) {
			return 0;
		}
		return (int) Math.min(parsed, MAX_PAGE_SIZE);
	}

	private static long parseInteger(String value) throws BadRequestException {
		try {
			return Long.parseLong(value);
		}
		catch (NumberFormatException exception) {
			throw invalidPagination();
		}
	}

	private static String single(List<String> values, String defaultValue) throws BadRequestException {
		if (values == null) {
			return defaultValue;
		}
		if (values.size() != 1 || values.getFirst().isEmpty()) {
			throw invalidPagination();
		}
		return values.getFirst();
	}

	private static String singleFilter(List<String> values) throws BadRequestException {
		if (values == null) {
			return null;
		}
		if (values.size() != 1 || values.getFirst().isBlank() || values.getFirst().length() > MAX_FILTER_LENGTH) {
			throw invalidFilter();
		}
		return values.getFirst();
	}

	private static GroupDirectoryQuery directoryQuery(int offset, int limit, String expression)
			throws BadRequestException {
		if (expression == null) {
			return GroupDirectoryQuery.all(offset, limit);
		}
		try {
			Filter filter = Filter.fromString(expression);
			if (!(filter instanceof EqualFilter equalFilter) || equalFilter.getComparisonValue() == null
					|| !equalFilter.getComparisonValue().isString()) {
				throw invalidFilter();
			}
			Path path = equalFilter.getAttributePath();
			if (path == null || path.isRoot() || path.size() != 1
					|| path.getSchemaUrn() != null && !ScimGroupSchema.URN.equalsIgnoreCase(path.getSchemaUrn())) {
				throw invalidFilter();
			}
			String attribute = path.getElement(0).getAttribute();
			String value = equalFilter.getComparisonValue().stringValue();
			if ("displayName".equalsIgnoreCase(attribute)) {
				return GroupDirectoryQuery.displayNameEquals(offset, limit, value);
			}
			if ("id".equalsIgnoreCase(attribute)) {
				return idQuery(offset, limit, value);
			}
			throw invalidFilter();
		}
		catch (BadRequestException exception) {
			throw invalidFilter();
		}
		catch (RuntimeException exception) {
			throw invalidFilter();
		}
	}

	private static GroupDirectoryQuery idQuery(int offset, int limit, String value) {
		try {
			GroupId groupId = GroupId.from(value);
			return groupId.toString().equals(value) ? GroupDirectoryQuery.idEquals(offset, limit, groupId)
					: GroupDirectoryQuery.none(offset, limit);
		}
		catch (RuntimeException exception) {
			return GroupDirectoryQuery.none(offset, limit);
		}
	}

	private static void rejectSort(List<String> sortBy, List<String> sortOrder) throws BadRequestException {
		if (sortBy != null || sortOrder != null) {
			throw BadRequestException.invalidValue(INVALID_SORT_DETAIL);
		}
	}

	private static BadRequestException invalidPagination() {
		return BadRequestException.invalidValue(INVALID_PAGINATION_DETAIL);
	}

	private static BadRequestException invalidFilter() {
		return BadRequestException.invalidFilter(INVALID_FILTER_DETAIL);
	}

}
