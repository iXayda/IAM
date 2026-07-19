package com.ixayda.iam.scim.internal;

import java.util.List;

import com.ixayda.iam.group.GroupDirectoryQuery;
import com.unboundid.scim2.common.exceptions.BadRequestException;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ScimGroupCollectionQueryTests {

	@Test
	void appliesRfcPaginationDefaultsAndBounds() throws Exception {
		ScimGroupCollectionQuery defaults = parse(null, null, null, null, null);
		assertThat(defaults.startIndex()).isEqualTo(1);
		assertThat(defaults.count()).isEqualTo(100);
		assertThat(defaults.directoryQuery()).isEqualTo(GroupDirectoryQuery.all(0, 100));

		ScimGroupCollectionQuery bounded = parse(List.of("-10"), List.of("101"), null, null, null);
		assertThat(bounded.startIndex()).isEqualTo(1);
		assertThat(bounded.count()).isEqualTo(100);

		ScimGroupCollectionQuery totalsOnly = parse(List.of("2"), List.of("-1"), null, null, null);
		assertThat(totalsOnly.directoryQuery()).isEqualTo(GroupDirectoryQuery.all(1, 0));
	}

	@Test
	void parsesTheSupportedExactFilters() throws Exception {
		ScimGroupCollectionQuery displayName = parse(null, null,
				List.of("urn:ietf:params:scim:schemas:core:2.0:Group:DisplayName EQ \"Engineering\""), null,
				null);
		assertThat(displayName.directoryQuery().criterion())
			.isEqualTo(new GroupDirectoryQuery.DisplayNameEquals("Engineering"));

		ScimGroupCollectionQuery id = parse(null, null,
				List.of("id eq \"00000000-0000-0000-0000-000000000101\""), null, null);
		assertThat(id.directoryQuery().criterion()).isInstanceOf(GroupDirectoryQuery.IdEquals.class);

		ScimGroupCollectionQuery nonCanonicalId = parse(null, null,
				List.of("id eq \"00000000-0000-0000-0000-000000000ABC\""), null, null);
		assertThat(nonCanonicalId.directoryQuery().criterion()).isInstanceOf(GroupDirectoryQuery.None.class);
	}

	@Test
	void rejectsUnsupportedOrUnsafeQueriesWithoutReflectingTheirValues() {
		assertInvalidFilter(List.of("displayName co \"secret-filter-value\""));
		assertInvalidFilter(List.of("members.value eq \"secret-filter-value\""));
		assertInvalidFilter(List.of("displayName eq \"engineering\" and id pr"));
		assertInvalidFilter(List.of("displayName eq 42"));
		assertInvalidFilter(List.of("urn:example:unsupported:Group:displayName eq \"secret-filter-value\""));
		assertInvalidFilter(List.of("not a valid filter"));
		assertInvalidFilter(List.of("displayName eq \"engineering\"", "id pr"));
		assertInvalidFilter(List.of("x".repeat(1025)));

		assertThatThrownBy(() -> parse(List.of("1", "2"), null, null, null, null))
			.isInstanceOfSatisfying(BadRequestException.class, (exception) -> {
				assertThat(exception.getScimError().getScimType()).isEqualTo("invalidValue");
			});
		assertThatThrownBy(() -> parse(List.of("9223372036854775808"), null, null, null, null))
			.isInstanceOf(BadRequestException.class);
		assertThatThrownBy(() -> parse(null, null, null, List.of("displayName"), null))
			.isInstanceOfSatisfying(BadRequestException.class, (exception) -> {
				assertThat(exception.getScimError().getScimType()).isEqualTo("invalidValue");
			});
		assertThatThrownBy(() -> parse(null, null, null, null, List.of("ascending")))
			.isInstanceOfSatisfying(BadRequestException.class, (exception) -> {
				assertThat(exception.getScimError().getScimType()).isEqualTo("invalidValue");
			});
	}

	private void assertInvalidFilter(List<String> filters) {
		assertThatThrownBy(() -> parse(null, null, filters, null, null))
			.isInstanceOfSatisfying(BadRequestException.class, (exception) -> {
				assertThat(exception.getScimError().getScimType()).isEqualTo("invalidFilter");
				assertThat(exception.getMessage()).doesNotContain("secret-filter-value");
			});
	}

	private static ScimGroupCollectionQuery parse(List<String> startIndexes, List<String> counts,
			List<String> filters, List<String> sortBy, List<String> sortOrder) throws BadRequestException {
		return ScimGroupCollectionQuery.parse(startIndexes, counts, filters, sortBy, sortOrder);
	}

}
