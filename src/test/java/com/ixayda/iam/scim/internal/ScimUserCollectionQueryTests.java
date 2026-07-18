package com.ixayda.iam.scim.internal;

import java.util.List;

import com.ixayda.iam.user.UserDirectoryQuery;
import com.unboundid.scim2.common.exceptions.BadRequestException;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ScimUserCollectionQueryTests {

	@Test
	void appliesRfcPaginationDefaultsAndBounds() throws Exception {
		ScimUserCollectionQuery defaults = parse(null, null, null, null, null);
		assertThat(defaults.startIndex()).isEqualTo(1);
		assertThat(defaults.count()).isEqualTo(100);
		assertThat(defaults.directoryQuery()).isEqualTo(UserDirectoryQuery.all(0, 100));

		ScimUserCollectionQuery bounded = parse(List.of("-10"), List.of("101"), null, null, null);
		assertThat(bounded.startIndex()).isEqualTo(1);
		assertThat(bounded.count()).isEqualTo(100);

		ScimUserCollectionQuery totalsOnly = parse(List.of("2"), List.of("-1"), null, null, null);
		assertThat(totalsOnly.directoryQuery()).isEqualTo(UserDirectoryQuery.all(1, 0));
	}

	@Test
	void parsesTheSupportedExactFilters() throws Exception {
		ScimUserCollectionQuery userName = parse(null, null,
				List.of("urn:ietf:params:scim:schemas:core:2.0:User:Username EQ \"Alice\""), null, null);
		assertThat(userName.directoryQuery().criterion())
			.isEqualTo(new UserDirectoryQuery.PrimaryIdentifierEquals("Alice"));

		ScimUserCollectionQuery id = parse(null, null,
				List.of("id eq \"00000000-0000-0000-0000-000000000101\""), null, null);
		assertThat(id.directoryQuery().criterion()).isInstanceOf(UserDirectoryQuery.IdEquals.class);

		ScimUserCollectionQuery nonCanonicalId = parse(null, null,
				List.of("id eq \"00000000-0000-0000-0000-000000000ABC\""), null, null);
		assertThat(nonCanonicalId.directoryQuery().criterion()).isInstanceOf(UserDirectoryQuery.None.class);
	}

	@Test
	void rejectsUnsupportedOrUnsafeQueriesWithoutReflectingTheirValues() {
		assertInvalidFilter(List.of("userName co \"secret-filter-value\""));
		assertInvalidFilter(List.of("displayName eq \"secret-filter-value\""));
		assertInvalidFilter(List.of("userName eq \"alice\" and active eq true"));
		assertInvalidFilter(List.of("userName eq 42"));
		assertInvalidFilter(List.of("urn:example:unsupported:User:userName eq \"secret-filter-value\""));
		assertInvalidFilter(List.of("not a valid filter"));
		assertInvalidFilter(List.of("userName eq \"alice\"", "id pr"));
		assertInvalidFilter(List.of("x".repeat(1025)));

		assertThatThrownBy(() -> parse(List.of("1", "2"), null, null, null, null))
			.isInstanceOfSatisfying(BadRequestException.class, (exception) -> {
				assertThat(exception.getScimError().getScimType()).isEqualTo("invalidValue");
			});
		assertThatThrownBy(() -> parse(List.of("9223372036854775808"), null, null, null, null))
			.isInstanceOf(BadRequestException.class);
		assertThatThrownBy(() -> parse(null, null, null, List.of("userName"), null))
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

	private static ScimUserCollectionQuery parse(List<String> startIndexes, List<String> counts,
			List<String> filters, List<String> sortBy, List<String> sortOrder) throws BadRequestException {
		return ScimUserCollectionQuery.parse(startIndexes, counts, filters, sortBy, sortOrder);
	}

}
