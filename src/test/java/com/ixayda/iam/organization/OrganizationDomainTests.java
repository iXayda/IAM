package com.ixayda.iam.organization;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.UUID;

import com.ixayda.iam.tenant.TenantId;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

class OrganizationDomainTests {

	private static final OrganizationId ORGANIZATION_ID =
			new OrganizationId(UUID.fromString("019bc1e7-14d1-7d38-bd23-0877f2cd0cc2"));

	private static final Instant CREATED_AT = Instant.parse("2026-01-01T00:00:00Z");

	@Test
	void usesUuidBackedOrganizationIds() {
		assertThat(OrganizationId.from(ORGANIZATION_ID.toString())).isEqualTo(ORGANIZATION_ID);
		assertThat(OrganizationId.random().value()).isNotNull();
	}

	@Test
	void validatesInputAndNormalizesTheDisplayName() {
		CreateOrganizationRequest request = new CreateOrganizationRequest("engineering", "  Engineering  ");

		assertThat(request.slug()).isEqualTo("engineering");
		assertThat(request.displayName()).isEqualTo("Engineering");
	}

	@ParameterizedTest
	@NullSource
	@ValueSource(strings = { "", "-engineering", "engineering-", "Engineering", " engineering ",
			"engineering_team", "a b", "\u7ec4\u7ec7",
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" })
	void rejectsInvalidSlugs(String value) {
		assertThatThrownBy(() -> new CreateOrganizationRequest(value, "Engineering"))
			.isInstanceOfAny(NullPointerException.class, IllegalArgumentException.class);
	}

	@Test
	void acceptsTheMaximumSlugLength() {
		assertThat(new CreateOrganizationRequest("a".repeat(63), "Engineering").slug()).hasSize(63);
	}

	@ParameterizedTest
	@NullSource
	@ValueSource(strings = { "", "   " })
	void rejectsEmptyDisplayNames(String value) {
		assertThatThrownBy(() -> new CreateOrganizationRequest("engineering", value))
			.isInstanceOfAny(NullPointerException.class, IllegalArgumentException.class);
	}

	@Test
	void rejectsDisplayNamesOverTwoHundredCharacters() {
		assertThatThrownBy(() -> new CreateOrganizationRequest("engineering", "a".repeat(201)))
			.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void changesStatusIdempotently() {
		Organization active = organization(OrganizationStatus.ACTIVE);
		Instant disabledAt = CREATED_AT.plusSeconds(60);

		assertThat(active.activate(disabledAt)).isSameAs(active);

		Organization disabled = active.disable(disabledAt);
		assertThat(disabled.status()).isEqualTo(OrganizationStatus.DISABLED);
		assertThat(disabled.version()).isOne();
		assertThat(disabled.updatedAt()).isEqualTo(disabledAt);
		assertThat(disabled.disable(disabledAt.plusSeconds(60))).isSameAs(disabled);

		Organization reactivated = disabled.activate(disabledAt.plusSeconds(120));
		assertThat(reactivated.status()).isEqualTo(OrganizationStatus.ACTIVE);
		assertThat(reactivated.version()).isEqualTo(2);
	}

	@Test
	void preservesTenantOwnershipAcrossTransitions() {
		Organization active = organization(OrganizationStatus.ACTIVE);

		assertThat(active.disable(CREATED_AT.plusSeconds(1)).tenantId()).isEqualTo(TenantId.DEFAULT);
	}

	@Test
	void rejectsInvalidEntityState() {
		assertThatThrownBy(() -> new Organization(ORGANIZATION_ID, TenantId.DEFAULT, "engineering", "Engineering",
				OrganizationStatus.ACTIVE, -1, CREATED_AT, CREATED_AT)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> organization(OrganizationStatus.ACTIVE).disable(CREATED_AT.minusSeconds(1)))
			.isInstanceOf(IllegalArgumentException.class);
	}

	private Organization organization(OrganizationStatus status) {
		return new Organization(ORGANIZATION_ID, TenantId.DEFAULT, "engineering", "Engineering", status, 0,
				CREATED_AT, CREATED_AT);
	}

}
