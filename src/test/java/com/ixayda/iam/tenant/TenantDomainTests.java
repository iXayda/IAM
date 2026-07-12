package com.ixayda.iam.tenant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

class TenantDomainTests {

	private static final Instant CREATED_AT = Instant.parse("2026-01-01T00:00:00Z");

	@Test
	void usesUuidBackedTenantIds() {
		UUID value = UUID.fromString("019bc1e7-14d1-7d38-bd23-0877f2cd0cc1");

		assertThat(TenantId.from(value.toString())).isEqualTo(new TenantId(value));
		assertThat(TenantId.DEFAULT.toString()).isEqualTo("00000000-0000-0000-0000-000000000001");
		assertThat(TenantId.random().value()).isNotNull();
	}

	@Test
	void validatesTenantInputAndNormalizesTheDisplayName() {
		CreateTenantRequest request = new CreateTenantRequest("acme-cloud", "  Acme Cloud  ");

		assertThat(request.slug()).isEqualTo("acme-cloud");
		assertThat(request.displayName()).isEqualTo("Acme Cloud");
	}

	@ParameterizedTest
	@NullSource
	@ValueSource(strings = { "", "-acme", "acme-", "Acme", " acme ", "acme_cloud", "a b", "\u79df\u6237",
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" })
	void rejectsInvalidSlugs(String value) {
		assertThatThrownBy(() -> new CreateTenantRequest(value, "Acme")).isInstanceOfAny(NullPointerException.class,
				IllegalArgumentException.class);
	}

	@Test
	void acceptsTheMaximumSlugLength() {
		String slug = "a".repeat(63);

		assertThat(new CreateTenantRequest(slug, "Acme").slug()).hasSize(63);
	}

	@ParameterizedTest
	@NullSource
	@ValueSource(strings = { "", "   " })
	void rejectsEmptyDisplayNames(String value) {
		assertThatThrownBy(() -> new CreateTenantRequest("acme", value)).isInstanceOfAny(NullPointerException.class,
				IllegalArgumentException.class);
	}

	@Test
	void rejectsDisplayNamesOverTwoHundredCharacters() {
		assertThatThrownBy(() -> new CreateTenantRequest("acme", "a".repeat(201)))
			.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void changesStatusIdempotently() {
		Tenant active = tenant(TenantStatus.ACTIVE);
		Instant disabledAt = CREATED_AT.plusSeconds(60);

		assertThat(active.activate(disabledAt)).isSameAs(active);

		Tenant disabled = active.disable(disabledAt);
		assertThat(disabled.status()).isEqualTo(TenantStatus.DISABLED);
		assertThat(disabled.version()).isOne();
		assertThat(disabled.updatedAt()).isEqualTo(disabledAt);
		assertThat(disabled.disable(disabledAt.plusSeconds(60))).isSameAs(disabled);

		Tenant reactivated = disabled.activate(disabledAt.plusSeconds(120));
		assertThat(reactivated.status()).isEqualTo(TenantStatus.ACTIVE);
		assertThat(reactivated.version()).isEqualTo(2);
	}

	@Test
	void protectsTheBuiltInDefaultTenant() {
		Tenant defaultTenant = new Tenant(TenantId.DEFAULT, "default", "Default",
				TenantStatus.ACTIVE, 0, CREATED_AT, CREATED_AT);

		assertThat(defaultTenant.isBuiltInDefault()).isTrue();
		assertThat(defaultTenant.activate(CREATED_AT.plusSeconds(1))).isSameAs(defaultTenant);
		assertThatThrownBy(() -> defaultTenant.disable(CREATED_AT.plusSeconds(1)))
			.isInstanceOf(ProtectedTenantException.class);
		assertThatThrownBy(() -> new Tenant(TenantId.DEFAULT, "other", "Default",
				TenantStatus.ACTIVE, 0, CREATED_AT, CREATED_AT)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new Tenant(TenantId.DEFAULT, "default", "Default", TenantStatus.DISABLED, 0,
				CREATED_AT, CREATED_AT)).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void rejectsInvalidEntityState() {
		assertThatThrownBy(() -> new Tenant(TenantId.random(), "acme", "Acme",
				TenantStatus.ACTIVE, -1, CREATED_AT, CREATED_AT)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> tenant(TenantStatus.ACTIVE).disable(CREATED_AT.minusSeconds(1)))
			.isInstanceOf(IllegalArgumentException.class);
	}

	private Tenant tenant(TenantStatus status) {
		return new Tenant(new TenantId(UUID.fromString("019bc1e7-14d1-7d38-bd23-0877f2cd0cc1")),
				"acme", "Acme", status, 0, CREATED_AT, CREATED_AT);
	}

}
