package com.ixayda.iam.user;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;

import com.ixayda.iam.tenant.TenantId;
import org.junit.jupiter.api.Test;

class UserExternalIdentityTests {

	private static final ExternalIdentityProviderId PROVIDER_ID =
			ExternalIdentityProviderId.from("corporate");

	private static final ExternalSubjectId SUBJECT_ID =
			ExternalSubjectId.from("8d86b38a-9e5e-4d4d-a08d-9cb9086a5932");

	private static final UserId USER_ID = UserId.from("019bc1e7-14d1-7d38-bd23-0877f2cd0e72");

	private static final Instant LINKED_AT = Instant.parse("2026-01-01T00:00:00Z");

	@Test
	void retainsItsCompositeIdentityAndOwner() {
		UserExternalIdentity identity = identity();

		assertThat(identity.tenantId()).isEqualTo(TenantId.DEFAULT);
		assertThat(identity.providerId()).isEqualTo(PROVIDER_ID);
		assertThat(identity.subjectId()).isEqualTo(SUBJECT_ID);
		assertThat(identity.userId()).isEqualTo(USER_ID);
		assertThat(identity.linkedAt()).isEqualTo(LINKED_AT);
	}

	@Test
	void rejectsIncompleteStoredState() {
		assertThatThrownBy(() -> new UserExternalIdentity(null, PROVIDER_ID, SUBJECT_ID, USER_ID, LINKED_AT))
			.isInstanceOf(NullPointerException.class);
		assertThatThrownBy(() -> new UserExternalIdentity(TenantId.DEFAULT, null, SUBJECT_ID, USER_ID, LINKED_AT))
			.isInstanceOf(NullPointerException.class);
		assertThatThrownBy(() -> new UserExternalIdentity(TenantId.DEFAULT, PROVIDER_ID, null, USER_ID, LINKED_AT))
			.isInstanceOf(NullPointerException.class);
		assertThatThrownBy(() -> new UserExternalIdentity(TenantId.DEFAULT, PROVIDER_ID, SUBJECT_ID, null, LINKED_AT))
			.isInstanceOf(NullPointerException.class);
		assertThatThrownBy(() -> new UserExternalIdentity(TenantId.DEFAULT, PROVIDER_ID, SUBJECT_ID, USER_ID, null))
			.isInstanceOf(NullPointerException.class);
	}

	@Test
	void usesValueEqualityWithoutExposingTheSubjectInDiagnostics() {
		UserExternalIdentity identity = identity();

		assertThat(identity).isEqualTo(identity()).hasSameHashCodeAs(identity());
		assertThat(identity)
			.isNotEqualTo(new UserExternalIdentity(TenantId.DEFAULT, PROVIDER_ID,
					ExternalSubjectId.from("another-subject"), USER_ID, LINKED_AT));
		assertThat(identity.toString()).contains("providerId=corporate", "subjectId=redacted")
			.doesNotContain(SUBJECT_ID.value());
	}

	private UserExternalIdentity identity() {
		return new UserExternalIdentity(TenantId.DEFAULT, PROVIDER_ID, SUBJECT_ID, USER_ID, LINKED_AT);
	}

}
