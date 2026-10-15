package com.ixayda.iam.model;

import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.*;

class SecurityAuditContextTests {

	@Test
	void preservesExplicitAttributionAndSupportsIdentifierLengthBoundaries() {
		UUID correlationId = UUID.randomUUID();
		SecurityAuditContext context = new SecurityAuditContext("system:iam.worker-1", "internal:identity", correlationId);
		assertThat(context.actor()).isEqualTo("system:iam.worker-1");
		assertThat(context.source()).isEqualTo("internal:identity");
		assertThat(context.correlationId()).isEqualTo(correlationId);
		assertThat(new SecurityAuditContext("a", "s", correlationId).actor()).isEqualTo("a");
		assertThat(new SecurityAuditContext("a".repeat(128), "s".repeat(64), correlationId).source()).hasSize(64);
	}

	@ParameterizedTest
	@NullAndEmptySource
	@ValueSource(strings = { " ", " system:iam", "system:iam ", "system:iam\n", "system\ractor", "system\u0000actor",
			"管理员", "actor';--", "-actor", "actor/name" })
	void rejectsMissingOrUnsafeActorIdentifiers(String actor) {
		assertThatIllegalArgumentException().isThrownBy(() -> new SecurityAuditContext(actor, "internal", UUID.randomUUID()));
	}

	@ParameterizedTest
	@NullAndEmptySource
	@ValueSource(strings = { " ", " internal", "internal ", "internal\n", "source\rname", "source\u0000name",
			"来源", "source';--", "-source", "source/name" })
	void rejectsMissingOrUnsafeSourceIdentifiers(String source) {
		assertThatIllegalArgumentException().isThrownBy(() -> new SecurityAuditContext("system:iam", source, UUID.randomUUID()));
	}

	@Test
	void rejectsOversizedIdentifiersAndMissingCorrelationIds() {
		assertThatIllegalArgumentException().isThrownBy(() -> new SecurityAuditContext("a".repeat(129), "internal", UUID.randomUUID()));
		assertThatIllegalArgumentException().isThrownBy(() -> new SecurityAuditContext("system:iam", "s".repeat(65), UUID.randomUUID()));
		assertThatIllegalArgumentException().isThrownBy(() -> new SecurityAuditContext("system:iam", "internal", null));
	}

}
