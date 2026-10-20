package com.ixayda.iam.service;

import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import com.ixayda.iam.IdentityProtocolTestSupport;
import com.ixayda.iam.credential.AuthorizationSecrets;
import com.ixayda.iam.model.IdentityAuthorizationInteraction;
import com.ixayda.iam.repository.IdentityAuthorizationProtectionRepository;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;

import static org.assertj.core.api.Assertions.*;

class IdentityAuthorizationProtectionIntegrationTests extends IdentityProtocolTestSupport {

	@Autowired IdentityAuthorizationProtection protection;
	@Autowired IdentityAuthorizationInteractions interactions;

	@Test
	void registeredProtectionRejectsAnotherWellFormedKeyEvenWithoutGrants() throws Exception {
		this.protection.requireCurrent();
		withWrongProtection(wrong -> assertThatIllegalStateException().isThrownBy(wrong::requireCurrent).withMessageContaining("does not match"));
		withWrongProtection(wrong -> assertThatIllegalStateException().isThrownBy(wrong::initializeForInstallation).withMessageContaining("does not match"));
		this.protection.requireCurrent();
	}

	@Test
	void installationIsIdempotentAndNeverReplacesThePinnedKey() {
		String first = this.protection.initializeForInstallation();
		String code = code(Set.of("openid")); exchange(request(code, authenticatedClient(code)));
		assertThat(this.protection.initializeForInstallation()).isEqualTo(first);
		assertThat(this.jdbc.sql("SELECT key_id FROM iam_authorization_protection").query(String.class).single()).isEqualTo(first);
	}

	@ParameterizedTest
	@ValueSource(booleans = { false, true })
	void firstRegistrationRejectsProtocolStateInsteadOfAdoptingIt(boolean interactionOnly) {
		UUID interactionId = null;
		if (interactionOnly) {
			var request = new IdentityAuthorizationInteraction.Request("https://iam.example/oauth2/authorize", this.clientId,
					"https://orders.example/callback", "original-state", Set.of("openid"),
					Map.of("code_challenge", "A".repeat(43), "code_challenge_method", "S256"));
			interactionId = this.interactions.create(this.interactions.newBrowserOwner(), request, 0).interaction().id();
		}
		else {
			String code = code(Set.of("openid", "offline_access"));
			exchange(request(code, authenticatedClient(code)));
		}
		String registered = this.jdbc.sql("SELECT key_id FROM iam_authorization_protection").query(String.class).single();
		String table = interactionOnly ? "iam_authorization_interaction" : "oauth2_authorization";
		var before = this.jdbc.sql("SELECT * FROM " + table).query().listOfRows();
		this.jdbc.sql("UPDATE iam_authorization_protection SET key_id=NULL").update();
		try {
			assertThatIllegalStateException().isThrownBy(this.protection::initializeForInstallation);
			assertThat(this.jdbc.sql("SELECT key_id IS NULL FROM iam_authorization_protection").query(Boolean.class).single()).isTrue();
			assertThat(this.jdbc.sql("SELECT * FROM " + table).query().listOfRows()).isEqualTo(before);
		}
		finally {
			this.jdbc.sql("UPDATE iam_authorization_protection SET key_id=:key").param("key", registered).update();
			if (interactionId != null) { this.jdbc.sql("DELETE FROM iam_authorization_interaction WHERE id=:id").param("id", interactionId).update(); }
		}
	}

	@Test
	void missingRegistrationFailsClosed() {
		this.jdbc.sql("UPDATE iam_authorization_protection SET key_id=NULL").update();
		try { assertThatIllegalStateException().isThrownBy(this.protection::requireCurrent).withMessageContaining("initialized"); }
		finally { this.protection.initializeForInstallation(); }
	}

	private void withWrongProtection(java.util.function.Consumer<IdentityAuthorizationProtection> action) throws Exception {
		var path = Files.createTempFile("iam-wrong-authorization-", ".key");
		byte[] bytes = new byte[64]; new SecureRandom().nextBytes(bytes); Files.write(path, bytes);
		try {
			try (var reloaded = new org.springframework.context.annotation.AnnotationConfigApplicationContext()) {
				reloaded.registerBean(AuthorizationSecrets.class, () -> new AuthorizationSecrets(path.toString()));
				reloaded.registerBean(org.springframework.jdbc.core.simple.JdbcClient.class, () -> this.jdbc);
				reloaded.registerBean(org.springframework.transaction.PlatformTransactionManager.class, () -> this.transactions);
				reloaded.register(IdentityAuthorizationProtectionRepository.class, IdentityAuthorizationProtection.class);
				reloaded.refresh(); action.accept(reloaded.getBean(IdentityAuthorizationProtection.class));
			}
		}
		finally { Files.deleteIfExists(path); java.util.Arrays.fill(bytes, (byte) 0); }
	}
}
