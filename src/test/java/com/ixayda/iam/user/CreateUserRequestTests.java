package com.ixayda.iam.user;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.Test;

class CreateUserRequestTests {

	@Test
	void requiresAtLeastOneUnambiguousIdentifier() {
		assertThatThrownBy(() -> new CreateUserRequest(null)).isInstanceOf(NullPointerException.class);
		assertThatThrownBy(() -> new CreateUserRequest(List.of())).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new CreateUserRequest(Collections.singletonList(null)))
			.isInstanceOf(NullPointerException.class);
		assertThatThrownBy(() -> new CreateUserRequest(
				List.of(LoginIdentifier.username("alice"), LoginIdentifier.username("alice-admin"))))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new CreateUserRequest(
				List.of(LoginIdentifier.username("15551234567"), LoginIdentifier.phone("+1 (555) 123-4567"))))
			.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void defensivelyCopiesIdentifiers() {
		List<LoginIdentifier> source = new ArrayList<>();
		source.add(LoginIdentifier.email("alice@example.com"));
		source.add(LoginIdentifier.username("alice"));
		CreateUserRequest request = new CreateUserRequest(source);

		source.add(LoginIdentifier.phone("15551234567"));

		assertThat(request.identifiers()).extracting(LoginIdentifier::type)
			.containsExactly(LoginIdentifierType.USERNAME, LoginIdentifierType.EMAIL);
		assertThatThrownBy(() -> request.identifiers().add(LoginIdentifier.phone("15551234567")))
			.isInstanceOf(UnsupportedOperationException.class);
	}

	@Test
	void keepsLoginValuesOutOfDiagnosticStrings() {
		LoginIdentifier email = LoginIdentifier.email("Alice@Example.COM");
		CreateUserRequest request = new CreateUserRequest(List.of(email));

		assertThat(request.toString()).doesNotContain(email.value(), email.canonicalValue());
	}

}
