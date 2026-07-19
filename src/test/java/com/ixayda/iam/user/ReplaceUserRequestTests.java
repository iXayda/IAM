package com.ixayda.iam.user;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ReplaceUserRequestTests {

	@Test
	void validatesAndDefensivelyCopiesReplacementValues() {
		List<LoginIdentifier> source = new ArrayList<>();
		source.add(LoginIdentifier.username("alice"));

		ReplaceUserRequest request = new ReplaceUserRequest(source, UserProfile.empty(), null);
		source.add(LoginIdentifier.email("alice@example.com"));

		assertThat(request.identifiers()).containsExactly(LoginIdentifier.username("alice"));
		assertThat(request.toString()).doesNotContain("alice");
		assertThat(request.toString()).contains("identifierCount=1", "activeSpecified=false");
		assertThatThrownBy(() -> new ReplaceUserRequest(List.of(), UserProfile.empty(), true))
			.isInstanceOf(IllegalArgumentException.class);
	}

}
