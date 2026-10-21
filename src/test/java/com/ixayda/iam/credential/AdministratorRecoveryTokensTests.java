package com.ixayda.iam.credential;

import java.util.UUID;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.*;

class AdministratorRecoveryTokensTests {

	private final AdministratorRecoveryTokens tokens = new AdministratorRecoveryTokens();

	@Test
	void proofsHave256RandomBitsAndCanonicalUnpaddedEncoding() {
		assertThat(Stream.generate(this.tokens::generate).limit(100).toList()).doesNotHaveDuplicates()
				.allSatisfy(value -> assertThat(value).matches("[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]"));
	}

	@Test
	void digestsBindTheIdentityRecoveryAndPurpose() {
		UUID userId = UUID.randomUUID(); UUID recoveryId = UUID.randomUUID(); String token = this.tokens.generate();
		String digest = this.tokens.digest(userId, recoveryId, token);
		assertThat(digest).matches("[0-9a-f]{64}").isEqualTo(this.tokens.digest(userId, recoveryId, token))
				.isNotEqualTo(this.tokens.digest(UUID.randomUUID(), recoveryId, token))
				.isNotEqualTo(this.tokens.digest(userId, UUID.randomUUID(), token))
				.isNotEqualTo(this.tokens.credentialRecoveryDigest(userId, recoveryId, token))
				.isNotEqualTo(new TotpRecoveryTokens().digest(userId, recoveryId, token))
				.isNotEqualTo(new TotpReplacementTokens().digest(userId, recoveryId, token));
	}

	@Test
	void credentialRecoveryProofsBindTheirIdentityAndRecovery() {
		UUID userId = UUID.randomUUID(); UUID recoveryId = UUID.randomUUID(); String token = this.tokens.generate();
		assertThat(this.tokens.credentialRecoveryDigest(userId, recoveryId, token)).matches("[0-9a-f]{64}")
				.isEqualTo(this.tokens.credentialRecoveryDigest(userId, recoveryId, token))
				.isNotEqualTo(this.tokens.credentialRecoveryDigest(UUID.randomUUID(), recoveryId, token))
				.isNotEqualTo(this.tokens.credentialRecoveryDigest(userId, UUID.randomUUID(), token));
	}

	@ParameterizedTest
	@NullAndEmptySource
	@ValueSource(strings = { "invalid", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+" })
	void malformedOrNoncanonicalProofsCannotBeDigested(String token) {
		assertThatIllegalArgumentException().isThrownBy(() -> this.tokens.digest(UUID.randomUUID(), UUID.randomUUID(), token));
		assertThatIllegalArgumentException().isThrownBy(() -> this.tokens.credentialRecoveryDigest(UUID.randomUUID(), UUID.randomUUID(), token));
	}

}
