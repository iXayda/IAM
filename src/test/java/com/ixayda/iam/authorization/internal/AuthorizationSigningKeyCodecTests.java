package com.ixayda.iam.authorization.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataRetrievalFailureException;

class AuthorizationSigningKeyCodecTests {

	private static final String KEY = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";

	private static final String DIFFERENT_KEY = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=";

	private static final UUID SIGNING_KEY_ID = UUID.fromString("019cf2eb-c956-75e2-9cf1-9042aaa93001");

	private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");

	@Test
	void generatesProtectsAndRestoresAnRsa3072SigningKey() {
		AuthorizationSigningKeyCodec codec = codec();

		StoredAuthorizationSigningKey stored = codec.generateActive(NOW);
		RSAKey active = codec.restoreActive(stored);
		RSAKey published = codec.restorePublic(stored);

		assertThat(stored.signingKeyId()).isEqualTo(SIGNING_KEY_ID);
		assertThat(stored.kid()).matches("[A-Za-z0-9_-]{43}");
		assertThat(stored.publicModulus()).hasSize(384);
		assertThat(stored.publicExponent()).isEqualTo(65537);
		assertThat(stored.privateKey().initializationVector()).hasSize(12);
		assertThat(stored.privateKey().ciphertext()).hasSizeBetween(1024, 8192);
		assertThat(active.isPrivate()).isTrue();
		assertThat(active.size()).isEqualTo(3072);
		assertThat(active.getKeyID()).isEqualTo(stored.kid());
		assertThat(active.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);
		assertThat(active.getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
		assertThat(published.isPrivate()).isFalse();
		assertThat(published.getKeyID()).isEqualTo(active.getKeyID());
	}

	@Test
	void rejectsChangedStableIdentityOrEncryptedMaterial() {
		AuthorizationSigningKeyCodec codec = codec();
		StoredAuthorizationSigningKey stored = codec.generateActive(NOW);

		StoredAuthorizationSigningKey changedKid = copy(stored, "B".repeat(43), stored.publicModulus(),
				stored.privateKey());
		assertThatThrownBy(() -> codec.restoreActive(changedKid))
			.isInstanceOf(DataRetrievalFailureException.class);

		byte[] changedModulus = stored.publicModulus();
		changedModulus[10] ^= 1;
		StoredAuthorizationSigningKey changedPublicKey = copy(stored, stored.kid(), changedModulus,
				stored.privateKey());
		assertThatThrownBy(() -> codec.restoreActive(changedPublicKey))
			.isInstanceOf(DataRetrievalFailureException.class);

		byte[] changedCiphertext = stored.privateKey().ciphertext();
		changedCiphertext[0] ^= 1;
		AuthorizationSigningKeyCipher.ProtectedPrivateKey corrupted =
				new AuthorizationSigningKeyCipher.ProtectedPrivateKey(stored.privateKey().keyId(),
						stored.privateKey().initializationVector(), changedCiphertext);
		assertThatThrownBy(() -> codec.restoreActive(copy(stored, stored.kid(), stored.publicModulus(), corrupted)))
			.isInstanceOf(DataRetrievalFailureException.class);
	}

	@Test
	void rejectsPublicKeysAttestedWithUntrustedKeyMaterial() {
		AuthorizationSigningKeyProtectionProperties untrustedProperties =
				new AuthorizationSigningKeyProtectionProperties("v1", Map.of("v1", DIFFERENT_KEY));
		AuthorizationSigningKeyCodec untrustedCodec = codec(untrustedProperties,
				new AuthorizationSigningKeyAttestation(untrustedProperties));
		StoredAuthorizationSigningKey forged = untrustedCodec.generateActive(NOW);

		assertThatThrownBy(() -> codec().restorePublic(forged))
			.isInstanceOf(DataRetrievalFailureException.class)
			.hasMessage("Authorization signing-key attestation validation failed");
	}

	@Test
	void requiresHistoricalAttestationKeysToRemainAvailable() {
		StoredAuthorizationSigningKey stored = codec().generateActive(NOW);
		AuthorizationSigningKeyProtectionProperties currentProperties =
				new AuthorizationSigningKeyProtectionProperties("v2", Map.of("v2", DIFFERENT_KEY));
		AuthorizationSigningKeyCodec currentCodec = codec(currentProperties,
				new AuthorizationSigningKeyAttestation(currentProperties));

		assertThatThrownBy(() -> currentCodec.restorePublic(stored))
			.isInstanceOf(DataRetrievalFailureException.class)
			.hasMessage("Authorization signing-key attestation key is unavailable: v1");
	}

	@Test
	void rejectsChangedLifecycleMetadata() {
		AuthorizationSigningKeyCodec codec = codec();
		StoredAuthorizationSigningKey stored = codec.generateActive(NOW);

		StoredAuthorizationSigningKey changedVersion = copy(stored, stored.version() + 1, stored.updatedAt());
		assertThatThrownBy(() -> codec.restorePublic(changedVersion))
			.isInstanceOf(DataRetrievalFailureException.class)
			.hasMessage("Authorization signing-key attestation validation failed");

		StoredAuthorizationSigningKey changedUpdateTime = copy(stored, stored.version(),
				stored.updatedAt().plusSeconds(1));
		assertThatThrownBy(() -> codec.restorePublic(changedUpdateTime))
			.isInstanceOf(DataRetrievalFailureException.class)
			.hasMessage("Authorization signing-key attestation validation failed");
	}

	@Test
	void validatesPublicThumbprintsWithoutPrivateMaterial() {
		AuthorizationSigningKeyProtectionProperties properties = properties();
		AuthorizationSigningKeyAttestation attestation = new AuthorizationSigningKeyAttestation(properties);
		AuthorizationSigningKeyCodec codec = codec(properties, attestation);
		StoredAuthorizationSigningKey active = codec.generateActive(NOW);
		StoredAuthorizationSigningKey retiredCandidate = new StoredAuthorizationSigningKey(active.signingKeyId(),
				"C".repeat(43), active.publicModulus(), active.publicExponent(),
				StoredAuthorizationSigningKey.Status.RETIRED, null, null, NOW, NOW, NOW, NOW, NOW.plusSeconds(1),
				NOW.plusSeconds(3600), NOW.plusSeconds(1), 1, NOW.plusSeconds(1));
		StoredAuthorizationSigningKey retired =
				retiredCandidate.withAttestation(attestation.attest(retiredCandidate));

		assertThatThrownBy(() -> codec.restorePublic(retired))
			.isInstanceOf(DataRetrievalFailureException.class)
			.hasMessage("Authorization signing key thumbprint validation failed");
	}

	private static AuthorizationSigningKeyCodec codec() {
		AuthorizationSigningKeyProtectionProperties properties = properties();
		return codec(properties, new AuthorizationSigningKeyAttestation(properties));
	}

	private static AuthorizationSigningKeyCodec codec(AuthorizationSigningKeyProtectionProperties properties,
			AuthorizationSigningKeyAttestation attestation) {
		return new AuthorizationSigningKeyCodec(new AuthorizationSigningKeyCipher(properties), attestation,
				new SecureRandom(), () -> SIGNING_KEY_ID);
	}

	private static AuthorizationSigningKeyProtectionProperties properties() {
		return new AuthorizationSigningKeyProtectionProperties("v1", Map.of("v1", KEY));
	}

	private static StoredAuthorizationSigningKey copy(StoredAuthorizationSigningKey stored, String kid,
			byte[] publicModulus, AuthorizationSigningKeyCipher.ProtectedPrivateKey privateKey) {
		return new StoredAuthorizationSigningKey(stored.signingKeyId(), kid, publicModulus, stored.publicExponent(),
				stored.status(), stored.attestation(), privateKey, stored.createdAt(), stored.publishedAt(), stored.activateAfter(),
				stored.activatedAt(), stored.retiredAt(), stored.publishUntil(), stored.privateKeyDestroyedAt(),
				stored.version(), stored.updatedAt());
	}

	private static StoredAuthorizationSigningKey copy(StoredAuthorizationSigningKey stored, long version,
			Instant updatedAt) {
		return new StoredAuthorizationSigningKey(stored.signingKeyId(), stored.kid(), stored.publicModulus(),
				stored.publicExponent(), stored.status(), stored.attestation(), stored.privateKey(), stored.createdAt(),
				stored.publishedAt(), stored.activateAfter(), stored.activatedAt(), stored.retiredAt(),
				stored.publishUntil(), stored.privateKeyDestroyedAt(), version, updatedAt);
	}

}
