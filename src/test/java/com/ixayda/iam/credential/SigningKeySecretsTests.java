package com.ixayda.iam.credential;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.UUID;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.*;

class SigningKeySecretsTests {

	@TempDir Path directory;
	private static KeyPair pair;
	private static KeyPair other;

	@BeforeAll
	static void generateSigningFixtures() throws Exception {
		var generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(3072);
		pair = generator.generateKeyPair();
		other = generator.generateKeyPair();
	}

	@Test
	void encryptsWithRandomNoncesAndRestoresWithTheSameProtectionKeyAfterRestart() throws Exception {
		String file = keyFile("key");
		var secrets = new SigningKeySecrets(file);
		UUID id = UUID.randomUUID();
		byte[] encrypted = secrets.encrypt(id, pair.getPrivate());
		assertThat(encrypted).hasSizeBetween(1024, 4096).isNotEqualTo(secrets.encrypt(id, pair.getPrivate()));
		assertThat(encrypted[0]).isEqualTo((byte) 1);
		assertThat(Arrays.equals(encrypted, pair.getPrivate().getEncoded())).isFalse();
		var restarted = new SigningKeySecrets(file);
		var restored = restarted.restore(id, "RS256", pair.getPublic().getEncoded(), secrets.protectionKeyId(), encrypted);
		assertThat(restored.getPublic().getEncoded()).isEqualTo(pair.getPublic().getEncoded());
		assertThat(restored.getPrivate().getEncoded()).isEqualTo(pair.getPrivate().getEncoded());
		assertThat(restarted.protectionKeyId()).matches("[0-9a-f]{64}").isEqualTo(secrets.protectionKeyId());
	}

	@Test
	void generatesTheConfiguredRsaKeySizeAndPublicExponent() throws Exception {
		var secrets = new SigningKeySecrets(keyFile("key"));
		var generated = secrets.generate();
		var publicKey = (RSAPublicKey) generated.getPublic();
		assertThat(publicKey.getModulus().bitLength()).isEqualTo(3072);
		assertThat(publicKey.getPublicExponent()).isEqualTo(java.math.BigInteger.valueOf(65537));
		assertThat(publicKey.getEncoded()).isNotEqualTo(pair.getPublic().getEncoded());
	}

	@Test
	void rejectsOwnerSwapsProtectionKeySwapsAlgorithmChangesAndMismatchedPairs() throws Exception {
		var secrets = new SigningKeySecrets(keyFile("key"));
		var different = new SigningKeySecrets(keyFile("other"));
		UUID id = UUID.randomUUID();
		byte[] encrypted = secrets.encrypt(id, pair.getPrivate());
		assertThatIllegalStateException().isThrownBy(() -> secrets.restore(UUID.randomUUID(), "RS256", pair.getPublic().getEncoded(), secrets.protectionKeyId(), encrypted));
		assertThatIllegalStateException().isThrownBy(() -> different.restore(id, "RS256", pair.getPublic().getEncoded(), secrets.protectionKeyId(), encrypted));
		assertThatIllegalStateException().isThrownBy(() -> different.restore(id, "RS256", pair.getPublic().getEncoded(), different.protectionKeyId(), encrypted));
		assertThatIllegalStateException().isThrownBy(() -> secrets.restore(id, "RS512", pair.getPublic().getEncoded(), secrets.protectionKeyId(), encrypted));
		assertThatIllegalStateException().isThrownBy(() -> secrets.restore(id, "RS256", other.getPublic().getEncoded(), secrets.protectionKeyId(), encrypted))
				.withMessage("Persisted signing key pair does not match");
	}

	@ParameterizedTest
	@ValueSource(strings = { "nonce", "ciphertext", "tag", "version", "truncated", "oversized", "null" })
	void rejectsTamperedAndMalformedEnvelopes(String fault) throws Exception {
		var secrets = new SigningKeySecrets(keyFile("key"));
		UUID id = UUID.randomUUID();
		byte[] encrypted = secrets.encrypt(id, pair.getPrivate());
		byte[] invalid = switch (fault) {
			case "truncated" -> Arrays.copyOf(encrypted, 40);
			case "oversized" -> Arrays.copyOf(encrypted, 4097);
			case "null" -> null;
			default -> encrypted.clone();
		};
		if (invalid != null && !fault.equals("truncated") && !fault.equals("oversized")) {
			int index = switch (fault) { case "version" -> 0; case "nonce" -> 1; case "tag" -> invalid.length - 1; default -> 30; };
			invalid[index] ^= 1;
		}
		assertThatIllegalStateException().isThrownBy(() -> secrets.restore(id, "RS256", pair.getPublic().getEncoded(), secrets.protectionKeyId(), invalid));
	}

	@Test
	void publicKeyReadsDoNotRequirePrivateKeyConfiguration() throws Exception {
		var secrets = new SigningKeySecrets("");
		assertThat(secrets.isConfigured()).isFalse();
		assertThat(secrets.readPublicKey(pair.getPublic().getEncoded()).getEncoded()).isEqualTo(pair.getPublic().getEncoded());
		assertThatIllegalStateException().isThrownBy(secrets::requireConfigured);
		assertThatIllegalStateException().isThrownBy(secrets::generate);
		assertThatIllegalStateException().isThrownBy(secrets::protectionKeyId);
		assertThatIllegalStateException().isThrownBy(() -> secrets.encrypt(UUID.randomUUID(), pair.getPrivate()));
		assertThatIllegalStateException().isThrownBy(() -> secrets.restore(UUID.randomUUID(), "RS256", pair.getPublic().getEncoded(), "", new byte[1024]));
	}

	@Test
	void rejectsInvalidPublicKeysAndUnsupportedKeySizes() throws Exception {
		var secrets = new SigningKeySecrets(keyFile("key"));
		for (byte[] invalid : new byte[][] { null, new byte[0], new byte[1025], new byte[422] }) {
			assertThatIllegalStateException().isThrownBy(() -> secrets.readPublicKey(invalid));
		}
		var generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(2048);
		var small = generator.generateKeyPair();
		assertThatIllegalStateException().isThrownBy(() -> secrets.readPublicKey(small.getPublic().getEncoded()));
		assertThatIllegalArgumentException().isThrownBy(() -> secrets.encrypt(UUID.randomUUID(), small.getPrivate()));
	}

	@ParameterizedTest
	@ValueSource(ints = { 0, 16, 31, 33, 10000 })
	void rejectsProtectionFilesWithTheWrongLength(int size) throws Exception {
		Path path = this.directory.resolve("key");
		Files.write(path, new byte[size]);
		assertThatIllegalStateException().isThrownBy(() -> new SigningKeySecrets(path.toString()))
				.withMessage("Signing protection key file must contain exactly 32 raw bytes");
	}

	@Test
	void unreadableConfiguredProtectionFilesFailImmediately() {
		assertThatIllegalStateException().isThrownBy(() -> new SigningKeySecrets(this.directory.resolve("missing").toString()));
		assertThatIllegalStateException().isThrownBy(() -> new SigningKeySecrets(this.directory.toString()));
	}

	private String keyFile(String name) throws Exception {
		byte[] key = new byte[32];
		new SecureRandom().nextBytes(key);
		return Files.write(this.directory.resolve(name), key).toString();
	}

}
