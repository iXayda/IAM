package com.ixayda.iam.credential;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.*;

class TotpSecretsTests {

	@TempDir
	Path directory;

	@Test
	void protectsSecretsWithRandomNoncesAndDecryptsAfterRestartWithTheSameKeyFile() throws Exception {
		String path = keyFile("key");
		var secrets = new TotpSecrets(path);
		UUID user = UUID.randomUUID();
		UUID factor = UUID.randomUUID();
		byte[] secret = secrets.generate();
		assertThat(secret).hasSize(20).isNotEqualTo(secrets.generate());
		String encrypted = secrets.encrypt(user, factor, secret);
		assertThat(encrypted).hasSize(67).startsWith("v1.").isNotEqualTo(secrets.encrypt(user, factor, secret));
		assertThat(encrypted).doesNotContain(Base64.getEncoder().encodeToString(secret));
		var restarted = new TotpSecrets(path);
		assertThat(restarted.keyId()).isEqualTo(secrets.keyId());
		assertThat(restarted.decrypt(user, factor, secrets.keyId(), encrypted)).isEqualTo(secret);
	}

	@Test
	void rejectsTamperingOwnerSwapsFactorSwapsWrongKeysAndMalformedEnvelopes() throws Exception {
		var secrets = new TotpSecrets(keyFile("key"));
		UUID user = UUID.randomUUID();
		UUID factor = UUID.randomUUID();
		String encrypted = secrets.encrypt(user, factor, secrets.generate());
		assertThatIllegalStateException().isThrownBy(() -> secrets.decrypt(UUID.randomUUID(), factor, secrets.keyId(), encrypted));
		assertThatIllegalStateException().isThrownBy(() -> secrets.decrypt(user, UUID.randomUUID(), secrets.keyId(), encrypted));
		var other = new TotpSecrets(keyFile("other"));
		assertThatIllegalStateException().isThrownBy(() -> other.decrypt(user, factor, secrets.keyId(), encrypted));
		assertThatIllegalStateException().isThrownBy(() -> other.decrypt(user, factor, other.keyId(), encrypted));
		String tampered = encrypted.substring(0, 3) + (encrypted.charAt(3) == 'A' ? "B" : "A") + encrypted.substring(4);
		assertThatIllegalStateException().isThrownBy(() -> secrets.decrypt(user, factor, secrets.keyId(), tampered));
		for (String invalid : new String[] { null, "", "v2." + encrypted.substring(3), encrypted + "=", "v1." + "!".repeat(64) }) {
			assertThatIllegalStateException().isThrownBy(() -> secrets.decrypt(user, factor, secrets.keyId(), invalid));
		}
	}

	@ParameterizedTest
	@ValueSource(ints = { 0, 16, 31, 33, 10000 })
	void rejectsConfiguredFilesThatAreNotExactlyAnAes256Key(int size) throws Exception {
		Path key = this.directory.resolve("key");
		Files.write(key, new byte[size]);
		assertThatIllegalStateException().isThrownBy(() -> new TotpSecrets(key.toString()))
				.withMessage("TOTP key file must contain exactly 32 raw bytes");
	}

	@Test
	void missingConfigurationDisablesFactorOperationsAndUnreadableConfigurationFails() throws Exception {
		var unconfigured = new TotpSecrets("");
		assertThatIllegalStateException().isThrownBy(unconfigured::requireConfigured);
		assertThatIllegalStateException().isThrownBy(unconfigured::generate);
		assertThatIllegalStateException().isThrownBy(unconfigured::keyId);
		assertThatIllegalStateException().isThrownBy(() -> new TotpSecrets(this.directory.resolve("missing").toString()));
		var configured = new TotpSecrets(keyFile("key"));
		assertThatIllegalArgumentException().isThrownBy(() -> configured.encrypt(UUID.randomUUID(), UUID.randomUUID(), new byte[19]));
	}

	private String keyFile(String name) throws Exception {
		byte[] bytes = new byte[32];
		new SecureRandom().nextBytes(bytes);
		Path path = this.directory.resolve(name);
		Files.write(path, bytes);
		return path.toString();
	}

}
