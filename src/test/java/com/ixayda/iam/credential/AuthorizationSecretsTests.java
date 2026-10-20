package com.ixayda.iam.credential;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.*;

class AuthorizationSecretsTests {

	private static final String BINDING = "f".repeat(64);

	@TempDir Path directory;

	@Test
	void randomizedEncryptionAuthenticatesTheAuthorizationAndColumnAndNeverFallsBackToPlaintext() throws Exception {
		var secrets = new AuthorizationSecrets(key(64).toString());
		UUID id = UUID.randomUUID();
		String value = "protected protocol value 😀";
		String first = secrets.encrypt(id, "attributes", BINDING, value);
		String second = secrets.encrypt(id, "attributes", BINDING, value);
		assertThat(first).startsWith("enc:v1:").doesNotContain(value).isNotEqualTo(second);
		assertThat(secrets.decrypt(id, "attributes", BINDING, first)).isEqualTo(value);
		assertThat(secrets.decrypt(id, "attributes", BINDING, second)).isEqualTo(value);
		assertThatThrownBy(() -> secrets.decrypt(UUID.randomUUID(), "attributes", BINDING, first)).isInstanceOf(IllegalStateException.class);
		assertThatThrownBy(() -> secrets.decrypt(id, "state", BINDING, first)).isInstanceOf(IllegalStateException.class);
		assertThatThrownBy(() -> secrets.decrypt(id, "attributes", "0".repeat(64), first)).isInstanceOf(IllegalStateException.class);
		assertThatThrownBy(() -> secrets.decrypt(id, "attributes", BINDING, value)).isInstanceOf(IllegalStateException.class).hasMessageNotContaining(value);
		assertThatThrownBy(() -> new AuthorizationSecrets(key(64).toString()).decrypt(id, "attributes", BINDING, first)).isInstanceOf(IllegalStateException.class);
	}

	@Test
	void lookupUsesAStableIndependentKeyAndEncryptionSurvivesReload() throws Exception {
		Path path = key(64);
		var secrets = new AuthorizationSecrets(path.toString());
		var reloaded = new AuthorizationSecrets(path.toString());
		UUID id = UUID.randomUUID();
		String value = "random-token";
		assertThat(reloaded.decrypt(id, "access_token_value", BINDING, secrets.encrypt(id, "access_token_value", BINDING, value))).isEqualTo(value);
		assertThat(secrets.digest(value)).matches("[0-9a-f]{64}").isEqualTo(reloaded.digest(value));
		assertThat(secrets.digest(value)).isNotEqualTo(secrets.digest(" " + value));
		byte[] changed = Files.readAllBytes(path); changed[0] ^= 1;
		Path encryptionChanged = this.directory.resolve("encryption-changed"); Files.write(encryptionChanged, changed);
		assertThat(new AuthorizationSecrets(encryptionChanged.toString()).digest(value)).isEqualTo(secrets.digest(value));
		changed[32] ^= 1;
		Path lookupChanged = this.directory.resolve("lookup-changed"); Files.write(lookupChanged, changed);
		assertThat(new AuthorizationSecrets(lookupChanged.toString()).digest(value)).isNotEqualTo(secrets.digest(value));
	}

	@Test
	void refreshDigestsAndHistorySealsUseDistinctPurposesAndSurviveKeyReload() throws Exception {
		Path path = key(64); var secrets = new AuthorizationSecrets(path.toString()); var reloaded = new AuthorizationSecrets(path.toString());
		String value = "refresh-proof-original-value";
		String digest = secrets.refreshDigest(value); String seal = secrets.refreshHistorySeal(value);
		assertThat(digest).matches("[0-9a-f]{64}").isEqualTo(reloaded.refreshDigest(value)).isNotEqualTo(secrets.digest(value)).isNotEqualTo(seal);
		assertThat(secrets.verifiesRefreshHistory(value, seal)).isTrue(); assertThat(reloaded.verifiesRefreshHistory(value, seal)).isTrue();
		assertThat(secrets.verifiesRefreshHistory(value + "changed", seal)).isFalse();
		assertThat(secrets.verifiesRefreshHistory(value, digest)).isFalse(); assertThat(secrets.verifiesRefreshHistory(value, null)).isFalse();
		assertThat(secrets.verifiesRefreshHistory(value, "invalid-seal")).isFalse();
		assertThat(new AuthorizationSecrets(key(64).toString()).verifiesRefreshHistory(value, seal)).isFalse();
		assertThat(digest + seal).doesNotContain(value);
	}

	@Test
	void refreshProtectionCannotOperateWithMissingKeysOrUnboundedInputs() throws Exception {
		var absent = new AuthorizationSecrets("");
		assertThatThrownBy(() -> absent.refreshDigest("token")).isInstanceOf(IllegalStateException.class);
		assertThatThrownBy(() -> absent.refreshHistorySeal("history")).isInstanceOf(IllegalStateException.class);
		var secrets = new AuthorizationSecrets(key(64).toString());
		assertThatThrownBy(() -> secrets.refreshDigest("x".repeat(16_385))).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> secrets.refreshHistorySeal("x".repeat(4097))).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> secrets.refreshDigest("\ud800")).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> secrets.refreshHistorySeal("\ud800")).isInstanceOf(IllegalArgumentException.class);
	}

	@ParameterizedTest
	@ValueSource(ints = { 0, 32, 63, 65, 1024 })
	void filesMustContainBothCompleteIndependentKeys(int bytes) throws Exception {
		assertThatThrownBy(() -> new AuthorizationSecrets(key(bytes).toString())).isInstanceOf(IllegalStateException.class);
	}

	@Test
	void absentKeysAndOversizedValuesCannotBeUsed() throws Exception {
		var absent = new AuthorizationSecrets("");
		assertThatThrownBy(absent::requireConfigured).isInstanceOf(IllegalStateException.class);
		assertThatThrownBy(() -> absent.digest("token")).isInstanceOf(IllegalStateException.class);
		var secrets = new AuthorizationSecrets(key(64).toString());
		UUID id = UUID.randomUUID();
		String value = "x".repeat(65_536);
		assertThat(secrets.decrypt(id, "attributes", BINDING, secrets.encrypt(id, "attributes", BINDING, value))).isEqualTo(value);
		assertThatThrownBy(() -> secrets.encrypt(id, "attributes", BINDING, value + "x")).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> secrets.encrypt(id, "attributes", BINDING, "\ud800")).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> secrets.digest("x".repeat(16_385))).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> secrets.digest("\ud800")).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> secrets.decrypt(id, "attributes", BINDING, "x".repeat(131_073))).isInstanceOf(IllegalStateException.class);
	}

	@Test
	void truncatedAlteredAndNoncanonicalEnvelopesAreRejected() throws Exception {
		var secrets = new AuthorizationSecrets(key(64).toString());
		UUID id = UUID.randomUUID();
		String value = secrets.encrypt(id, "refresh_token_value", BINDING, "secret-token");
		int start = value.lastIndexOf(':') + 1;
		String changed = value.substring(0, start + 4) + (value.charAt(start + 4) == 'A' ? "B" : "A") + value.substring(start + 5);
		for (String invalid : java.util.List.of(value.substring(0, value.length() - 3), changed, value + "=", value.substring(0, start) + "AA", value.replace("enc:v1:", "enc:v2:"))) {
			assertThatThrownBy(() -> secrets.decrypt(id, "refresh_token_value", BINDING, invalid)).isInstanceOf(IllegalStateException.class).hasMessageNotContaining("secret-token");
		}
	}

	private Path key(int length) throws Exception {
		byte[] bytes = new byte[length]; new SecureRandom().nextBytes(bytes);
		Path path = this.directory.resolve(UUID.randomUUID().toString()); Files.write(path, bytes); return path;
	}

}
