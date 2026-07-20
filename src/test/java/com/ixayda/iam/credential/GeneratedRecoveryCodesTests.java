package com.ixayda.iam.credential;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class GeneratedRecoveryCodesTests {

	@Test
	void protectsAndDestroysTheWholeSet() {
		List<RecoveryCode> codes = codes();
		GeneratedRecoveryCodes generated = new GeneratedRecoveryCodes(codes);
		codes.forEach(RecoveryCode::close);

		char[][] copy = generated.copy();
		try {
			assertThat(copy.length).isEqualTo(GeneratedRecoveryCodes.CODE_COUNT);
			assertThat(copy[0]).containsExactly("00000-ABCDE-FGHJK-MNPQR".toCharArray());
			assertThat(generated.size()).isEqualTo(GeneratedRecoveryCodes.CODE_COUNT);
			assertThat(generated.toString()).contains("values=redacted").doesNotContain("00000-00000");
		}
		finally {
			for (char[] value : copy) {
				Arrays.fill(value, '\0');
			}
		}

		generated.close();
		generated.close();
		assertThat(generated.isDestroyed()).isTrue();
		assertThatThrownBy(generated::copy).isInstanceOf(IllegalStateException.class);
		assertThatThrownBy(generated::size).isInstanceOf(IllegalStateException.class);
	}

	@Test
	void rejectsWrongCountsAndDuplicateSelectors() {
		List<RecoveryCode> complete = codes();
		assertThatThrownBy(() -> new GeneratedRecoveryCodes(
				complete.subList(0, GeneratedRecoveryCodes.CODE_COUNT - 1)))
			.isInstanceOf(IllegalArgumentException.class);
		complete.forEach(RecoveryCode::close);

		List<RecoveryCode> duplicates = codes();
		RecoveryCode replaced = duplicates.get(1);
		duplicates.set(1, new RecoveryCode("00000-11111-11111-11111".toCharArray()));
		assertThatThrownBy(() -> new GeneratedRecoveryCodes(duplicates)).isInstanceOf(IllegalArgumentException.class);
		replaced.close();
		duplicates.forEach(RecoveryCode::close);
	}

	private static List<RecoveryCode> codes() {
		List<RecoveryCode> codes = new ArrayList<>();
		String[] selectors = { "00000", "11111", "22222", "33333", "44444", "55555", "66666", "77777",
				"88888", "99999" };
		for (String selector : selectors) {
			codes.add(new RecoveryCode((selector + "-ABCDE-FGHJK-MNPQR").toCharArray()));
		}
		return codes;
	}

}
