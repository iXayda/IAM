package com.ixayda.iam;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

class IamApplicationArgumentsTests {

	@ParameterizedTest
	@ValueSource(strings = { "migarte", "initialize-signing-keys", "unknown", "" })
	void rejectsUnknownPositionalCommandBeforeApplicationStartup(String command) {
		assertThatIllegalArgumentException().isThrownBy(() -> IamApplication.main(new String[] { command }))
				.withMessageContaining("Unknown maintenance command");
	}

	@ParameterizedTest
	@ValueSource(strings = { "--server.port=0,migrate", "--server.port=0,unknown", "migrate,unknown", "--server.port=0,--,unknown" })
	void rejectsMisplacedPositionalArgumentsBeforeApplicationStartup(String arguments) {
		assertThatIllegalArgumentException().isThrownBy(() -> IamApplication.main(arguments.split(",")))
				.withMessageContaining("positional");
	}
}
