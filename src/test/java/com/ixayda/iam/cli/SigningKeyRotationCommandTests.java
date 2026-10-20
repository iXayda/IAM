package com.ixayda.iam.cli;

import java.io.Console;
import java.io.IOError;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import com.ixayda.iam.IamApplication;
import com.ixayda.iam.model.IdentitySigningKey;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.service.IdentitySigningKeys;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class SigningKeyRotationCommandTests {

	@Test
	void confirmsTheExpectedCurrentKeyAndRecordsTheAuthorizedOperatorBeforeReportingCommittedSuccess() {
		var console = mock(Console.class); var keys = mock(IdentitySigningKeys.class);
		var current = key(); var next = key(); var output = new StringWriter(); inputs(console, current.id(), output);
		when(keys.findPublicKey()).thenReturn(Optional.of(current));
		when(keys.rotate(eq(current.id()), any())).thenAnswer(invocation -> {
			assertThat(output.toString()).contains("Current signing key: " + current.id()).doesNotContain("Signing key rotated:"); return next;
		});
		SigningKeyRotationCommand.execute(console, keys);
		var context = ArgumentCaptor.forClass(SecurityAuditContext.class); verify(keys).rotate(eq(current.id()), context.capture());
		assertThat(context.getValue().actor()).isEqualTo("deployment:operator-1");
		assertThat(context.getValue().source()).isEqualTo("deployment:signing-rotation:CHANGE-123");
		assertThat(output.toString()).contains("Signing key rotation correlation: " + context.getValue().correlationId(),
				"Signing key rotated: " + next.id(), "Previous public key retained for 330 seconds: " + current.id());
		verify(keys, never()).initialize(); verify(keys, never()).signingMaterial();
	}

	@ParameterizedTest
	@ValueSource(strings = { "operator", "reference", "cancel", "operator-io", "missing", "selection", "read-io", "backend" })
	void cancelledInvalidAndFailedOperationsDoNotReportSuccessOrDiscloseBackendDetails(String failure) {
		var console = mock(Console.class); var keys = mock(IdentitySigningKeys.class); var current = key();
		var output = new StringWriter(); inputs(console, current.id(), output);
		when(keys.findPublicKey()).thenReturn(Optional.of(current));
		when(keys.rotate(any(), any())).thenThrow(new IllegalStateException("private-backend-detail"));
		switch (failure) {
			case "operator" -> when(console.readLine("Deployment operator: ")).thenReturn("bad operator");
			case "reference" -> when(console.readLine("Authorization reference: ")).thenReturn("x".repeat(33));
			case "cancel" -> when(console.readLine("Authorization reference: ")).thenReturn(null);
			case "operator-io" -> when(console.readLine("Deployment operator: ")).thenThrow(new IOError(new IOException("private-terminal-detail")));
			case "missing" -> when(keys.findPublicKey()).thenReturn(Optional.empty());
			case "selection" -> when(console.readLine("Confirm rotation by entering the current key UUID: ")).thenReturn(UUID.randomUUID().toString());
			case "read-io" -> when(console.readLine("Confirm rotation by entering the current key UUID: ")).thenThrow(new IOError(new IOException("private-terminal-detail")));
			default -> { }
		}
		assertThatIllegalStateException().isThrownBy(() -> SigningKeyRotationCommand.execute(console, keys))
				.withMessageMatching("Signing key rotation was not confirmed; correlation: [0-9a-f-]{36}").withNoCause();
		if (!failure.equals("backend")) { verify(keys, never()).rotate(any(), any()); }
		assertThat(output.toString()).doesNotContain("Signing key rotated:", "private-backend-detail", "private-terminal-detail");
	}

	@ParameterizedTest
	@ValueSource(strings = { "initial", "current", "committed" })
	void terminalOutputFailuresDistinguishUnconfirmedOperationsFromCommittedRotation(String stage) {
		var console = mock(Console.class); var keys = mock(IdentitySigningKeys.class); var current = key();
		inputs(console, current.id(), new StringWriter());
		when(keys.findPublicKey()).thenReturn(Optional.of(current)); when(keys.rotate(any(), any())).thenReturn(key());
		var writer = mock(PrintWriter.class); when(console.writer()).thenReturn(writer);
		if (stage.equals("initial")) { when(writer.checkError()).thenReturn(true); }
		else if (stage.equals("current")) { when(writer.checkError()).thenReturn(false, true); }
		else { when(writer.checkError()).thenReturn(false, false, true); }
		String expected = stage.equals("committed") ? "Signing key rotated; terminal delivery was not confirmed; correlation: [0-9a-f-]{36}"
				: "Signing key rotation was not confirmed; correlation: [0-9a-f-]{36}";
		assertThatIllegalStateException().isThrownBy(() -> SigningKeyRotationCommand.execute(console, keys)).withMessageMatching(expected).withNoCause();
		verify(keys, times(stage.equals("committed") ? 1 : 0)).rotate(any(), any());
	}

	@Test
	void dispatchRequiresAnInteractiveTerminalAndRejectsAdditionalArgumentsBeforeApplicationStartup() {
		assertThatIllegalArgumentException().isThrownBy(() -> IamApplication.main(new String[] { "rotate-signing-key", "--server.port=0" }));
		assertThatIllegalArgumentException().isThrownBy(() -> SigningKeyRotationCommand.run(IamApplication.class, new String[] { "wrong-command" }));
		assertThat(System.console()).isNull();
		assertThatIllegalStateException().isThrownBy(() -> IamApplication.main(new String[] { "rotate-signing-key" }))
				.withMessage("Signing key rotation requires an interactive terminal");
	}

	private static void inputs(Console console, UUID current, StringWriter output) {
		var writer = new PrintWriter(output, true); when(console.writer()).thenReturn(writer);
		when(console.printf(anyString(), any(Object[].class))).thenAnswer(invocation -> {
			Object[] arguments = invocation.getArguments(); writer.format((String) arguments[0], java.util.Arrays.copyOfRange(arguments, 1, arguments.length)); return console;
		});
		when(console.readLine("Deployment operator: ")).thenReturn("operator-1");
		when(console.readLine("Authorization reference: ")).thenReturn("CHANGE-123");
		when(console.readLine("Confirm rotation by entering the current key UUID: ")).thenReturn(current.toString());
	}

	private static IdentitySigningKey key() { return new IdentitySigningKey(UUID.randomUUID(), "RS256", mock(java.security.interfaces.RSAPublicKey.class), Instant.now()); }
}
