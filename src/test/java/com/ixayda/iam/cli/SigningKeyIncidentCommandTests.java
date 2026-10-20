package com.ixayda.iam.cli;

import java.io.Console;
import java.io.IOError;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import com.ixayda.iam.IamApplication;
import com.ixayda.iam.model.IdentitySigningKey;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.service.IdentitySigningKeyIncidents;
import com.ixayda.iam.service.IdentitySigningKeys;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class SigningKeyIncidentCommandTests {

	@ParameterizedTest
	@ValueSource(booleans = { false, true })
	void confirmedCommandsUseTheSelectedKeyAndAuthorizedOperatorAndReportOnlyCommittedResults(boolean recovery) {
		var console = mock(Console.class); var keys = mock(IdentitySigningKeys.class); var incidents = mock(IdentitySigningKeyIncidents.class);
		UUID id = UUID.randomUUID(); var output = inputs(console, id, recovery);
		when(keys.metadata()).thenReturn(List.of()); var next = new IdentitySigningKey(UUID.randomUUID(), "RS256", mock(java.security.interfaces.RSAPublicKey.class), Instant.now());
		when(keys.recover(eq(id), any())).thenReturn(next); when(incidents.compromise(eq(id), any())).thenReturn(4);
		SigningKeyIncidentCommand.execute(console, keys, incidents, recovery);
		var audit = ArgumentCaptor.forClass(SecurityAuditContext.class);
		if (recovery) { verify(keys).recover(eq(id), audit.capture()); verifyNoInteractions(incidents); assertThat(output.toString()).contains("Replacement signing key created: " + next.id()); }
		else { verify(incidents).compromise(eq(id), audit.capture()); verify(keys, never()).recover(any(), any()); assertThat(output.toString()).contains("Signing key compromised: " + id, "authorizations revoked: 4"); }
		assertThat(audit.getValue().actor()).isEqualTo("deployment:operator-1");
		assertThat(audit.getValue().source()).isEqualTo("deployment:signing-incident:CHANGE-123");
		assertThat(output.toString()).contains("Signing key incident correlation: " + audit.getValue().correlationId());
		verify(keys, never()).initialize(); verify(keys, never()).signingMaterial();
	}

	@ParameterizedTest
	@ValueSource(strings = { "operator", "reference", "cancel", "invalid-id", "short-id", "read-io", "confirmation", "metadata", "backend" })
	void invalidCancelledAndFailedCommandsCannotDiscloseStorageDetailsOrReportSuccess(String failure) {
		var console = mock(Console.class); var keys = mock(IdentitySigningKeys.class); var incidents = mock(IdentitySigningKeyIncidents.class);
		UUID id = UUID.randomUUID(); var output = inputs(console, id, false);
		when(keys.metadata()).thenReturn(List.of()); when(incidents.compromise(any(), any())).thenThrow(new IllegalStateException("private-backend-details"));
		switch (failure) {
			case "operator" -> when(console.readLine("Deployment operator: ")).thenReturn("not an identifier");
			case "reference" -> when(console.readLine("Authorization reference: ")).thenReturn("x".repeat(33));
			case "cancel" -> when(console.readLine("Affected signing key UUID: ")).thenReturn(null);
			case "invalid-id" -> when(console.readLine("Affected signing key UUID: ")).thenReturn("invalid");
			case "short-id" -> when(console.readLine("Affected signing key UUID: ")).thenReturn("1-1-1-1-1");
			case "read-io" -> when(console.readLine("Affected signing key UUID: ")).thenThrow(new IOError(new IOException("private-terminal-details")));
			case "confirmation" -> when(console.readLine("Confirm by typing %s:%s: ", "COMPROMISE", id)).thenReturn("no");
			case "metadata" -> when(keys.metadata()).thenThrow(new IllegalStateException("private-backend-details"));
			default -> { }
		}
		assertThatIllegalStateException().isThrownBy(() -> SigningKeyIncidentCommand.execute(console, keys, incidents, false))
				.withMessageMatching("Signing key incident action was not confirmed; correlation: [0-9a-f-]{36}").withNoCause();
		assertThat(output.toString()).doesNotContain("Signing key compromised:", "Replacement signing key created:", "private-backend-details", "private-terminal-details");
		if (!failure.equals("backend")) { verifyNoInteractions(incidents); }
		verify(keys, never()).recover(any(), any());
	}

	@ParameterizedTest
	@ValueSource(booleans = { false, true })
	void terminalFailureAfterCommitReportsACommittedActionAndDoesNotRepeatIt(boolean recovery) {
		var console = mock(Console.class); var keys = mock(IdentitySigningKeys.class); var incidents = mock(IdentitySigningKeyIncidents.class);
		UUID id = UUID.randomUUID(); inputs(console, id, recovery); when(keys.metadata()).thenReturn(List.of());
		var writer = mock(PrintWriter.class); when(console.writer()).thenReturn(writer); when(writer.checkError()).thenReturn(false, false, true);
		when(keys.recover(any(), any())).thenReturn(new IdentitySigningKey(UUID.randomUUID(), "RS256", mock(java.security.interfaces.RSAPublicKey.class), Instant.now()));
		assertThatIllegalStateException().isThrownBy(() -> SigningKeyIncidentCommand.execute(console, keys, incidents, recovery))
				.withMessageMatching("Signing key incident action committed; terminal delivery was not confirmed; correlation: [0-9a-f-]{36}").withNoCause();
		if (recovery) { verify(keys, times(1)).recover(any(), any()); }
		else { verify(incidents, times(1)).compromise(any(), any()); }
	}

	@ParameterizedTest
	@ValueSource(strings = { "compromise-signing-key", "recover-signing-key" })
	void dispatchRequiresAProtectedTerminalAndRejectsAdditionalArgumentsBeforeStartingTheApplication(String command) {
		assertThatIllegalArgumentException().isThrownBy(() -> IamApplication.main(new String[] { command, "--server.port=0" }));
		assertThat(System.console()).isNull();
		assertThatIllegalStateException().isThrownBy(() -> IamApplication.main(new String[] { command })).withMessage("Signing key incident commands require an interactive terminal");
	}

	private static StringWriter inputs(Console console, UUID id, boolean recovery) {
		var output = new StringWriter(); var writer = new PrintWriter(output, true); when(console.writer()).thenReturn(writer);
		when(console.printf(anyString(), any(Object[].class))).thenAnswer(invocation -> {
			Object[] arguments = invocation.getArguments(); writer.format((String) arguments[0], java.util.Arrays.copyOfRange(arguments, 1, arguments.length)); return console;
		});
		when(console.readLine("Deployment operator: ")).thenReturn("operator-1"); when(console.readLine("Authorization reference: ")).thenReturn("CHANGE-123");
		when(console.readLine("Affected signing key UUID: ")).thenReturn(id.toString()); String action = recovery ? "RECOVER" : "COMPROMISE";
		when(console.readLine("Confirm by typing %s:%s: ", action, id)).thenReturn(action + ":" + id); return output;
	}
}
