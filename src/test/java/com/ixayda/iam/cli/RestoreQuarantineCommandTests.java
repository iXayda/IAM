package com.ixayda.iam.cli;

import java.io.Console;
import java.io.IOError;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;
import java.util.UUID;

import com.ixayda.iam.IamApplication;
import com.ixayda.iam.model.IdentityRestore;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.service.IdentityRestores;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class RestoreQuarantineCommandTests {

	@TempDir Path directory;

	@Test
	void confirmsTheTargetAndActualArchiveDigestAndAttributesOnlyACommittedQuarantine() throws Exception {
		var console = mock(Console.class); var restores = mock(IdentityRestores.class); var output = inputs(console, restores);
		String checksum = checksum(); var result = result(checksum);
		when(restores.quarantine(eq("iam_restore_test"), eq(checksum), any())).thenReturn(result);
		RestoreQuarantineCommand.execute(console, restores);
		var audit = ArgumentCaptor.forClass(SecurityAuditContext.class);
		verify(restores).quarantine(eq("iam_restore_test"), eq(checksum), audit.capture());
		assertThat(audit.getValue().actor()).isEqualTo("deployment:operator-1");
		assertThat(audit.getValue().source()).isEqualTo("deployment:restore:CHANGE-123");
		assertThat(output.toString()).contains("Restore quarantined: " + result.id(), "Audit gap: unresolved", "Keep IAM stopped", "Correlation: " + audit.getValue().correlationId());
	}

	@ParameterizedTest
	@ValueSource(strings = { "operator", "reference", "checksum", "cancel-checksum", "archive", "missing-archive", "directory", "confirmation", "io", "database", "backend" })
	void rejectsUnverifiedInputsAndSanitizesFailuresWithoutClaimingSuccess(String failure) throws Exception {
		var console = mock(Console.class); var restores = mock(IdentityRestores.class); var output = inputs(console, restores);
		switch (failure) {
			case "operator" -> when(console.readLine("Deployment operator: ")).thenReturn("untrusted operator");
			case "reference" -> when(console.readLine("Authorization reference: ")).thenReturn("x".repeat(33));
			case "checksum" -> when(console.readLine("Independently recorded archive SHA-256: ")).thenReturn("b".repeat(64));
			case "cancel-checksum" -> when(console.readLine("Independently recorded archive SHA-256: ")).thenReturn(null);
			case "archive" -> when(console.readLine("Verified local archive path: ")).thenReturn(null);
			case "missing-archive" -> when(console.readLine("Verified local archive path: ")).thenReturn(this.directory.resolve("absent.dump").toString());
			case "directory" -> when(console.readLine("Verified local archive path: ")).thenReturn(this.directory.toString());
			case "confirmation" -> when(console.readLine("Confirm by typing QUARANTINE:%s: ", "iam_restore_test")).thenReturn("no");
			case "io" -> when(console.readLine("Deployment operator: ")).thenThrow(new IOError(new IOException("private-terminal-details")));
			case "database" -> when(restores.databaseName()).thenThrow(new IllegalStateException("private-database-details"));
			case "backend" -> when(restores.quarantine(any(), any(), any())).thenThrow(new IllegalStateException("private-database-details"));
		}
		assertThatIllegalStateException().isThrownBy(() -> RestoreQuarantineCommand.execute(console, restores))
				.withMessageMatching("Restore quarantine was not confirmed; correlation: [0-9a-f-]{36}").withNoCause();
		assertThat(output.toString()).doesNotContain("Restore quarantined:", "private-database-details", "private-terminal-details");
		if (!failure.equals("backend")) { verify(restores, never()).quarantine(any(), any(), any()); }
	}

	@Test
	void outputFailureAfterCommitReportsCommittedStateAndNeverRepeatsTheOperation() throws Exception {
		var console = mock(Console.class); var restores = mock(IdentityRestores.class); inputs(console, restores);
		when(restores.quarantine(any(), any(), any())).thenReturn(result(checksum()));
		var writer = mock(PrintWriter.class); when(console.writer()).thenReturn(writer); when(writer.checkError()).thenReturn(false, false, true);
		assertThatIllegalStateException().isThrownBy(() -> RestoreQuarantineCommand.execute(console, restores))
				.withMessageMatching("Restore quarantine committed; terminal delivery was not confirmed; correlation: [0-9a-f-]{36}").withNoCause();
		verify(restores, times(1)).quarantine(any(), any(), any());
	}

	@Test
	void requiresAnInteractiveTerminalAndRejectsAdditionalArgumentsBeforeStartingSpring() {
		assertThatIllegalArgumentException().isThrownBy(() -> IamApplication.main(new String[] { "quarantine-restore", "--server.port=0" }));
		assertThat(System.console()).isNull();
		assertThatIllegalStateException().isThrownBy(() -> IamApplication.main(new String[] { "quarantine-restore" })).withMessageContaining("interactive terminal");
	}

	private StringWriter inputs(Console console, IdentityRestores restores) throws Exception {
		var output = new StringWriter(); var writer = new PrintWriter(output); when(console.writer()).thenReturn(writer);
		when(console.printf(anyString(), any(Object[].class))).thenAnswer(invocation -> {
			Object[] arguments = invocation.getArguments(); writer.printf((String) arguments[0], java.util.Arrays.copyOfRange(arguments, 1, arguments.length)); return console;
		});
		when(console.readLine("Deployment operator: ")).thenReturn("operator-1"); when(console.readLine("Authorization reference: ")).thenReturn("CHANGE-123");
		when(console.readLine("Independently recorded archive SHA-256: ")).thenReturn(checksum());
		Path archive = Files.writeString(this.directory.resolve("verified.dump"), "isolated archive fixture");
		when(console.readLine("Verified local archive path: ")).thenReturn(archive.toString());
		when(restores.databaseName()).thenReturn("iam_restore_test");
		when(console.readLine("Confirm by typing QUARANTINE:%s: ", "iam_restore_test")).thenReturn("QUARANTINE:iam_restore_test");
		return output;
	}

	private static String checksum() throws Exception { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest("isolated archive fixture".getBytes(java.nio.charset.StandardCharsets.UTF_8))); }
	private static IdentityRestore result(String checksum) { return new IdentityRestore(UUID.randomUUID(), checksum, "iam_restore_test", Instant.now(), 3, Instant.now(), UUID.randomUUID()); }
}
