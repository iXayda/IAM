package com.ixayda.iam.cli;

import java.io.Console;
import java.io.IOError;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import com.ixayda.iam.IamApplication;
import com.ixayda.iam.model.IdentityRestoreRelease;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.service.IdentityRestoreReleases;
import com.ixayda.iam.service.IdentityRestores;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class RestoreReleaseCommandTests {

	private final UUID restoreId = UUID.randomUUID();
	private final UUID userId = UUID.randomUUID();
	private final UUID keyId = UUID.randomUUID();
	private final Console console = mock(Console.class);
	private final IdentityRestores restores = mock(IdentityRestores.class);
	private final IdentityRestoreReleases releases = mock(IdentityRestoreReleases.class);
	private final char[] password = "violet lighthouse cedar river 827".toCharArray();
	private final char[] code = "123456".toCharArray();

	@Test
	void confirmsAllRecoveryIdentifiersAndReportsOnlyACommittedRelease() {
		var output = inputs();
		RestoreReleaseCommand.execute(this.console, this.restores, this.releases);
		var audit = ArgumentCaptor.forClass(SecurityAuditContext.class);
		verify(this.releases).release(eq("iam_restore_test"), eq(this.restoreId), eq(this.userId), eq(this.keyId), eq("violet lighthouse cedar river 827"), eq("123456"), audit.capture());
		assertThat(audit.getValue().actor()).isEqualTo("deployment:operator-2");
		assertThat(audit.getValue().source()).isEqualTo("deployment:restore-release:CHANGE-124");
		assertThat(output.toString()).contains("Restore released: " + this.restoreId, "Audit gap: unresolved", "Other users and applications remain disabled", audit.getValue().correlationId().toString());
		assertThat(output.toString()).doesNotContain("violet lighthouse cedar river 827", "123456");
		assertThat(this.password).containsOnly('\0'); assertThat(this.code).containsOnly('\0');
	}

	@ParameterizedTest
	@ValueSource(strings = { "operator", "reference", "restore", "user", "key", "confirmation", "cancel-password", "cancel-code", "io", "database", "backend", "rejected" })
	void invalidCancelledOrFailedReleaseNeverClaimsSuccessOrLeaksDetails(String failure) {
		var output = inputs();
		switch (failure) {
			case "operator" -> when(this.console.readLine("Deployment operator: ")).thenReturn("untrusted operator");
			case "reference" -> when(this.console.readLine("Authorization reference: ")).thenReturn(null);
			case "restore" -> when(this.console.readLine("Quarantine UUID from the independent recovery record: ")).thenReturn("1-1-1-1-1");
			case "user" -> when(this.console.readLine("Recovered administrator user UUID: ")).thenReturn(null);
			case "key" -> when(this.console.readLine("New signing key UUID: ")).thenReturn("not-a-key");
			case "confirmation" -> when(this.console.readLine("Confirm by typing RELEASE:%s:%s:%s:%s: ", "iam_restore_test", this.restoreId, this.userId, this.keyId)).thenReturn("no");
			case "cancel-password" -> when(this.console.readPassword("Current recovered password: ")).thenReturn(null);
			case "cancel-code" -> when(this.console.readPassword("Fresh authenticator code: ")).thenReturn(null);
			case "io" -> when(this.console.readLine("Deployment operator: ")).thenThrow(new IOError(new IOException("private-terminal-details")));
			case "database" -> when(this.restores.databaseName()).thenThrow(new IllegalStateException("private-database-details"));
			case "backend" -> when(this.releases.release(any(), any(), any(), any(), any(), any(), any())).thenThrow(new IllegalStateException("private-database-details"));
			case "rejected" -> when(this.releases.release(any(), any(), any(), any(), any(), any(), any())).thenReturn(Optional.empty());
		}
		assertThatIllegalStateException().isThrownBy(() -> RestoreReleaseCommand.execute(this.console, this.restores, this.releases))
				.withMessageMatching("Restore release was not confirmed; correlation: [0-9a-f-]{36}").withNoCause();
		assertThat(output.toString()).doesNotContain("Restore released: ", "private-terminal-details", "private-database-details");
		if (List.of("backend", "rejected").contains(failure)) { assertThat(this.password).containsOnly('\0'); assertThat(this.code).containsOnly('\0'); }
		else { verify(this.releases, never()).release(any(), any(), any(), any(), any(), any(), any()); }
	}

	@Test
	void outputFailureAfterCommitReportsCommittedReleaseWithoutRepeatingIt() {
		inputs(); var writer = mock(PrintWriter.class); when(this.console.writer()).thenReturn(writer);
		when(writer.checkError()).thenReturn(false, false, true);
		assertThatIllegalStateException().isThrownBy(() -> RestoreReleaseCommand.execute(this.console, this.restores, this.releases))
				.withMessageMatching("Restore release committed; terminal delivery was not confirmed; correlation: [0-9a-f-]{36}").withNoCause();
		verify(this.releases, times(1)).release(any(), any(), any(), any(), any(), any(), any());
		assertThat(this.password).containsOnly('\0'); assertThat(this.code).containsOnly('\0');
	}

	@Test
	void requiresInteractiveTerminalAndRejectsArgumentsBeforeStartingSpring() {
		assertThatIllegalArgumentException().isThrownBy(() -> IamApplication.main(new String[] { "release-restore", "--server.port=0" }));
		assertThat(System.console()).isNull();
		assertThatIllegalStateException().isThrownBy(() -> IamApplication.main(new String[] { "release-restore" })).withMessageContaining("interactive terminal");
	}

	private StringWriter inputs() {
		var output = new StringWriter(); var writer = new PrintWriter(output); when(this.console.writer()).thenReturn(writer);
		when(this.console.printf(anyString(), any(Object[].class))).thenAnswer(invocation -> {
			Object[] arguments = invocation.getArguments(); writer.printf((String) arguments[0], Arrays.copyOfRange(arguments, 1, arguments.length)); return this.console;
		});
		when(this.console.readLine("Deployment operator: ")).thenReturn("operator-2"); when(this.console.readLine("Authorization reference: ")).thenReturn("CHANGE-124");
		when(this.console.readLine("Quarantine UUID from the independent recovery record: ")).thenReturn(this.restoreId.toString());
		when(this.console.readLine("Recovered administrator user UUID: ")).thenReturn(this.userId.toString());
		when(this.console.readLine("New signing key UUID: ")).thenReturn(this.keyId.toString());
		when(this.restores.databaseName()).thenReturn("iam_restore_test");
		when(this.console.readLine("Confirm by typing RELEASE:%s:%s:%s:%s: ", "iam_restore_test", this.restoreId, this.userId, this.keyId)).thenReturn("RELEASE:iam_restore_test:" + this.restoreId + ":" + this.userId + ":" + this.keyId);
		when(this.console.readPassword("Current recovered password: ")).thenReturn(this.password); when(this.console.readPassword("Fresh authenticator code: ")).thenReturn(this.code);
		when(this.releases.release(any(), any(), any(), any(), any(), any(), any())).thenReturn(Optional.of(new IdentityRestoreRelease(this.restoreId, this.userId, UUID.randomUUID(), this.keyId, Instant.now())));
		return output;
	}
}
