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
import com.ixayda.iam.model.IdentityTotpEnrollment;
import com.ixayda.iam.model.MfaRecoveryCodeSet;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.service.IdentityRestoreAdministrators;
import com.ixayda.iam.service.IdentityRestores;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class RestoreAdministratorCommandTests {

	private final UUID restoreId = UUID.randomUUID();
	private final UUID userId = UUID.randomUUID();
	private final UUID factorId = UUID.randomUUID();
	private final Console console = mock(Console.class);
	private final IdentityRestores restores = mock(IdentityRestores.class);
	private final IdentityRestoreAdministrators administrators = mock(IdentityRestoreAdministrators.class);
	private final char[] password = "violet lighthouse cedar river 827".toCharArray();
	private final char[] confirmation = this.password.clone();
	private final char[] code = "123456".toCharArray();

	@Test
	void confirmsExistingIdentityAttributesBothTransactionsAndDeliversOnlyCommittedRecoveryCodes() {
		var output = inputs();
		RestoreAdministratorCommand.execute(this.console, this.restores, this.administrators);
		var audit = ArgumentCaptor.forClass(SecurityAuditContext.class);
		verify(this.administrators).prepare(eq("iam_restore_test"), eq(this.restoreId), eq(this.userId), eq("violet lighthouse cedar river 827"), audit.capture());
		assertThat(audit.getValue().actor()).isEqualTo("deployment:operator-1");
		assertThat(audit.getValue().source()).isEqualTo("deployment:restore-admin:CHANGE-123");
		verify(this.administrators).complete("iam_restore_test", this.restoreId, this.userId, this.factorId, "violet lighthouse cedar river 827", "123456", audit.getValue());
		assertThat(output.toString()).contains("Restored administrator: " + this.userId, "recovery-code-fixture", "IAM remains quarantined", "independent second-person approval", audit.getValue().correlationId().toString());
		assertThat(output.toString()).doesNotContain("violet lighthouse cedar river 827", "123456");
		assertCleared(this.password); assertCleared(this.confirmation); assertCleared(this.code);
	}

	@ParameterizedTest
	@ValueSource(strings = { "operator", "reference", "cancel-restore", "restore", "user", "confirmation", "password", "cancel-password", "io", "database", "prepare", "cancel-code", "rejected", "complete" })
	void invalidCancelledAndFailedInputsNeverClaimRecoveryOrRevealBackendDetails(String failure) {
		var output = inputs();
		switch (failure) {
			case "operator" -> when(this.console.readLine("Deployment operator: ")).thenReturn("operator:extra");
			case "reference" -> when(this.console.readLine("Authorization reference: ")).thenReturn("x".repeat(33));
			case "cancel-restore" -> when(this.console.readLine("Quarantine UUID from the independent recovery record: ")).thenReturn(null);
			case "restore" -> when(this.console.readLine("Quarantine UUID from the independent recovery record: ")).thenReturn("1-1-1-1-1");
			case "user" -> when(this.console.readLine("Verified existing user UUID: ")).thenReturn("not-a-user");
			case "confirmation" -> when(this.console.readLine("Confirm by typing RECOVER:%s:%s:%s: ", "iam_restore_test", this.restoreId, this.userId)).thenReturn("no");
			case "password" -> when(this.console.readPassword("Confirm new password: ")).thenReturn("different".toCharArray());
			case "cancel-password" -> when(this.console.readPassword("New password: ")).thenReturn(null);
			case "io" -> when(this.console.readLine("Deployment operator: ")).thenThrow(new IOError(new IOException("private-terminal-details")));
			case "database" -> when(this.restores.databaseName()).thenThrow(new IllegalStateException("private-database-details"));
			case "prepare" -> when(this.administrators.prepare(any(), any(), any(), any(), any())).thenThrow(new IllegalStateException("private-database-details"));
			case "cancel-code" -> when(this.console.readPassword("New authenticator code: ")).thenReturn(null);
			case "rejected" -> when(this.administrators.complete(any(), any(), any(), any(), any(), any(), any())).thenReturn(Optional.empty());
			case "complete" -> when(this.administrators.complete(any(), any(), any(), any(), any(), any(), any())).thenThrow(new IllegalStateException("private-database-details"));
		}
		assertThatIllegalStateException().isThrownBy(() -> RestoreAdministratorCommand.execute(this.console, this.restores, this.administrators))
				.withMessageMatching("Restored administrator was not confirmed; pending preparation may remain; correlation: [0-9a-f-]{36}").withNoCause();
		assertThat(output.toString()).doesNotContain("Restored administrator: ", "recovery-code-fixture", "private-database-details", "private-terminal-details");
		if (List.of("prepare", "cancel-code", "rejected", "complete").contains(failure)) { assertCleared(this.password); assertCleared(this.confirmation); }
		if (List.of("rejected", "complete").contains(failure)) { assertCleared(this.code); }
		if (!List.of("rejected", "complete").contains(failure)) { verify(this.administrators, never()).complete(any(), any(), any(), any(), any(), any(), any()); }
	}

	@Test
	void preparationOutputFailureLeavesNoMembershipAndReportsPossiblePendingPreparation() {
		inputs(); var writer = mock(PrintWriter.class); when(this.console.writer()).thenReturn(writer);
		when(writer.checkError()).thenReturn(false, false, true);
		assertThatIllegalStateException().isThrownBy(() -> RestoreAdministratorCommand.execute(this.console, this.restores, this.administrators)).withMessageContaining("pending preparation may remain").withNoCause();
		verify(this.administrators).prepare(any(), any(), any(), any(), any());
		verify(this.administrators, never()).complete(any(), any(), any(), any(), any(), any(), any());
		assertCleared(this.password); assertCleared(this.confirmation);
	}

	@Test
	void outputFailureAfterCompletionReportsCommittedQualificationAndNeverRepeatsIt() {
		inputs(); var writer = mock(PrintWriter.class); when(this.console.writer()).thenReturn(writer);
		when(writer.checkError()).thenReturn(false, false, false, true);
		assertThatIllegalStateException().isThrownBy(() -> RestoreAdministratorCommand.execute(this.console, this.restores, this.administrators))
				.withMessageMatching("Restored administrator committed; recovery code delivery was not confirmed; correlation: [0-9a-f-]{36}").withNoCause();
		verify(this.administrators, times(1)).complete(any(), any(), any(), any(), any(), any(), any());
		assertCleared(this.password); assertCleared(this.confirmation); assertCleared(this.code);
	}

	@Test
	void requiresInteractiveTerminalAndRejectsArgumentsBeforeStartingSpring() {
		assertThatIllegalArgumentException().isThrownBy(() -> IamApplication.main(new String[] { "recover-restored-admin", "--server.port=0" }));
		assertThat(System.console()).isNull();
		assertThatIllegalStateException().isThrownBy(() -> IamApplication.main(new String[] { "recover-restored-admin" })).withMessageContaining("interactive terminal");
	}

	private StringWriter inputs() {
		var output = new StringWriter(); var writer = new PrintWriter(output); when(this.console.writer()).thenReturn(writer);
		when(this.console.printf(anyString(), any(Object[].class))).thenAnswer(invocation -> {
			Object[] arguments = invocation.getArguments(); writer.printf((String) arguments[0], Arrays.copyOfRange(arguments, 1, arguments.length)); return this.console;
		});
		when(this.console.readLine("Deployment operator: ")).thenReturn("operator-1"); when(this.console.readLine("Authorization reference: ")).thenReturn("CHANGE-123");
		when(this.console.readLine("Quarantine UUID from the independent recovery record: ")).thenReturn(this.restoreId.toString());
		when(this.console.readLine("Verified existing user UUID: ")).thenReturn(this.userId.toString());
		when(this.restores.databaseName()).thenReturn("iam_restore_test");
		when(this.console.readLine("Confirm by typing RECOVER:%s:%s:%s: ", "iam_restore_test", this.restoreId, this.userId)).thenReturn("RECOVER:iam_restore_test:" + this.restoreId + ":" + this.userId);
		when(this.console.readPassword("New password: ")).thenReturn(this.password); when(this.console.readPassword("Confirm new password: ")).thenReturn(this.confirmation);
		when(this.console.readPassword("New authenticator code: ")).thenReturn(this.code);
		when(this.administrators.prepare(any(), any(), any(), any(), any())).thenReturn(new IdentityTotpEnrollment(this.userId, this.factorId, "secret-fixture", "otpauth://fixture", Instant.now().plusSeconds(600)));
		when(this.administrators.complete(any(), any(), any(), any(), any(), any(), any())).thenReturn(Optional.of(new MfaRecoveryCodeSet(this.userId, this.factorId, UUID.randomUUID(), List.of("recovery-code-fixture"), Instant.now())));
		return output;
	}

	private static void assertCleared(char[] value) { assertThat(value).containsOnly('\0'); }
}
