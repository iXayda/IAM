package com.ixayda.iam.cli;

import java.io.Console;
import java.io.IOError;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.Writer;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;

import com.ixayda.iam.IamApplication;
import com.ixayda.iam.model.IdentityAdministratorRecovery;
import com.ixayda.iam.model.IdentityTotpEnrollment;
import com.ixayda.iam.model.MfaRecoveryCodeSet;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.service.IdentityAdministratorRecoveries;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class AdministratorRecoveryCommandTests {

	@Test
	void deliversOnlyCommittedMaterialAndKeepsTheProofInProcess() {
		var console = mock(Console.class); var service = mock(IdentityAdministratorRecoveries.class);
		var output = new StringWriter(); useWriter(console, new PrintWriter(output, true));
		UUID userId = UUID.randomUUID(); var pending = pending(userId);
		char[] password = "private-password".toCharArray(); char[] code = "123456".toCharArray();
		inputs(console, userId, password, code);
		when(service.begin(eq(userId), eq("private-password"), any())).thenAnswer(invocation -> {
			assertThat(output.toString()).contains("notify the owner through a previously verified independent channel", "record delivery with this correlation")
					.doesNotContain("REGISTRATION-SECRET", "committed-recovery-code"); return Optional.of(pending);
		});
		when(service.complete(eq(userId), eq(pending.recoveryId()), eq(pending.token()), eq("private-password"), eq("123456"), any()))
				.thenAnswer(invocation -> {
					assertThat(output.toString()).contains("REGISTRATION-SECRET").doesNotContain("committed-recovery-code");
					return Optional.of(codeSet(userId));
				});
		AdministratorRecoveryCommand.execute(console, service);
		assertThat(output.toString()).contains("Administrator recovered: " + userId, "committed-recovery-code")
				.doesNotContain("private-password", "123456", pending.token(), pending.enrollment().provisioningUri());
		var audit = ArgumentCaptor.forClass(SecurityAuditContext.class);
		verify(service).begin(eq(userId), eq("private-password"), audit.capture());
		assertThat(output.toString()).contains("Administrator recovery correlation: " + audit.getValue().correlationId());
		assertThat(audit.getValue().actor()).isEqualTo("deployment:operator-1");
		assertThat(audit.getValue().source()).isEqualTo("deployment:admin-recovery:CHANGE-123");
		verify(service).complete(userId, pending.recoveryId(), pending.token(), "private-password", "123456", audit.getValue());
		assertThat(password).containsOnly('\0'); assertThat(code).containsOnly('\0');
	}

	@ParameterizedTest
	@ValueSource(strings = { "confirmation", "operator", "reference", "cancel-reference", "user", "short-user", "cancel-password", "preparation-denied", "preparation-error", "cancel-code", "completion-denied", "completion-error" })
	void rejectedOrCancelledOperationsDoNotShowSuccessAndNeverLeakStorageDetails(String failure) {
		var console = mock(Console.class); var service = mock(IdentityAdministratorRecoveries.class);
		var output = new StringWriter(); useWriter(console, new PrintWriter(output, true));
		UUID userId = UUID.randomUUID(); char[] password = "private-password".toCharArray(); char[] code = "123456".toCharArray();
		inputs(console, userId, password, code); var pending = pending(userId);
		when(service.begin(any(), any(), any())).thenReturn(Optional.of(pending));
		when(service.complete(any(), any(), any(), any(), any(), any())).thenReturn(Optional.empty());
		switch (failure) {
			case "confirmation" -> when(console.readLine("Service stopped and identity verified (type RECOVER): ")).thenReturn("no");
			case "operator" -> when(console.readLine("Deployment operator: ")).thenReturn("operator with spaces");
			case "reference" -> when(console.readLine("Authorization reference: ")).thenReturn("x".repeat(33));
			case "cancel-reference" -> when(console.readLine("Authorization reference: ")).thenReturn(null);
			case "user" -> when(console.readLine("Administrator user UUID: ")).thenReturn("invalid");
			case "short-user" -> when(console.readLine("Administrator user UUID: ")).thenReturn("1-1-1-1-1");
			case "cancel-password" -> when(console.readPassword("Current password: ")).thenReturn(null);
			case "preparation-denied" -> when(service.begin(any(), any(), any())).thenReturn(Optional.empty());
			case "preparation-error" -> when(service.begin(any(), any(), any())).thenThrow(new IllegalStateException("private-storage-error"));
			case "cancel-code" -> when(console.readPassword("New authenticator code: ")).thenReturn(null);
			case "completion-error" -> when(service.complete(any(), any(), any(), any(), any(), any())).thenThrow(new IllegalStateException("private-storage-error"));
			default -> { }
		}
		assertThatIllegalStateException().isThrownBy(() -> AdministratorRecoveryCommand.execute(console, service))
				.withMessageMatching("Administrator recovery was not confirmed; correlation: [0-9a-f-]{36}").withNoCause();
		assertThat(output.toString()).doesNotContain("Administrator recovered", "committed-recovery-code", "private-password", "123456", "private-storage-error", pending.token());
		if (List.of("confirmation", "operator", "reference", "cancel-reference", "user", "short-user", "cancel-password").contains(failure)) {
			verifyNoInteractions(service);
		}
		else { assertThat(password).containsOnly('\0'); }
		if (failure.startsWith("completion")) { assertThat(code).containsOnly('\0'); }
	}

	@ParameterizedTest
	@ValueSource(strings = { "confirmation", "operator", "reference", "user", "password", "code" })
	void terminalReadErrorsAreSanitizedAndAcquiredInputsAreCleared(String stage) {
		var console = mock(Console.class); var service = mock(IdentityAdministratorRecoveries.class);
		var output = new StringWriter(); useWriter(console, new PrintWriter(output, true));
		UUID userId = UUID.randomUUID(); char[] password = "private-password".toCharArray();
		inputs(console, userId, password, "123456".toCharArray());
		when(service.begin(any(), any(), any())).thenReturn(Optional.of(pending(userId)));
		var error = new IOError(new IOException("private-terminal-error"));
		switch (stage) {
			case "confirmation" -> when(console.readLine("Service stopped and identity verified (type RECOVER): ")).thenThrow(error);
			case "operator" -> when(console.readLine("Deployment operator: ")).thenThrow(error);
			case "reference" -> when(console.readLine("Authorization reference: ")).thenThrow(error);
			case "user" -> when(console.readLine("Administrator user UUID: ")).thenThrow(error);
			case "password" -> when(console.readPassword("Current password: ")).thenThrow(error);
			default -> when(console.readPassword("New authenticator code: ")).thenThrow(error);
		}
		assertThatIllegalStateException().isThrownBy(() -> AdministratorRecoveryCommand.execute(console, service))
				.withMessageMatching("Administrator recovery was not confirmed; correlation: [0-9a-f-]{36}").withNoCause();
		verify(service, never()).complete(any(), any(), any(), any(), any(), any());
		if (stage.equals("code")) { assertThat(password).containsOnly('\0'); }
		assertThat(output.toString()).doesNotContain("Administrator recovered", "private-terminal-error", "private-password");
	}

	@Test
	void secretOutputFailureLeavesOnlyACommittedPreparationAndDoesNotAttemptCompletion() {
		var console = mock(Console.class); var service = mock(IdentityAdministratorRecoveries.class);
		UUID userId = UUID.randomUUID(); char[] password = "private-password".toCharArray(); inputs(console, userId, password, "123456".toCharArray());
		var writer = mock(PrintWriter.class); when(console.writer()).thenReturn(writer); when(writer.checkError()).thenReturn(false, true);
		when(service.begin(eq(userId), any(), any())).thenReturn(Optional.of(pending(userId)));
		assertThatIllegalStateException().isThrownBy(() -> AdministratorRecoveryCommand.execute(console, service)).withNoCause();
		verify(console, never()).readPassword("New authenticator code: ");
		verify(service, never()).complete(any(), any(), any(), any(), any(), any());
		assertThat(password).containsOnly('\0');
	}

	@ParameterizedTest
	@ValueSource(strings = { "all", "partial", "flush", "io-error" })
	void finalDeliveryFailureReportsTheCommittedRecoveryWithoutRepeatingIt(String failure) {
		var console = mock(Console.class); var service = mock(IdentityAdministratorRecoveries.class);
		UUID userId = UUID.randomUUID(); char[] password = "private-password".toCharArray(); char[] code = "123456".toCharArray();
		inputs(console, userId, password, code); var pending = pending(userId);
		var failed = new AtomicBoolean(); var output = new StringBuilder(); var acceptedAfterCommit = new int[1];
		var writer = new PrintWriter(new Writer() {
			@Override
			public void write(char[] characters, int offset, int length) throws IOException {
				if (!failed.get()) { output.append(characters, offset, length); return; }
				if (failure.equals("io-error")) { throw new IOError(new IOException("private-terminal-error")); }
				int limit = failure.equals("all") ? 0 : failure.equals("partial") ? 7 : Integer.MAX_VALUE;
				int accepted = Math.min(length, limit - acceptedAfterCommit[0]); acceptedAfterCommit[0] += accepted;
				output.append(characters, offset, accepted);
				if (accepted < length) { throw new IOException("private-terminal-error"); }
			}
			@Override public void flush() throws IOException { if (failed.get() && failure.equals("flush")) { throw new IOException("private-terminal-error"); } }
			@Override public void close() { }
		}, true);
		useWriter(console, writer);
		when(service.begin(any(), any(), any())).thenReturn(Optional.of(pending));
		when(service.complete(any(), any(), any(), any(), any(), any())).thenAnswer(invocation -> {
			failed.set(true); return Optional.of(codeSet(userId));
		});
		assertThatIllegalStateException().isThrownBy(() -> AdministratorRecoveryCommand.execute(console, service))
				.withMessageMatching("Administrator recovered; recovery code delivery was not confirmed; correlation: [0-9a-f-]{36}").withNoCause();
		verify(service, times(1)).begin(any(), any(), any()); verify(service, times(1)).complete(any(), any(), any(), any(), any(), any());
		assertThat(password).containsOnly('\0'); assertThat(code).containsOnly('\0');
		assertThat(output.toString()).doesNotContain("private-password", pending.token(), "private-terminal-error");
	}

	@Test
	void unrelatedErrorsPropagateButStillClearAcquiredPasswordInput() {
		var console = mock(Console.class); var service = mock(IdentityAdministratorRecoveries.class);
		UUID userId = UUID.randomUUID(); char[] password = "private-password".toCharArray();
		inputs(console, userId, password, "123456".toCharArray()); useWriter(console, new PrintWriter(new StringWriter(), true));
		when(service.begin(any(), any(), any())).thenReturn(Optional.of(pending(userId)));
		var error = new AssertionError("unrelated-error"); when(console.readPassword("New authenticator code: ")).thenThrow(error);
		assertThatThrownBy(() -> AdministratorRecoveryCommand.execute(console, service)).isSameAs(error);
		assertThat(password).containsOnly('\0'); verify(service, never()).complete(any(), any(), any(), any(), any(), any());
	}

	@Test
	void commandDispatchRejectsAdditionalArgumentsBeforeStartingAnApplication() {
		assertThatIllegalArgumentException().isThrownBy(() -> IamApplication.main(new String[] { "recover-admin", "--server.port=0" }))
				.withMessage("recover-admin accepts no command arguments");
	}

	@Test
	void commandDispatchRequiresAnInteractiveTerminal() {
		assertThat(System.console()).isNull();
		assertThatIllegalStateException().isThrownBy(() -> IamApplication.main(new String[] { "recover-admin" }))
				.withMessage("Administrator recovery requires an interactive terminal");
	}

	private static void inputs(Console console, UUID userId, char[] password, char[] code) {
		when(console.readLine("Service stopped and identity verified (type RECOVER): ")).thenReturn("RECOVER");
		when(console.readLine("Deployment operator: ")).thenReturn("operator-1");
		when(console.readLine("Authorization reference: ")).thenReturn("CHANGE-123");
		when(console.readLine("Administrator user UUID: ")).thenReturn(userId.toString());
		when(console.readPassword("Current password: ")).thenReturn(password);
		when(console.readPassword("New authenticator code: ")).thenReturn(code);
	}

	private static IdentityAdministratorRecovery pending(UUID userId) {
		return new IdentityAdministratorRecovery(userId, UUID.randomUUID(), "in-process-proof",
				new IdentityTotpEnrollment(userId, UUID.randomUUID(), "REGISTRATION-SECRET", "secret-provisioning-uri", Instant.now().plusSeconds(600)));
	}

	private static MfaRecoveryCodeSet codeSet(UUID userId) {
		return new MfaRecoveryCodeSet(userId, UUID.randomUUID(), UUID.randomUUID(), List.of("committed-recovery-code"), Instant.now());
	}

	private static void useWriter(Console console, PrintWriter writer) {
		when(console.writer()).thenReturn(writer);
		when(console.printf(anyString(), any(Object[].class))).thenAnswer(invocation -> {
			Object[] arguments = invocation.getArguments();
			writer.format((String) arguments[0], java.util.Arrays.copyOfRange(arguments, 1, arguments.length)); return console;
		});
	}

}
