package com.ixayda.iam.cli;

import java.io.Console;
import java.io.IOError;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.Writer;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import com.ixayda.iam.IamApplication;
import com.ixayda.iam.model.IdentityAdministratorSetup;
import com.ixayda.iam.model.IdentityTotpEnrollment;
import com.ixayda.iam.model.MfaRecoveryCodeSet;
import com.ixayda.iam.model.TotpAuthenticationContext;
import com.ixayda.iam.service.IdentityAdministrators;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class AdministratorBootstrapCommandTests {

	@Test
	void readsCredentialsWithoutEchoAndDisplaysOnlyCommittedRecoveryCodes() {
		var console = mock(Console.class); var administrators = mock(IdentityAdministrators.class);
		var output = new StringWriter();
		useWriter(console, new PrintWriter(output, true));
		UUID userId = UUID.randomUUID(); char[] password = "example password".toCharArray(); char[] code = "123456".toCharArray();
		when(console.readLine("User UUID (or new): ")).thenReturn(userId.toString());
		when(console.readPassword("Current password: ")).thenReturn(password);
		when(console.readPassword("Current TOTP code: ")).thenReturn(code);
		prepareExisting(administrators, userId);
		var codes = new MfaRecoveryCodeSet(userId, UUID.randomUUID(), UUID.randomUUID(), List.of("one-time-example"), Instant.now());
		when(administrators.bootstrap(eq(userId), isNull(), eq("example password"), eq("123456"), any(TotpAuthenticationContext.class)))
				.thenReturn(Optional.of(codes));
		AdministratorBootstrapCommand.execute(console, administrators);
		verify(console).printf("%s%n", "one-time-example");
		verify(console).printf("Administrator initialized: %s%nRecovery codes (store securely):%n", userId);
		assertThat(output.toString()).contains("one-time-example").doesNotContain("example password", "123456");
		assertThat(password).containsOnly('\0'); assertThat(code).containsOnly('\0');
	}

	@ParameterizedTest
	@ValueSource(strings = { "all", "partial", "flush" })
	void outputFailureReportsUnconfirmedDeliveryWithoutRepeatingInitialization(String failure) {
		var console = mock(Console.class); var administrators = mock(IdentityAdministrators.class);
		UUID userId = UUID.randomUUID(); char[] password = "example password".toCharArray(); char[] code = "123456".toCharArray();
		when(console.readLine("User UUID (or new): ")).thenReturn(userId.toString());
		when(console.readPassword("Current password: ")).thenReturn(password);
		when(console.readPassword("Current TOTP code: ")).thenReturn(code);
		prepareExisting(administrators, userId);
		var codes = List.of("first-recovery-code", "second-recovery-code", "third-recovery-code");
		when(administrators.bootstrap(eq(userId), isNull(), eq("example password"), eq("123456"), any()))
				.thenReturn(Optional.of(new MfaRecoveryCodeSet(userId, UUID.randomUUID(), UUID.randomUUID(), codes, Instant.now())));
		String header = "Administrator initialized: %s%nRecovery codes (store securely):%n".formatted(userId);
		int limit = failure.equals("all") ? 0 : failure.equals("partial")
				? header.length() + codes.getFirst().length() + System.lineSeparator().length() + 5 : Integer.MAX_VALUE;
		var output = new StringBuilder();
		var writer = new PrintWriter(new Writer() {
			@Override
			public void write(char[] characters, int offset, int length) throws IOException {
				int accepted = Math.min(length, limit - output.length());
				output.append(characters, offset, accepted);
				if (accepted < length) { throw new IOException("private-terminal-error"); }
			}

			@Override
			public void flush() throws IOException {
				if (failure.equals("flush")) { throw new IOException("private-terminal-error"); }
			}

			@Override
			public void close() { }
		}, true);
		useWriter(console, writer);
		assertThatIllegalStateException().isThrownBy(() -> AdministratorBootstrapCommand.execute(console, administrators))
				.withMessageMatching("Administrator initialized; recovery code delivery was not confirmed; correlation: [0-9a-f-]{36}")
				.withNoCause();
		assertThat(writer.checkError()).isTrue();
		if (failure.equals("all")) { assertThat(output).isEmpty(); }
		if (failure.equals("partial")) {
			assertThat(output.toString()).contains(codes.getFirst()).endsWith("secon").doesNotContain(codes.get(1), codes.get(2));
		}
		verify(administrators, times(1)).bootstrap(eq(userId), isNull(), eq("example password"), eq("123456"), any());
		verify(administrators).candidateId();
		verify(administrators).prepareCandidate(eq(userId), eq("example password"), any());
		verifyNoMoreInteractions(administrators);
		assertThat(password).containsOnly('\0'); assertThat(code).containsOnly('\0');
	}

	@ParameterizedTest
	@ValueSource(strings = { "denial", "exception", "cancel-password", "cancel-code", "invalid-user" })
	void failureNeverDisplaysSuccessSecretsOrTheUnderlyingStorageError(String failure) {
		var console = mock(Console.class); var administrators = mock(IdentityAdministrators.class);
		char[] password = "sensitive-input".toCharArray(); char[] code = "123456".toCharArray();
		when(console.readLine("User UUID (or new): ")).thenReturn(failure.equals("invalid-user") ? "invalid" : UUID.randomUUID().toString());
		when(console.readPassword("Current password: ")).thenReturn(failure.equals("cancel-password") ? null : password);
		when(console.readPassword("Current TOTP code: ")).thenReturn(failure.equals("cancel-code") ? null : code);
		when(administrators.prepareCandidate(any(), any(), any())).thenAnswer(invocation ->
				Optional.of(new IdentityAdministratorSetup(invocation.getArgument(0), Optional.empty())));
		when(administrators.bootstrap(any(), any(), any(), any(), any())).thenReturn(Optional.empty());
		if (failure.equals("exception")) {
			when(administrators.bootstrap(any(), any(), any(), any(), any())).thenThrow(new IllegalStateException("private-storage-detail"));
		}
		assertThatIllegalStateException().isThrownBy(() -> AdministratorBootstrapCommand.execute(console, administrators))
				.withMessageMatching("Administrator initialization was not confirmed; correlation: [0-9a-f-]{36}")
				.withNoCause();
		verify(console, never()).printf(anyString(), any(Object[].class));
		if (!failure.equals("invalid-user")) {
			if (!failure.equals("cancel-password")) { assertThat(password).containsOnly('\0'); }
			if (!failure.equals("cancel-password") && !failure.equals("cancel-code")) { assertThat(code).containsOnly('\0'); }
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "selection", "username", "display-name", "new-password", "confirmation", "password", "totp", "new-totp" })
	void terminalReadErrorsAreSanitizedWithoutGrantingAccessAndClearAcquiredInputs(String stage) {
		var console = mock(Console.class); var administrators = mock(IdentityAdministrators.class);
		var output = new StringWriter(); useWriter(console, new PrintWriter(output, true));
		UUID userId = UUID.randomUUID();
		boolean newAccount = List.of("username", "display-name", "new-password", "confirmation", "new-totp").contains(stage);
		char[] password = "sensitive-password".toCharArray(); char[] confirmation = password.clone();
		when(console.readLine("User UUID (or new): ")).thenReturn(newAccount ? "new" : userId.toString());
		when(console.readLine("Username: ")).thenReturn("alice");
		when(console.readLine("Display name: ")).thenReturn("Alice");
		when(console.readPassword("New password: ")).thenReturn(password);
		when(console.readPassword("Confirm password: ")).thenReturn(confirmation);
		when(console.readPassword("Current password: ")).thenReturn(password);
		when(administrators.createCandidate(eq("alice"), eq("Alice"), anyString(), any())).thenReturn(userId);
		prepareExisting(administrators, userId);
		var failure = new IOError(new IOException("private-terminal-detail"));
		switch (stage) {
			case "selection" -> when(console.readLine("User UUID (or new): ")).thenThrow(failure);
			case "username" -> when(console.readLine("Username: ")).thenThrow(failure);
			case "display-name" -> when(console.readLine("Display name: ")).thenThrow(failure);
			case "new-password" -> when(console.readPassword("New password: ")).thenThrow(failure);
			case "confirmation" -> when(console.readPassword("Confirm password: ")).thenThrow(failure);
			case "password" -> when(console.readPassword("Current password: ")).thenThrow(failure);
			default -> when(console.readPassword("Current TOTP code: ")).thenThrow(failure);
		}
		assertThatIllegalStateException().isThrownBy(() -> AdministratorBootstrapCommand.execute(console, administrators))
				.withMessageMatching("Administrator initialization was not confirmed; correlation: [0-9a-f-]{36}")
				.withNoCause();
		verify(administrators, never()).bootstrap(any(), any(), any(), any(), any());
		verify(administrators, never()).bootstrap(any(), any(), any(), any());
		assertThat(output.toString()).doesNotContain("Administrator initialized", "Recovery codes", "sensitive-password", "private-terminal-detail");
		if (List.of("confirmation", "totp", "new-totp").contains(stage)) { assertThat(password).containsOnly('\0'); }
		if (stage.equals("new-totp")) { assertThat(confirmation).containsOnly('\0'); }
	}

	@Test
	void unrelatedErrorsPropagateWhileAcquiredInputsAreStillCleared() {
		var console = mock(Console.class); var administrators = mock(IdentityAdministrators.class);
		UUID userId = UUID.randomUUID(); char[] password = "sensitive-password".toCharArray();
		when(console.readLine("User UUID (or new): ")).thenReturn(userId.toString());
		when(console.readPassword("Current password: ")).thenReturn(password);
		prepareExisting(administrators, userId);
		var fatal = new AssertionError("unrelated-error");
		when(console.readPassword("Current TOTP code: ")).thenThrow(fatal);
		assertThatThrownBy(() -> AdministratorBootstrapCommand.execute(console, administrators)).isSameAs(fatal);
		assertThat(password).containsOnly('\0');
		verify(administrators, never()).bootstrap(any(), any(), any(), any(), any());
	}

	@Test
	void aNewAccountUsesConfirmedPasswordAndDeliversThePendingFactorBeforeTheAtomicGrant() {
		var console = mock(Console.class); var administrators = mock(IdentityAdministrators.class);
		var output = new StringWriter(); useWriter(console, new PrintWriter(output, true));
		UUID userId = UUID.randomUUID(); UUID factorId = UUID.randomUUID();
		char[] password = "new example password".toCharArray(); char[] confirmation = password.clone(); char[] code = "123456".toCharArray();
		when(console.readLine("User UUID (or new): ")).thenReturn("new");
		when(console.readLine("Username: ")).thenReturn("alice");
		when(console.readLine("Display name: ")).thenReturn("Alice");
		when(console.readPassword("New password: ")).thenReturn(password);
		when(console.readPassword("Confirm password: ")).thenReturn(confirmation);
		when(console.readPassword("Current TOTP code: ")).thenReturn(code);
		when(administrators.createCandidate(eq("alice"), eq("Alice"), eq("new example password"), any())).thenReturn(userId);
		var enrollment = new IdentityTotpEnrollment(userId, factorId, "REGISTRATION-SECRET", "private-uri", Instant.now().plusSeconds(600));
		when(administrators.prepareCandidate(eq(userId), eq("new example password"), any()))
				.thenReturn(Optional.of(new IdentityAdministratorSetup(userId, Optional.of(enrollment))));
		when(administrators.bootstrap(eq(userId), eq(factorId), eq("new example password"), eq("123456"), any())).thenAnswer(invocation -> {
			assertThat(output.toString()).contains("REGISTRATION-SECRET").doesNotContain("committed-code");
			return Optional.of(new MfaRecoveryCodeSet(userId, factorId, UUID.randomUUID(), List.of("committed-code"), Instant.now()));
		});
		AdministratorBootstrapCommand.execute(console, administrators);
		assertThat(output.toString()).contains(userId.toString(), "committed-code").doesNotContain("new example password", "123456");
		assertThat(password).containsOnly('\0'); assertThat(confirmation).containsOnly('\0'); assertThat(code).containsOnly('\0');
	}

	@Test
	void interruptedPreparationIsResumedWithoutCreatingAnAdditionalAccount() {
		var console = mock(Console.class); var administrators = mock(IdentityAdministrators.class);
		var output = new StringWriter(); useWriter(console, new PrintWriter(output, true));
		UUID userId = UUID.randomUUID(); when(administrators.candidateId()).thenReturn(Optional.of(userId));
		when(console.readPassword("Current password: ")).thenReturn("example password".toCharArray());
		when(console.readPassword("Current TOTP code: ")).thenReturn("123456".toCharArray());
		prepareExisting(administrators, userId);
		when(administrators.bootstrap(eq(userId), isNull(), any(), any(), any())).thenReturn(Optional.of(
				new MfaRecoveryCodeSet(userId, UUID.randomUUID(), UUID.randomUUID(), List.of("committed-code"), Instant.now())));
		AdministratorBootstrapCommand.execute(console, administrators);
		verify(console, never()).readLine(anyString());
		verify(administrators, never()).createCandidate(any(), any(), any(), any());
		assertThat(output.toString()).contains("Resuming candidate: " + userId, "committed-code").doesNotContain("TOTP secret");
	}

	@ParameterizedTest
	@ValueSource(strings = { "mismatch", "cancel-password", "cancel-confirmation" })
	void unconfirmedNewPasswordDoesNotCreateAnAccount(String failure) {
		var console = mock(Console.class); var administrators = mock(IdentityAdministrators.class);
		char[] password = "new example password".toCharArray(); char[] confirmation = "different password".toCharArray();
		when(console.readLine("User UUID (or new): ")).thenReturn("new");
		when(console.readPassword("New password: ")).thenReturn(failure.equals("cancel-password") ? null : password);
		when(console.readPassword("Confirm password: ")).thenReturn(failure.equals("cancel-confirmation") ? null : confirmation);
		assertThatIllegalStateException().isThrownBy(() -> AdministratorBootstrapCommand.execute(console, administrators)).withNoCause();
		verify(administrators).candidateId(); verifyNoMoreInteractions(administrators);
		if (!failure.equals("cancel-password")) { assertThat(password).containsOnly('\0'); }
		if (!failure.equals("cancel-confirmation")) { assertThat(confirmation).containsOnly('\0'); }
	}

	@Test
	void enrollmentOutputFailureDoesNotReadTheCodeOrGrantAdministratorAccess() {
		var console = mock(Console.class); var administrators = mock(IdentityAdministrators.class);
		UUID userId = UUID.randomUUID(); char[] password = "example password".toCharArray();
		when(console.readLine("User UUID (or new): ")).thenReturn(userId.toString());
		when(console.readPassword("Current password: ")).thenReturn(password);
		var enrollment = new IdentityTotpEnrollment(userId, UUID.randomUUID(), "PRIVATE-SECRET", "private-uri", Instant.now());
		when(administrators.prepareCandidate(eq(userId), any(), any()))
				.thenReturn(Optional.of(new IdentityAdministratorSetup(userId, Optional.of(enrollment))));
		var writer = mock(PrintWriter.class); when(writer.checkError()).thenReturn(true); useWriter(console, writer);
		assertThatIllegalStateException().isThrownBy(() -> AdministratorBootstrapCommand.execute(console, administrators))
				.withMessageMatching("Administrator initialization was not confirmed; correlation: [0-9a-f-]{36}").withNoCause();
		verify(console, never()).readPassword("Current TOTP code: ");
		verify(administrators, never()).bootstrap(any(), any(), any(), any(), any());
		assertThat(password).containsOnly('\0');
	}

	@Test
	void rejectsCommandArgumentsBeforeStartingAnApplicationOrReadingSecrets() {
		assertThatIllegalArgumentException().isThrownBy(() -> AdministratorBootstrapCommand.run(IamApplication.class,
				new String[] { "bootstrap-admin", "--password=must-not-be-accepted" }))
				.withMessage("bootstrap-admin accepts no command arguments");
	}

	@Test
	void aNoninteractiveInvocationFailsBeforeOpeningTheDatabase() {
		assertThat(System.console()).isNull();
		assertThatIllegalStateException().isThrownBy(() -> IamApplication.main(new String[] { "bootstrap-admin" }))
				.withMessage("Administrator initialization requires an interactive terminal");
	}

	private static void prepareExisting(IdentityAdministrators administrators, UUID userId) {
		when(administrators.prepareCandidate(eq(userId), anyString(), any()))
				.thenReturn(Optional.of(new IdentityAdministratorSetup(userId, Optional.empty())));
	}

	private static void useWriter(Console console, PrintWriter writer) {
		when(console.writer()).thenReturn(writer);
		doAnswer(invocation -> {
			Object[] arguments = invocation.getArguments();
			writer.format((String) arguments[0], Arrays.copyOfRange(arguments, 1, arguments.length));
			return console;
		}).when(console).printf(anyString(), any(Object[].class));
	}

}
