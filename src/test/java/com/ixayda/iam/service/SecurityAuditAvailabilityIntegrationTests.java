package com.ixayda.iam.service;

import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import com.ixayda.iam.PostgreSqlTestConfiguration;
import com.ixayda.iam.model.SecurityAuditContext;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import static org.assertj.core.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
@Import(PostgreSqlTestConfiguration.class)
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_CLASS)
class SecurityAuditAvailabilityIntegrationTests {

	private static final SecurityAuditContext AUDIT = new SecurityAuditContext("system:audit-health-test", "internal:test", UUID.randomUUID());
	@Autowired IdentityUsers users;
	@Autowired SecurityAudits audits;
	@Autowired JdbcClient jdbc;
	@Autowired PlatformTransactionManager transactions;

	@BeforeEach
	void establishHealthyCommittedAuditState() {
		removeFault(); this.jdbc.sql("DELETE FROM iam_security_audit").update(); this.jdbc.sql("DELETE FROM iam_user").update();
		this.users.create("baseline", "Baseline", AUDIT); assertThat(this.audits.isAvailable()).isTrue();
	}

	@AfterEach
	void removeFault() {
		this.jdbc.sql("DROP TRIGGER IF EXISTS audit_availability_fault ON iam_security_audit").update();
		this.jdbc.sql("DROP FUNCTION IF EXISTS audit_availability_fault()").update();
	}

	@ParameterizedTest
	@ValueSource(strings = { "error", "skip", "tamper", "deferred" })
	void writeFailuresRemainDegradedUntilAGenuineAuditSuccessfullyCommits(String fault) {
		fault(fault);
		assertThatThrownBy(() -> this.users.create("rejected", "Rejected", AUDIT)).isInstanceOf(RuntimeException.class);
		removeFault();
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_user WHERE username='rejected'").query(Long.class).single()).isZero();
		assertThat(this.audits.isAvailable()).isFalse();
		long before = count(); for (int i = 0; i < 3; i++) { assertThat(this.audits.isAvailable()).isFalse(); } assertThat(count()).isEqualTo(before);
		new TransactionTemplate(this.transactions).executeWithoutResult(status -> {
			this.users.create("rolledback", "Rolled Back", AUDIT); status.setRollbackOnly();
		});
		assertThat(this.audits.isAvailable()).isFalse();
		this.users.create("recovered", "Recovered", AUDIT); assertThat(this.audits.isAvailable()).isTrue(); assertThat(count()).isEqualTo(before + 1);
	}

	@Test
	void ordinaryBusinessRollbackDoesNotReportAnAuditOutage() {
		new TransactionTemplate(this.transactions).executeWithoutResult(status -> {
			this.users.create("cancelled", "Cancelled", AUDIT); status.setRollbackOnly();
		});
		assertThat(this.audits.isAvailable()).isTrue(); assertThat(count()).isEqualTo(1);
	}

	@Test
	void anOlderSuccessfulCommitCannotClearANewerAuditFailure() throws Exception {
		fault("conditional");
		var appended = new CountDownLatch(1); var commit = new CountDownLatch(1);
		try (var executor = Executors.newSingleThreadExecutor()) {
			var original = executor.submit(() -> new TransactionTemplate(this.transactions).executeWithoutResult(status -> {
				this.users.create("older", "Older", AUDIT); appended.countDown();
				try { if (!commit.await(10, TimeUnit.SECONDS)) { throw new IllegalStateException("Commit release timed out"); } }
				catch (InterruptedException ex) { Thread.currentThread().interrupt(); throw new IllegalStateException(ex); }
			}));
			try {
				assertThat(appended.await(10, TimeUnit.SECONDS)).isTrue();
				assertThatThrownBy(() -> this.users.create("rejected", "Rejected", new SecurityAuditContext("system:failed-audit", "internal:test", UUID.randomUUID())))
						.isInstanceOf(RuntimeException.class);
			}
			finally { commit.countDown(); }
			original.get(10, TimeUnit.SECONDS);
		}
		assertThat(this.audits.isAvailable()).isFalse();
		this.users.create("newer", "Newer", AUDIT); assertThat(this.audits.isAvailable()).isTrue();
	}

	private void fault(String type) {
		String body = switch (type) {
			case "skip" -> "RETURN NULL;";
			case "tamper" -> "NEW.actor='system:tampered'; RETURN NEW;";
			case "conditional" -> "IF NEW.actor='system:failed-audit' THEN RAISE EXCEPTION 'unavailable-audit-storage'; END IF; RETURN NEW;";
			default -> "RAISE EXCEPTION 'unavailable-audit-storage';";
		};
		this.jdbc.sql("CREATE FUNCTION audit_availability_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN " + body + " END $$").update();
		this.jdbc.sql(type.equals("deferred")
				? "CREATE CONSTRAINT TRIGGER audit_availability_fault AFTER INSERT ON iam_security_audit DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION audit_availability_fault()"
				: "CREATE TRIGGER audit_availability_fault BEFORE INSERT ON iam_security_audit FOR EACH ROW EXECUTE FUNCTION audit_availability_fault()")
				.update();
	}

	private long count() { return this.jdbc.sql("SELECT count(*) FROM iam_security_audit").query(Long.class).single(); }
}
